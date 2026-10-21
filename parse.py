"""Defensive parsers and normalized evidence models for Sentinel-ADF."""

from __future__ import annotations

import base64
import io
import json
import re
import sqlite3
import struct
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field


class SMSRecord(BaseModel):
    """Normalized SMS/MMS provider record."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")
    record_id: str | None = Field(default=None, alias="_id")
    address: str | None = None
    date: str | None = None
    body: str | None = None
    type: str | None = None
    read: str | None = None
    seen: str | None = None


class CallLogRecord(BaseModel):
    """Normalized call-log provider record."""

    model_config = ConfigDict(extra="allow")
    number: str | None = None
    date: str | None = None
    duration: str | None = None
    name: str | None = None
    type: str | None = None
    countryiso: str | None = None
    geocoded_location: str | None = None


class ContactRecord(BaseModel):
    """Normalized contacts provider record."""

    model_config = ConfigDict(extra="allow")
    display_name: str | None = None
    number: str | None = None
    notes: str | None = None
    last_contacted: str | None = None


class RecoveredRecord(BaseModel):
    """Generic app-database record with a forensic provenance label."""

    model_config = ConfigDict(extra="allow")
    source: str
    table: str
    provenance: Literal["LIVE", "WAL-PENDING", "FREELIST", "CARVED-UNALLOC"]
    fields: dict[str, Any] = Field(default_factory=dict)


class PackageRecord(BaseModel):
    """Installed package metadata; no application secrets are collected."""

    model_config = ConfigDict(extra="allow")
    package: str
    apk_path: str | None = None
    apk_sha256: str | None = None
    permissions: list[str] = Field(default_factory=list)
    first_install_time: str | None = None
    last_update_time: str | None = None


class MediaRecord(BaseModel):
    """Public media metadata extracted on the workstation."""

    model_config = ConfigDict(extra="allow")
    path: str
    sha256: str | None = None
    mime_type: str | None = None
    exif: dict[str, Any] = Field(default_factory=dict)
    gps_latitude: float | None = None
    gps_longitude: float | None = None
    timestamp: str | None = None


class BackupEntry(BaseModel):
    """One file from an unencrypted Android backup tar stream."""

    model_config = ConfigDict(extra="allow")
    name: str
    size: int
    data_sha256: str


def _clean_value(value: str) -> str | None:
    value = value.strip()
    if value in {"", "null", "NULL", "<null>"}:
        return None
    # content's text output can escape commas and line breaks.
    return (
        value.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\,", ",")
        .replace("\\=", "=")
        .strip()
    )


def parse_content_query(text: str) -> list[dict[str, str | None]]:
    """Parse ``adb shell content query``'s flat ``Row: ... key=value`` output.

    A look-ahead is used instead of a naive comma split because message bodies,
    contact notes, and locations frequently contain commas.
    """

    if not text or "No result found" in text:
        return []
    records: list[dict[str, str | None]] = []
    field_pattern = re.compile(
        r"(?P<key>[A-Za-z_][\w.:-]*)=(?P<value>.*?)(?=,\s*[A-Za-z_][\w.:-]*=|$)"
    )
    for line in text.splitlines():
        if not re.match(r"\s*Row\s*:\s*", line, re.I):
            continue
        body = re.sub(r"^\s*Row\s*:\s*\d+\s*", "", line, flags=re.I)
        if not body:
            continue
        fields: dict[str, str | None] = {}
        for match in field_pattern.finditer(body):
            fields[match.group("key")] = _clean_value(match.group("value"))
        if fields:
            records.append(fields)
    return records


def _field(record: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _model_dict(model: BaseModel, *, by_alias: bool = False) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=by_alias, exclude_none=False)


def parse_sms_records(text: str) -> list[dict[str, Any]]:
    """Parse and normalize SMS/MMS provider rows."""

    output: list[dict[str, Any]] = []
    for row in parse_content_query(text):
        model = SMSRecord(
            **{
                "_id": _field(row, "_id", "id"),
                "address": _field(row, "address", "from", "destination"),
                "date": _field(row, "date", "date_sent", "date_received"),
                "body": _field(row, "body", "text", "snippet"),
                "type": _field(row, "type", "msg_box"),
                "read": _field(row, "read"),
                "seen": _field(row, "seen"),
            }
        )
        output.append(_model_dict(model, by_alias=True))
    return output


def parse_call_records(text: str) -> list[dict[str, Any]]:
    """Parse and normalize call-log provider rows."""

    output: list[dict[str, Any]] = []
    for row in parse_content_query(text):
        model = CallLogRecord(
            number=_field(row, "number", "address"),
            date=_field(row, "date"),
            duration=_field(row, "duration"),
            name=_field(row, "name"),
            type=_field(row, "type"),
            countryiso=_field(row, "countryiso", "country_iso"),
            geocoded_location=_field(row, "geocoded_location", "geocodedLocation"),
        )
        output.append(_model_dict(model))
    return output


def parse_contact_records(text: str) -> list[dict[str, Any]]:
    """Parse and normalize contacts provider rows."""

    output: list[dict[str, Any]] = []
    for row in parse_content_query(text):
        model = ContactRecord(
            display_name=_field(row, "display_name", "display_name_alt", "name"),
            number=_field(row, "number", "data1"),
            notes=_field(row, "notes", "note"),
            last_contacted=_field(row, "last_contacted"),
        )
        output.append(_model_dict(model))
    return output


def _package_blocks(dumpsys: str) -> Iterable[tuple[str, str]]:
    pattern = re.compile(
        r"(?ms)^\s*Package \[([^\]]+)\].*?(?=^\s*Package \[|\Z)"
    )
    for match in pattern.finditer(dumpsys):
        yield match.group(1), match.group(0)


def parse_package_metadata(
    package_output: str,
    dumpsys: str = "",
    apk_hashes: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Normalize ``pm list packages -f`` and relevant ``dumpsys package`` data."""

    blocks = dict(_package_blocks(dumpsys))
    records: list[dict[str, Any]] = []
    line_pattern = re.compile(r"^\s*package:(.+?)=(\S+)")
    for line in package_output.splitlines():
        match = line_pattern.match(line)
        if not match:
            continue
        apk_path, package = match.group(1), match.group(2)
        block = blocks.get(package, "")
        permission_section = re.search(
            r"(?ms)requested permissions:\s*(.*?)(?:\n\s*install permissions:|\n\s*User |\Z)",
            block,
            re.I,
        )
        permissions = []
        if permission_section:
            permissions = sorted(
                {
                    permission.strip().rstrip(":")
                    for permission in re.findall(
                        r"^\s*([A-Za-z0-9_.]+)\s*$",
                        permission_section.group(1),
                        re.M,
                    )
                    if permission.strip()
                }
            )
        first = re.search(r"firstInstallTime=([^\s]+)", block)
        updated = re.search(r"lastUpdateTime=([^\s]+)", block)
        record = PackageRecord(
            package=package,
            apk_path=apk_path,
            apk_sha256=(apk_hashes or {}).get(package),
            permissions=permissions,
            first_install_time=first.group(1) if first else None,
            last_update_time=updated.group(1) if updated else None,
        )
        records.append(_model_dict(record))
    return records


def parse_dumpsys_summary(outputs: Mapping[str, str]) -> dict[str, Any]:
    """Keep useful device/network diagnostics structured without over-parsing OEM text."""

    result: dict[str, Any] = {}
    for name, text in outputs.items():
        if name == "android_id":
            result[name] = text.strip() or None
        elif name == "accounts":
            result[name] = parse_account_identifiers(text)
        else:
            result[name] = {
                "line_count": len(text.splitlines()),
                "text": text,
            }
    return result


def parse_account_identifiers(text: str) -> list[dict[str, str]]:
    """Extract account name/type only; never return passwords or tokens."""

    accounts: list[dict[str, str]] = []
    for match in re.finditer(r"Account\s*\{\s*name=([^,}]+),\s*type=([^}]+)\}", text):
        accounts.append({"name": match.group(1).strip(), "type": match.group(2).strip()})
    # Some Android releases print name/type on separate lines.
    if not accounts:
        for match in re.finditer(
            r"(?ms)^\s*name=([^\n]+)\n\s*type=([^\n]+)", text
        ):
            accounts.append({"name": match.group(1).strip(), "type": match.group(2).strip()})
    return accounts


# ---- SQLite recovery -----------------------------------------------------


def _sqlite_json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _query_live_tables(db_bytes: bytes) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, list[str]]]:
    """Query only the main database image, never a live device database."""

    records: list[dict[str, Any]] = []
    roots: dict[str, int] = {}
    columns_by_table: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory(prefix="sentinel-sqlite-") as temporary:
        path = Path(temporary) / "database.sqlite"
        path.write_bytes(db_bytes)
        uri = f"file:{path.as_posix()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True)
            connection.row_factory = sqlite3.Row
            tables = connection.execute(
                "SELECT name, rootpage FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for table_row in tables:
                table = str(table_row[0])
                roots[table] = int(table_row[1] or 0)
                info = connection.execute(f'PRAGMA table_info("{table.replace(chr(34), chr(34) * 2)}")').fetchall()
                columns = [str(item[1]) for item in info]
                columns_by_table[table] = columns
                try:
                    rows = connection.execute(f'SELECT * FROM "{table.replace(chr(34), chr(34) * 2)}"').fetchall()
                except sqlite3.DatabaseError:
                    continue
                for row in rows:
                    records.append(
                        {
                            "table": table,
                            "fields": {
                                key: _sqlite_json_value(row[key]) for key in row.keys()
                            },
                            "provenance": "LIVE",
                        }
                    )
            connection.close()
        except sqlite3.DatabaseError:
            return [], {}, {}
    return records, roots, columns_by_table


def _query_wal_view(db_bytes: bytes, wal_bytes: bytes) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, list[str]]]:
    """Read a host-side copy with its WAL when schema pages exist only in WAL."""

    records: list[dict[str, Any]] = []
    roots: dict[str, int] = {}
    columns_by_table: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory(prefix="sentinel-sqlite-wal-") as temporary:
        path = Path(temporary) / "database.sqlite"
        path.write_bytes(db_bytes)
        Path(f"{path}-wal").write_bytes(wal_bytes)
        try:
            # This is a temporary workstation copy, not the source device or
            # an evidence artifact. SQLite may create a temporary -shm file.
            connection = sqlite3.connect(str(path))
            connection.row_factory = sqlite3.Row
            tables = connection.execute(
                "SELECT name, rootpage FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for table_row in tables:
                table = str(table_row[0])
                roots[table] = int(table_row[1] or 0)
                identifier = table.replace(chr(34), chr(34) * 2)
                info = connection.execute(f'PRAGMA table_info("{identifier}")').fetchall()
                columns_by_table[table] = [str(item[1]) for item in info]
                try:
                    rows = connection.execute(f'SELECT * FROM "{identifier}"').fetchall()
                except sqlite3.DatabaseError:
                    continue
                for row in rows:
                    records.append(
                        {
                            "table": table,
                            "fields": {key: _sqlite_json_value(row[key]) for key in row.keys()},
                            "provenance": "WAL-PENDING",
                        }
                    )
            connection.close()
        except sqlite3.DatabaseError:
            return [], {}, {}
    return records, roots, columns_by_table


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for index in range(9):
        position = offset + index
        if position >= len(data):
            return None
        byte = data[position]
        if index == 8:
            return (value << 8) | byte, position + 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, position + 1
    return None


def _decode_serial(serial: int, data: bytes, offset: int) -> tuple[Any, int] | None:
    if serial == 0:
        return None, offset
    if serial in {8, 9}:
        return (0 if serial == 8 else 1), offset
    if serial in {10, 11}:
        return None, offset
    if serial == 1:
        size = 1
        value = int.from_bytes(data[offset : offset + size], "big", signed=True)
    elif serial == 2:
        size = 2
        value = int.from_bytes(data[offset : offset + size], "big", signed=True)
    elif serial == 3:
        size = 3
        raw = data[offset : offset + size]
        value = int.from_bytes(raw, "big", signed=False)
        if value & 0x800000:
            value -= 1 << 24
    elif serial == 4:
        size = 4
        value = int.from_bytes(data[offset : offset + size], "big", signed=True)
    elif serial == 5:
        size = 6
        value = int.from_bytes(data[offset : offset + size], "big", signed=True)
    elif serial == 6:
        size = 8
        value = int.from_bytes(data[offset : offset + size], "big", signed=True)
    elif serial == 7:
        size = 8
        if offset + size > len(data):
            return None
        value = struct.unpack(">d", data[offset : offset + size])[0]
    elif serial >= 12 and serial % 2 == 0:
        size = (serial - 12) // 2
        value = {"encoding": "base64", "value": base64.b64encode(data[offset : offset + size]).decode("ascii")}
    elif serial >= 13 and serial % 2 == 1:
        size = (serial - 13) // 2
        value = data[offset : offset + size].decode("utf-8", errors="replace")
    else:
        return None
    if offset + size > len(data):
        return None
    return value, offset + size


def _decode_record(data: bytes, offset: int = 0) -> tuple[list[Any], int] | None:
    header = _read_varint(data, offset)
    if header is None:
        return None
    header_size, cursor = header
    if header_size < 2 or offset + header_size > len(data) or header_size > 4096:
        return None
    serials: list[int] = []
    while cursor < offset + header_size:
        item = _read_varint(data, cursor)
        if item is None:
            return None
        serial, cursor = item
        serials.append(serial)
    if cursor != offset + header_size or not serials or len(serials) > 128:
        return None
    values: list[Any] = []
    payload_cursor = offset + header_size
    for serial in serials:
        decoded = _decode_serial(serial, data, payload_cursor)
        if decoded is None:
            return None
        value, payload_cursor = decoded
        values.append(value)
    return values, payload_cursor


def _page_size(db_bytes: bytes, wal_bytes: bytes | None) -> int:
    value = int.from_bytes(db_bytes[16:18], "big") if len(db_bytes) >= 18 else 4096
    if value == 1:
        value = 65536
    if wal_bytes and len(wal_bytes) >= 12:
        wal_value = int.from_bytes(wal_bytes[8:12], "big")
        if wal_value in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}:
            value = wal_value
    return value if value >= 512 else 4096


def _main_page(db: bytes, page_number: int, size: int) -> bytes:
    start = (page_number - 1) * size
    return db[start : start + size]


def _wal_pages(wal: bytes, size: int) -> dict[int, tuple[bytes, int]]:
    pages: dict[int, tuple[bytes, int]] = {}
    if len(wal) < 32:
        return pages
    frame_size = 24 + size
    frame_number = 0
    for offset in range(32, len(wal) - frame_size + 1, frame_size):
        frame_number += 1
        page_number = int.from_bytes(wal[offset : offset + 4], "big")
        page = wal[offset + 24 : offset + frame_size]
        if page_number:
            pages[page_number] = (page, frame_number)
    return pages


def _btree_page(page: bytes, page_number: int) -> tuple[list[list[Any]], list[int], list[bytes]]:
    """Return table-leaf records, child page numbers, and unallocated ranges."""

    base = 100 if page_number == 1 else 0
    if len(page) < base + 12:
        return [], [], []
    page_type = page[base]
    if page_type not in {5, 13}:
        return [], [], []
    cell_count = int.from_bytes(page[base + 3 : base + 5], "big")
    content_start = int.from_bytes(page[base + 5 : base + 7], "big")
    if content_start == 0:
        content_start = len(page)
    pointer_start = base + (12 if page_type == 5 else 8)
    if pointer_start + cell_count * 2 > len(page):
        return [], [], []
    cells: list[int] = []
    for index in range(cell_count):
        pointer = int.from_bytes(
            page[pointer_start + index * 2 : pointer_start + index * 2 + 2], "big"
        )
        if 0 < pointer < len(page):
            cells.append(pointer)
    records: list[list[Any]] = []
    children: list[int] = []
    if page_type == 5:
        rightmost = int.from_bytes(page[base + 8 : base + 12], "big")
        if rightmost:
            children.append(rightmost)
    for pointer in cells:
        if page_type == 5:
            if pointer + 4 <= len(page):
                child = int.from_bytes(page[pointer : pointer + 4], "big")
                if child:
                    children.append(child)
            continue
        payload_info = _read_varint(page, pointer)
        if payload_info is None:
            continue
        payload_length, cursor = payload_info
        rowid_info = _read_varint(page, cursor)
        if rowid_info is None:
            continue
        _, payload_start = rowid_info
        payload_end = min(len(page), payload_start + payload_length)
        decoded = _decode_record(page[payload_start:payload_end])
        if decoded:
            records.append(decoded[0])
    # Approximate unallocated content for carving.  Free-list blocks are also
    # scanned separately; overlapping candidates are de-duplicated later.
    ranges: list[bytes] = []
    if content_start > pointer_start + cell_count * 2:
        ranges.append(page[pointer_start + cell_count * 2 : content_start])
    return records, children, ranges


def _map_values(values: list[Any], columns: list[str]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for index, value in enumerate(values):
        key = columns[index] if index < len(columns) else f"column_{index}"
        mapped[key] = _sqlite_json_value(value)
    return mapped


def _freelist_pages(db: bytes, size: int) -> list[int]:
    if len(db) < 40:
        return []
    trunk = int.from_bytes(db[32:36], "big")
    found: list[int] = []
    seen: set[int] = set()
    while trunk and trunk not in seen and len(found) < 10000:
        seen.add(trunk)
        page = _main_page(db, trunk, size)
        if len(page) < 8:
            break
        next_trunk = int.from_bytes(page[0:4], "big")
        count = min(int.from_bytes(page[4:8], "big"), (len(page) - 8) // 4)
        for index in range(count):
            number = int.from_bytes(page[8 + index * 4 : 12 + index * 4], "big")
            if number:
                found.append(number)
        trunk = next_trunk
    return found


def _carve_range(data: bytes, columns: list[str], limit: int = 250) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    max_columns = max(1, min(len(columns), 64))
    for offset in range(len(data)):
        decoded = _decode_record(data, offset)
        if not decoded:
            continue
        values, end = decoded
        if len(values) > max_columns or end <= offset or not any(value is not None for value in values):
            continue
        # A record header generally has one byte per column.  This constraint
        # drops most random binary false positives while retaining deleted rows.
        header = _read_varint(data, offset)
        if not header or header[0] > 1 + len(values) * 9:
            continue
        candidates.append(_map_values(values, columns))
        if len(candidates) >= limit:
            break
    return candidates


def _recovered_from_pages(
    db: bytes,
    wal: bytes | None,
    roots: Mapping[str, int],
    columns: Mapping[str, list[str]],
) -> list[dict[str, Any]]:
    size = _page_size(db, wal)
    wal_map = _wal_pages(wal or b"", size)
    page_cache: dict[int, bytes] = {}

    def page_for(number: int) -> bytes:
        if number in page_cache:
            return page_cache[number]
        if number in wal_map:
            page_cache[number] = wal_map[number][0]
        else:
            page_cache[number] = _main_page(db, number, size)
        return page_cache[number]

    recovered: list[dict[str, Any]] = []
    visited: set[tuple[str, int]] = set()

    def visit(table: str, number: int) -> None:
        marker = (table, number)
        if marker in visited or len(visited) > 10000:
            return
        visited.add(marker)
        page = page_for(number)
        records, children, unallocated = _btree_page(page, number)
        provenance = "WAL-PENDING" if number in wal_map else "LIVE"
        for values in records:
            recovered.append(
                {
                    "table": table,
                    "fields": _map_values(values, columns.get(table, [])),
                    "provenance": provenance,
                }
            )
        for raw in unallocated:
            for fields in _carve_range(raw, columns.get(table, []), limit=100):
                recovered.append(
                    {
                        "table": table,
                        "fields": fields,
                        "provenance": "CARVED-UNALLOC",
                    }
                )
        for child in children:
            visit(table, child)

    for table, root in roots.items():
        if root:
            visit(table, root)

    for free_page_number in _freelist_pages(db, size):
        page = _main_page(db, free_page_number, size)
        # There is no reliable table owner in a freed page.  Try each schema,
        # preserving the explicit FREELIST provenance and conservative limits.
        for table, table_columns in columns.items():
            for fields in _carve_range(page, table_columns, limit=40):
                recovered.append(
                    {
                        "table": table,
                        "fields": fields,
                        "provenance": "FREELIST",
                    }
                )
    return recovered


def _record_key(record: Mapping[str, Any]) -> str:
    return json.dumps(
        {"table": record.get("table"), "fields": record.get("fields", {})},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def parse_sqlite_database(
    db_bytes: bytes,
    *,
    wal_bytes: bytes | None = None,
    source: str = "database.sqlite",
) -> list[dict[str, Any]]:
    """Recover live, WAL, freelist, and unallocated SQLite records.

    This is a deliberately conservative SQLite b-tree/record parser.  It does
    not claim complete recovery of encrypted, corrupted, or overflow payloads;
    those limitations remain visible in the output provenance and case log.
    """

    if not db_bytes.startswith(b"SQLite format 3\x00"):
        return []
    live, roots, columns = _query_live_tables(db_bytes)
    if not roots and wal_bytes:
        # A newly-created or recently migrated database can have sqlite_master
        # itself pending in WAL. Recover its schema from a temporary WAL view.
        live, roots, columns = _query_wal_view(db_bytes, wal_bytes)
    recovered = _recovered_from_pages(db_bytes, wal_bytes, roots, columns)
    ordered: list[dict[str, Any]] = []
    seen: set[str] = set()
    priority = {"LIVE": 0, "WAL-PENDING": 1, "FREELIST": 2, "CARVED-UNALLOC": 3}
    all_records = live + recovered
    all_records.sort(key=lambda item: priority.get(str(item.get("provenance")), 9))
    for record in all_records:
        key = _record_key(record)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(
            {
                "source": source,
                "table": str(record.get("table", "unknown")),
                "provenance": record.get("provenance", "LIVE"),
                "fields": record.get("fields", {}),
            }
        )
    return [RecoveredRecord(**item).model_dump(mode="json") for item in ordered]


def parse_sqlite_buffers(buffers: Mapping[str, bytes]) -> list[dict[str, Any]]:
    """Parse base database buffers and pair each with its captured WAL."""

    output: list[dict[str, Any]] = []
    for path, data in buffers.items():
        if path.endswith("-wal") or path.endswith("-shm"):
            continue
        records = parse_sqlite_database(
            data,
            wal_bytes=buffers.get(f"{path}-wal"),
            source=Path(path).name,
        )
        output.extend(records)
    return output


# ---- EXIF and backup -----------------------------------------------------


def _rational_float(value: Any) -> float | None:
    try:
        if hasattr(value, "num") and hasattr(value, "den"):
            return float(value.num) / float(value.den)
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1])
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _gps_decimal(values: Any, reference: Any) -> float | None:
    try:
        pieces = list(values)
        if len(pieces) != 3:
            return None
        decimal = sum((_rational_float(item) or 0.0) / (60**index) for index, item in enumerate(pieces))
        if str(reference).upper().strip() in {"S", "W"}:
            decimal *= -1
        return decimal
    except (TypeError, ValueError):
        return None


def parse_exif(data: bytes, path: str = "") -> dict[str, Any]:
    """Extract EXIF/GPS metadata with exifread and a Pillow fallback."""

    tags: dict[str, Any] = {}
    latitude = longitude = None
    timestamp: str | None = None
    try:
        import exifread  # type: ignore

        parsed = exifread.process_file(io.BytesIO(data), details=False)
        tags = {str(key): str(value) for key, value in parsed.items()}
        latitude = _gps_decimal(
            parsed.get("GPS GPSLatitude", []), parsed.get("GPS GPSLatitudeRef", "")
        )
        longitude = _gps_decimal(
            parsed.get("GPS GPSLongitude", []), parsed.get("GPS GPSLongitudeRef", "")
        )
        timestamp = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
    except Exception:
        try:
            from PIL import Image, ExifTags  # type: ignore

            with Image.open(io.BytesIO(data)) as image:
                raw = image.getexif()
                tags = {
                    str(ExifTags.TAGS.get(key, key)): str(value)
                    for key, value in raw.items()
                }
                timestamp = tags.get("DateTimeOriginal") or tags.get("DateTime")
                gps = raw.get(34853, {})
                if gps:
                    latitude = _gps_decimal(gps.get(2), gps.get(1))
                    longitude = _gps_decimal(gps.get(4), gps.get(3))
        except Exception:
            tags = {}
    return MediaRecord(
        path=path,
        exif=tags,
        gps_latitude=latitude,
        gps_longitude=longitude,
        timestamp=timestamp,
    ).model_dump(mode="json")


def parse_android_backup(data: bytes) -> list[dict[str, Any]]:
    """Parse an unencrypted Android ``.ab`` tar stream.

    Encrypted backups are intentionally rejected rather than brute-forced or
    passed to an opaque decryptor.  API 31+ restrictions are recorded by the
    acquisition layer, and an old backup is never represented as complete data.
    """

    header_end = data.find(b"\n", 0)
    if header_end < 0 or data[:header_end] != b"ANDROID BACKUP":
        raise ValueError("Not an Android Backup (.ab) file")
    lines = data.split(b"\n", 4)
    if len(lines) < 4:
        raise ValueError("Truncated Android Backup header")
    version = lines[1].decode("ascii", errors="replace")
    compression = lines[2].decode("ascii", errors="replace")
    encryption = lines[3].decode("ascii", errors="replace")
    if encryption.lower() != "none":
        raise ValueError(
            f"Encrypted Android backup (version {version}) is unsupported; no password recovery is attempted"
        )
    payload = lines[4]
    if compression == "1":
        import gzip

        payload = gzip.decompress(payload)
    elif compression != "0":
        raise ValueError(f"Unsupported Android Backup compression flag: {compression}")
    entries: list[dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            content = stream.read()
            import hashlib

            entries.append(
                BackupEntry(
                    name=member.name,
                    size=len(content),
                    data_sha256=hashlib.sha256(content).hexdigest(),
                ).model_dump(mode="json")
            )
    return entries


__all__ = [
    "BackupEntry",
    "CallLogRecord",
    "ContactRecord",
    "MediaRecord",
    "PackageRecord",
    "RecoveredRecord",
    "SMSRecord",
    "parse_account_identifiers",
    "parse_android_backup",
    "parse_call_records",
    "parse_contact_records",
    "parse_content_query",
    "parse_dumpsys_summary",
    "parse_exif",
    "parse_package_metadata",
    "parse_sms_records",
    "parse_sqlite_buffers",
    "parse_sqlite_database",
]
