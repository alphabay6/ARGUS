"""Evidence integrity and chain-of-custody primitives for Sentinel-ADF.

The audit log is append-only from the application's point of view.  Each JSONL
entry contains the digest of the preceding entry and its own digest.  Artifact
hashes are deliberately kept outside artifact JSON files so an artifact does
not hash itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


UTC = timezone.utc


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def iso_now() -> str:
    """Return an RFC-3339-like UTC timestamp suitable for evidence records."""

    return utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically for hashing and audit-chain work."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    """JSON fallback for paths, datetimes, and Pydantic models."""

    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return dict_method()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 digest of bytes."""

    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a workstation file without loading it all into memory."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


class AuditLogger:
    """Append-only JSONL logger with a tamper-evident hash chain."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._previous_hash = self._read_previous_hash()

    def _read_previous_hash(self) -> str:
        if not self.path.exists():
            return ""
        previous = ""
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    previous = str(item.get("entry_sha256", ""))
        except (OSError, json.JSONDecodeError):
            # Continuing with an empty predecessor would hide a damaged log.
            # Refuse to append instead; the operator can preserve the damaged
            # file and start a new case directory.
            raise RuntimeError(f"Audit log is not valid JSONL: {self.path}")
        return previous

    @property
    def previous_hash(self) -> str:
        """Digest that will be referenced by the next entry."""

        return self._previous_hash

    def log(
        self,
        action: str,
        *,
        artifact: str = "",
        sha256: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append and fsync one audit event, returning the written event."""

        event: dict[str, Any] = {
            "timestamp": iso_now(),
            "action": action,
            "artifact": artifact,
            "sha256": sha256,
            "previous_sha256": self._previous_hash,
        }
        if details:
            event["details"] = dict(details)
        event["entry_sha256"] = sha256_bytes(canonical_json(event))
        line = canonical_json(event) + b"\n"
        with self.path.open("ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        self._previous_hash = event["entry_sha256"]
        return event

    def entries(self) -> list[dict[str, Any]]:
        """Read the verified-format audit entries in order."""

        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        predecessor = ""
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                item = json.loads(line)
                if item.get("previous_sha256", "") != predecessor:
                    raise ValueError(
                        f"Audit chain predecessor mismatch at line {line_number}"
                    )
                supplied = item.get("entry_sha256", "")
                unsigned = dict(item)
                unsigned.pop("entry_sha256", None)
                if supplied != sha256_bytes(canonical_json(unsigned)):
                    raise ValueError(f"Audit entry digest mismatch at line {line_number}")
                entries.append(item)
                predecessor = supplied
        return entries


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes atomically and flush them to the workstation filesystem."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def write_json_artifact(
    path: str | Path,
    value: Any,
    audit: AuditLogger,
    *,
    action: str = "artifact_written",
) -> str:
    """Write a stable JSON artifact, hash it immediately, and audit the hash."""

    destination = Path(path)
    payload = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=_json_default,
    ).encode("utf-8") + b"\n"
    _atomic_write(destination, payload)
    digest = sha256_file(destination)
    audit.log(action, artifact=destination.name, sha256=digest)
    return digest


def write_text_artifact(
    path: str | Path,
    text: str,
    audit: AuditLogger,
    *,
    action: str = "artifact_written",
) -> str:
    """Write, hash, and audit a UTF-8 text artifact."""

    destination = Path(path)
    _atomic_write(destination, text.encode("utf-8"))
    digest = sha256_file(destination)
    audit.log(action, artifact=destination.name, sha256=digest)
    return digest


def build_chain_of_custody(
    *,
    case_id: str,
    operator: str,
    device_serial: str,
    start_time: str,
    end_time: str,
    acquisition_tier: str,
    authorization_reference: str,
    audit: AuditLogger,
) -> dict[str, Any]:
    """Build the sealed custody object from the verified audit chain."""

    events = [
        {
            "timestamp": item.get("timestamp", ""),
            "action": item.get("action", ""),
            "artifact": item.get("artifact", ""),
            "sha256": item.get("sha256", ""),
        }
        for item in audit.entries()
    ]
    return {
        "case_id": case_id,
        "operator": operator,
        "device_serial": device_serial,
        "start_time": start_time,
        "end_time": end_time,
        "acquisition_tier": acquisition_tier,
        "authorization_reference": authorization_reference,
        "events": events,
    }


def write_chain_of_custody(
    path: str | Path,
    custody: Mapping[str, Any],
) -> str:
    """Write and hash chain_of_custody.json without adding a circular log event."""

    destination = Path(path)
    payload = json.dumps(
        custody,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=_json_default,
    ).encode("utf-8") + b"\n"
    _atomic_write(destination, payload)
    return sha256_file(destination)


def generate_manifest(
    evidence_directory: str | Path,
    *,
    manifest_name: str = "MANIFEST.sha256",
) -> Path:
    """Create a sorted ``filename: sha256`` manifest.

    A manifest cannot contain a meaningful digest of itself.  Consequently the
    manifest is the one deliberately excluded entry; every other file that is
    shipped in the ZIP, including the custody and audit files, is listed.
    """

    root = Path(evidence_directory)
    manifest = root / manifest_name
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() == manifest.resolve():
            continue
        relative = path.relative_to(root).as_posix()
        lines.append(f"{relative}: {sha256_file(path)}")
    data = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    _atomic_write(manifest, data)
    return manifest


def create_evidence_zip(
    evidence_directory: str | Path,
    destination: str | Path,
) -> Path:
    """Generate a manifest and package the complete evidence directory."""

    root = Path(evidence_directory)
    manifest = generate_manifest(root)
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    return target


def verify_manifest(evidence_directory: str | Path) -> list[str]:
    """Return manifest mismatches; an empty list indicates matching files."""

    root = Path(evidence_directory)
    manifest = root / "MANIFEST.sha256"
    if not manifest.exists():
        return ["MANIFEST.sha256 is missing"]
    failures: list[str] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip() or ": " not in line:
            failures.append(f"Malformed manifest line: {line}")
            continue
        name, expected = line.rsplit(": ", 1)
        candidate = root / name
        if not candidate.exists():
            failures.append(f"Missing: {name}")
        elif sha256_file(candidate) != expected:
            failures.append(f"Digest mismatch: {name}")
    return failures
