"""Local Gradio dashboard for the Sentinel-ADF acquisition pipeline.

Running ``python app.py`` also performs a small host-side dependency check.  A
forensic workstation may be intentionally provisioned offline, so automatic
installation can be disabled with ``SENTINEL_AUTO_INSTALL=0`` after the
requirements have been installed by an administrator.
"""

from __future__ import annotations

import html
import importlib.metadata
import importlib.util
import json
import mimetypes
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


# Keep the bootstrap here, before third-party imports, so a fresh checkout can
# be started with only Python and pip.  The package names and import names are
# not identical for Pillow and python-magic.  The SQLite and .ab parsers used
# by this project are implemented in parse.py, so neither of their historical
# third-party packages is needed at startup.
_RUNTIME_DEPENDENCIES = (
    ("adbutils", "adbutils", "2.0.0"),
    ("exifread", "exifread", "3.0.0"),
    ("Pillow", "PIL", "10.0.0"),
    ("python-magic", "magic", "0.4.27"),
    ("gradio", "gradio", "4.0.0"),
    ("pandas", "pandas", "2.0.0"),
    ("pydantic", "pydantic", "2.0.0"),
)


def _version_numbers(value: str) -> tuple[int, ...]:
    """Return a comparable numeric representation of a package version."""

    numbers = tuple(int(item) for item in re.findall(r"\d+", value))
    return numbers or (0,)


def _dependency_needs_install(package: str, module: str, minimum: str) -> bool:
    """Check both importability and the minimum version required by the code."""

    try:
        if importlib.util.find_spec(module) is None:
            return True
        installed = importlib.metadata.version(package)
    except (ImportError, ModuleNotFoundError, importlib.metadata.PackageNotFoundError):
        return True
    return _version_numbers(installed) < _version_numbers(minimum)


def ensure_runtime_dependencies() -> None:
    """Install missing/old runtime packages into the active Python environment.

    Installation is performed with ``sys.executable -m pip`` so the packages
    land in the interpreter that will run the dashboard.  This only changes the
    forensic workstation; Sentinel-ADF never installs anything on the Android
    device.  Set ``SENTINEL_AUTO_INSTALL=0`` to require an administrator to
    provision dependencies manually.
    """

    disabled = os.environ.get("SENTINEL_AUTO_INSTALL", "1").strip().lower()
    if disabled in {"0", "false", "no", "off"}:
        return

    missing = [
        package
        for package, module, minimum in _RUNTIME_DEPENDENCIES
        if _dependency_needs_install(package, module, minimum)
    ]
    if not missing:
        return

    requirements = Path(__file__).with_name("requirements.txt")
    if not requirements.exists():
        raise RuntimeError(
            f"Missing runtime dependencies ({', '.join(missing)}) and {requirements} was not found."
        )

    print(
        "Sentinel-ADF: installing missing workstation dependencies: "
        + ", ".join(missing),
        flush=True,
    )
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "-r",
        str(requirements),
    ]
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "Automatic dependency installation failed. Run this command manually "
            f"and then start the dashboard again:\n\n  {' '.join(command)}"
        ) from exc

    still_missing = [
        package
        for package, module, minimum in _RUNTIME_DEPENDENCIES
        if _dependency_needs_install(package, module, minimum)
    ]
    if still_missing:
        raise RuntimeError(
            "The dependency installer completed, but these packages are still "
            f"unavailable or too old: {', '.join(still_missing)}"
        )


ensure_runtime_dependencies()

import gradio as gr
import pandas as pd

from acquire import ADBClient, AcquisitionBundle, DeviceInfo, acquire_bundle, discover_device
from config import LEGAL_NOTICE, OUTPUT_DIRECTORY, READ_ONLY_NOTICE, new_case_directory
from custody import (
    AuditLogger,
    build_chain_of_custody,
    create_evidence_zip,
    iso_now,
    sha256_bytes,
    sha256_file,
    write_chain_of_custody,
    write_json_artifact,
)
from parse import (
    parse_call_records,
    parse_contact_records,
    parse_dumpsys_summary,
    parse_exif,
    parse_package_metadata,
    parse_sms_records,
    parse_sqlite_buffers,
)


CSS = """
:root { --bg: #111827; --panel: #1f2937; --ink: #e5e7eb; --accent: #22c55e; }
body, .gradio-container { background: var(--bg) !important; color: var(--ink) !important; }
.gr-block, .gr-box, .gr-panel { background: var(--panel) !important; border-color: #374151 !important; }
button.primary { background: #166534 !important; border-color: #22c55e !important; }
.sentinel-warning { border-left: 4px solid #f59e0b; padding: 0.8rem; background: #292524; }
.audit-stream { max-height: 260px; overflow-y: auto; background: #030712; padding: .75rem; font: .84rem ui-monospace, monospace; }
.audit-line { color: #a7f3d0; white-space: pre-wrap; }
"""


COVERAGE_TEXT = """### Coverage & Limitations

- **Tier 1 / non-rooted logical:** SMS, calls, and contacts are attempted through legacy content providers only on Android API < 31. Public media, selected public documents, device diagnostics, package metadata, and APK hashes are collected where Android permits.
- **Android 12+ (API 31+):** `content query` and legacy `adb backup` are restricted for many apps. Sentinel-ADF visibly records that limitation and falls back to publicly readable storage and package metadata; it does not silently report an empty result as complete evidence.
- **Tier 2 / rooted logical:** Authorized root permits read-only copies of selected SQLite databases. Records are labeled `LIVE`, `WAL-PENDING`, `FREELIST`, or `CARVED-UNALLOC`; carving is conservative and cannot recover encrypted or overwritten data.
- **Tier 3 / physical:** Capability is only reported when a read-only raw path is available and encryption is not a hard stop. The normal dashboard does not image automatically. FDE/FBE, secure boot, TEE protections, locked bootloaders, and inaccessible paths are hard stops—not bypass targets.
- Empty provider results are recorded as **absence of evidence**, not proof that the artifact never existed. No passwords, 2FA secrets, or covert instrumentation are collected.
"""


def sanitize_serial(serial: str) -> str:
    """Show enough of a serial to correlate a live session without exposing it."""

    if not serial:
        return "unknown"
    if len(serial) <= 6:
        return "*" * len(serial)
    return f"{serial[:3]}…{serial[-2:]}"


def _empty_frame(records: list[Mapping[str, Any]] | None = None) -> pd.DataFrame:
    return pd.DataFrame(list(records or []))


def _session_case_id(case_id: str) -> tuple[str, str]:
    requested = case_id.strip() or "case"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return requested, f"{requested}_{stamp}"


def _new_session(operator: str, case_id: str, authorization_reference: str) -> dict[str, Any]:
    requested_id, directory_id = _session_case_id(case_id)
    directory = new_case_directory(directory_id)
    audit_path = directory / "audit_log.jsonl"
    audit = AuditLogger(audit_path)
    start_time = iso_now()
    audit.log(
        "session_started",
        details={
            "case_id": requested_id,
            "operator": operator.strip() or "unspecified",
            "authorization_reference_present": bool(authorization_reference.strip()),
            "legal_notice_acknowledged": True,
            "read_only_guarantee": READ_ONLY_NOTICE,
        },
    )
    return {
        "case_id": requested_id,
        "operator": operator.strip() or "unspecified",
        "authorization_reference": authorization_reference.strip(),
        "start_time": start_time,
        "evidence_dir": str(directory),
        "audit_path": str(audit_path),
        "serial": "",
        "device": {},
        "acquired": False,
    }


def _audit_html(audit: AuditLogger, progress: int = 100) -> str:
    """Render the persistent audit stream, escaping device-provided text."""

    lines = []
    for entry in audit.entries():
        details = entry.get("details") or {}
        suffix = f" {json.dumps(details, ensure_ascii=False, sort_keys=True)}" if details else ""
        lines.append(
            '<div class="audit-line">'
            + html.escape(f"[{entry.get('timestamp', '')}] {entry.get('action', '')}"
                          f" {entry.get('artifact', '')}{suffix}")
            + "</div>"
        )
    return (
        f'<progress value="{max(0, min(progress, 100))}" max="100" style="width:100%"></progress>'
        + '<div class="audit-stream">'
        + "".join(lines)
        + "</div>"
    )


def _device_status(device: DeviceInfo) -> str:
    return (
        f"**Connection:** ADB device detected\n\n"
        f"**Model:** {device.model}\n\n"
        f"**Android:** {device.android_version} (API {device.sdk or 'unknown'})\n\n"
        f"**Serial:** `{sanitize_serial(device.serial)}`\n\n"
        f"**Root:** {'available' if device.rooted else 'not detected'}\n\n"
        f"**Detected acquisition tier:** **{device.tier}**"
    )


def _mime(data: bytes, path: str) -> str:
    try:
        import magic  # type: ignore

        return str(magic.from_buffer(data, mime=True))
    except Exception:
        return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _parse_bundle(bundle: AcquisitionBundle) -> dict[str, Any]:
    """Turn raw acquisition buffers into serializable artifact collections."""

    sms = parse_sms_records(bundle.content_queries.get("sms", ""))
    calls = parse_call_records(bundle.content_queries.get("calls", ""))
    contacts = parse_contact_records(bundle.content_queries.get("contacts", ""))
    messages = parse_sqlite_buffers(bundle.database_buffers)
    packages = parse_package_metadata(
        bundle.package_output,
        bundle.package_dumpsys,
        bundle.package_hashes,
    )
    media: list[dict[str, Any]] = []
    for remote_path, data in bundle.public_media.items():
        record = parse_exif(data, remote_path)
        record["sha256"] = sha256_bytes(data)
        record["mime_type"] = _mime(data, remote_path)
        media.append(record)
    public_files = [
        {
            "path": remote_path,
            "size": len(data),
            "sha256": sha256_bytes(data),
            "mime_type": _mime(data, remote_path),
        }
        for remote_path, data in bundle.public_files.items()
    ]
    device_network = {
        "device": bundle.device.as_dict(),
        "diagnostics": parse_dumpsys_summary(bundle.system_outputs),
        "limitations": bundle.limitations,
        "read_only_notice": READ_ONLY_NOTICE,
    }
    return {
        "sms": sms,
        "calls": calls,
        "contacts": contacts,
        "messages": messages,
        "packages": packages,
        "media": media,
        "public_storage": public_files,
        "device_network": device_network,
        "limitations": bundle.limitations,
    }


def _seal_custody(state: Mapping[str, Any], audit: AuditLogger, end_time: str) -> str:
    custody = build_chain_of_custody(
        case_id=str(state["case_id"]),
        operator=str(state["operator"]),
        device_serial=str(state.get("serial", "")),
        start_time=str(state["start_time"]),
        end_time=end_time,
        acquisition_tier=str(state.get("device", {}).get("tier", "unknown")),
        authorization_reference=str(state.get("authorization_reference", "")),
        audit=audit,
    )
    return write_chain_of_custody(Path(state["evidence_dir"]) / "chain_of_custody.json", custody)


def detect_callback(
    consent: bool,
    operator: str,
    case_id: str,
    authorization_reference: str,
):
    """Create an audited session and probe the connected device."""

    if not consent:
        return "Authorization gate is not checked.", {}, COVERAGE_TEXT, None, ""
    state: dict[str, Any] = {}
    try:
        state = _new_session(operator, case_id, authorization_reference)
        audit = AuditLogger(state["audit_path"])
        client = ADBClient(audit)
        device = discover_device(client)
        state["serial"] = device.serial
        state["device"] = device.as_dict()
        audit.log("device_status_displayed", details={"tier": device.tier})
        return (
            _device_status(device),
            state,
            COVERAGE_TEXT + "\n\n" + "\n".join(f"- {item}" for item in device.limitations),
            state["audit_path"],
            _audit_html(audit),
        )
    except Exception as exc:
        # Keep the diagnostic and the audit stream downloadable.  In
        # particular, an unauthorized phone is a setup/authorization state,
        # not a reason to discard the session record.
        audit_path = state.get("audit_path")
        audit_html = ""
        if audit_path:
            try:
                audit = AuditLogger(audit_path)
                audit_html = _audit_html(audit)
            except Exception:
                pass
        return (
            f"Device detection failed: {exc}",
            state,
            COVERAGE_TEXT,
            audit_path,
            audit_html,
        )


def acquire_callback(
    consent: bool,
    state: Mapping[str, Any],
    progress=gr.Progress(track_tqdm=True),
):
    """Run tiered collection and write/hash normalized JSON artifacts."""

    empty = [_empty_frame() for _ in range(6)]
    if not consent:
        return ("Authorization gate is not checked.", *empty, {}, None, "", COVERAGE_TEXT)
    if not state or not state.get("serial"):
        return ("Detect a connected device before acquisition.", *empty, {}, None, "", COVERAGE_TEXT)
    try:
        progress(0.05, desc="Opening audited read-only ADB session")
        audit = AuditLogger(state["audit_path"])
        client = ADBClient(audit)
        client.bind(str(state["serial"]))
        # Re-assess capabilities immediately before extraction so a changed
        # device state cannot silently inherit an earlier tier decision.
        device = discover_device(client)
        state = dict(state)
        state["device"] = device.as_dict()
        state["serial"] = device.serial
        progress(0.15, desc=f"Collecting {device.tier}")
        bundle = acquire_bundle(client, device)
        progress(0.65, desc="Parsing provider rows, SQLite, EXIF, and diagnostics")
        parsed = _parse_bundle(bundle)
        root = Path(state["evidence_dir"])
        artifact_values = {
            "sms.json": parsed["sms"],
            "call_logs.json": parsed["calls"],
            "contacts.json": parsed["contacts"],
            "messaging.json": parsed["messages"],
            "packages.json": parsed["packages"],
            "media_location.json": parsed["media"],
            "public_storage.json": parsed["public_storage"],
            "device_network.json": parsed["device_network"],
            "limitations.json": parsed["limitations"],
        }
        for filename, value in artifact_values.items():
            progress(0.68 + 0.025 * list(artifact_values).index(filename), desc=f"Hashing {filename}")
            write_json_artifact(root / filename, value, audit)
        state["acquired"] = True
        state["serial"] = device.serial
        audit.log("acquisition_completed", details={"tier": device.tier})
        audit.log("chain_of_custody_prepared", artifact="chain_of_custody.json")
        _seal_custody(state, audit, iso_now())
        progress(1.0, desc="Acquisition complete")
        status = _device_status(device) + f"\n\n**Artifacts:** {len(artifact_values)} JSON files written and hashed."
        return (
            status,
            _empty_frame(parsed["sms"]),
            _empty_frame(parsed["calls"]),
            _empty_frame(parsed["contacts"]),
            _empty_frame(parsed["messages"]),
            _empty_frame(parsed["packages"]),
            _empty_frame(parsed["media"]),
            {"device": parsed["device_network"]["device"], "diagnostics": parsed["device_network"]["diagnostics"]},
            state["audit_path"],
            _audit_html(audit),
            COVERAGE_TEXT + "\n\n" + "\n".join(f"- {item}" for item in bundle.limitations),
        )
    except Exception as exc:
        try:
            AuditLogger(state["audit_path"]).log("acquisition_failed", details={"error": str(exc)})
        except Exception:
            pass
        return (f"Acquisition failed: {exc}", *empty, {}, state.get("audit_path"), "", COVERAGE_TEXT)


def export_callback(consent: bool, state: Mapping[str, Any]):
    """Seal the final audit state, create MANIFEST.sha256, and build the ZIP."""

    if not consent:
        return "Authorization gate is not checked.", None, ""
    if not state or not state.get("acquired"):
        return "Run a successful acquisition before export.", None, ""
    try:
        audit = AuditLogger(state["audit_path"])
        # This is intentionally the final audit event.  No event is appended
        # after the manifest is generated, otherwise its audit hash would be
        # stale inside the package.
        audit.log("evidence_export_started", details={"read_only_source": True})
        _seal_custody(state, audit, iso_now())
        target = OUTPUT_DIRECTORY / f"{state['case_id']}.zip"
        create_evidence_zip(state["evidence_dir"], target)
        digest = sha256_file(target)
        return (
            f"Evidence package ready. ZIP SHA-256: `{digest}`. "
            "MANIFEST.sha256 excludes only itself because self-hashing is circular.",
            str(target),
            _audit_html(audit),
        )
    except Exception as exc:
        return f"Export failed: {exc}", None, ""


def toggle_actions(consent: bool):
    update = gr.update(interactive=bool(consent))
    return update, update, update


def build_app() -> gr.Blocks:
    """Construct the single local Blocks dashboard."""

    with gr.Blocks(title="Sentinel-ADF", css=CSS) as demo:
        session_state = gr.State({})
        gr.Markdown(
            "# Sentinel-ADF — Android Defense Forensics\n\n"
            f'<div class="sentinel-warning">{html.escape(LEGAL_NOTICE)}</div>'
        )
        with gr.Row():
            operator = gr.Textbox(label="Operator name", placeholder="Required for custody record")
            case_id = gr.Textbox(label="Case ID", placeholder="Case-2025-001")
            authorization_reference = gr.Textbox(
                label="Authorization / warrant reference", placeholder="Reference number"
            )
        consent = gr.Checkbox(
            label=(
                "I confirm I have explicit written authorization to examine this device "
                "and understand my legal obligations under applicable law."
            ),
            value=False,
        )
        with gr.Row():
            detect = gr.Button("Detect device", interactive=False)
            acquire = gr.Button("Acquire evidence", variant="primary", interactive=False)
            export = gr.Button("Export evidence ZIP", interactive=False)
        device_status = gr.Markdown("**Connection:** No device checked yet")
        coverage = gr.Markdown(COVERAGE_TEXT)
        gr.Markdown("## Progress & Audit Stream")
        audit_stream = gr.HTML('<progress value="0" max="100" style="width:100%"></progress>')
        audit_file = gr.File(label="Download audit_log.jsonl", interactive=False)
        gr.Markdown("## Artifact Tabs")
        with gr.Tabs():
            with gr.Tab("SMS"):
                sms_table = gr.Dataframe(label="SMS / MMS", interactive=False)
            with gr.Tab("Call Logs"):
                call_table = gr.Dataframe(label="Call logs", interactive=False)
            with gr.Tab("Contacts"):
                contact_table = gr.Dataframe(label="Contacts", interactive=False)
            with gr.Tab("Messaging (WhatsApp / Signal / Telegram)"):
                message_table = gr.Dataframe(
                    label="Recovered messaging database rows — provenance is mandatory",
                    interactive=False,
                )
            with gr.Tab("Device & Network"):
                device_json = gr.JSON(label="Device, identifiers, Wi-Fi, Bluetooth, network, and location")
            with gr.Tab("Packages"):
                package_table = gr.Dataframe(label="Installed packages, permissions, install times, APK SHA-256", interactive=False)
            with gr.Tab("Media & Location"):
                media_table = gr.Dataframe(label="Public media EXIF / GPS", interactive=False)
        export_status = gr.Markdown()
        evidence_zip = gr.File(label="Evidence ZIP", interactive=False)

        consent.change(
            toggle_actions,
            inputs=consent,
            outputs=[detect, acquire, export],
        )
        detect.click(
            detect_callback,
            inputs=[consent, operator, case_id, authorization_reference],
            outputs=[device_status, session_state, coverage, audit_file, audit_stream],
        )
        acquire.click(
            acquire_callback,
            inputs=[consent, session_state],
            outputs=[
                device_status,
                sms_table,
                call_table,
                contact_table,
                message_table,
                package_table,
                media_table,
                device_json,
                audit_file,
                audit_stream,
                coverage,
            ],
        )
        export.click(
            export_callback,
            inputs=[consent, session_state],
            outputs=[export_status, evidence_zip, audit_stream],
        )
    return demo


demo = build_app()

if __name__ == "__main__":
    # Binding to loopback is intentional: this is a local forensic workstation
    # dashboard, not a remotely exposed service.
    demo.launch(server_name="127.0.0.1", inbrowser=True)
