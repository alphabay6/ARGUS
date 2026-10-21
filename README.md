# Sentinel-ADF (Android Defense Forensics)

> ## LEGAL AND ETHICAL NOTICE
> **Use this software only for a consensual examination, a law-enforcement examination supported by a proper warrant or other applicable authority, or an authorized security audit.** The operator must obtain written authorization, preserve the original device, follow applicable law and organizational policy, and document scope and minimization. Sentinel-ADF is not a covert tool and does not bypass Android encryption, Secure Boot, a locked bootloader, a TEE, account security, or application access controls. It does not recover passwords, 2FA secrets, or encryption keys.

Sentinel-ADF is a local, Python-based Android acquisition dashboard. It uses a tiered capability model instead of treating one ADB command as a complete acquisition:

1. **Tier 1 — non-rooted logical:** provider queries where supported, publicly readable storage, diagnostics, and package metadata.
2. **Tier 2 — rooted/privileged logical:** read-only copies of selected application databases, including WAL-aware SQLite recovery and conservative carving.
3. **Tier 3 — physical/filesystem capability:** capability detection only by default. A separate function can stream a raw image only after an explicit authorization decision and only when encryption is not a hard stop.

Every device command is written to a hash-chained JSONL audit stream before execution. Host-side JSON artifacts are hashed immediately after writing. The export includes `audit_log.jsonl`, `chain_of_custody.json`, `MANIFEST.sha256`, and all normalized artifact files.

## Prerequisites

- Python **3.10 or newer** (Python 3.11+ is recommended).
- Android SDK Platform-Tools and a working `adb` executable on `PATH`, or set `SENTINEL_ADB_PATH` to its full path.
- An Android device with USB debugging enabled and an authorized workstation key. Confirm the device appears as `device`, not `unauthorized`, with `adb devices -l`.
- A forensic workstation with enough storage for selected public media and the resulting evidence package.
- Written consent, a warrant, or an authorized audit scope. Record its reference in the dashboard.
- Root/privileged access only where it is lawfully authorized and already available. Sentinel-ADF does not exploit or obtain root.

On Windows, install Android Platform-Tools and verify, for example:

```powershell
adb version
adb devices -l
```

## Installation

The project does not depend on the unpublished `android-backup-extractor`
PyPI name.  Unencrypted `.ab` parsing is implemented defensively in `parse.py`,
and the SQLite recovery path is implemented locally as well.  This keeps a
fresh installation reproducible on Windows.

Recommended setup:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python app.py
```

When `app.py` starts, it checks the active Python interpreter for every runtime
package and automatically runs `python -m pip install -r requirements.txt` if a
package is missing or below the required version.  Installation is host-side
only; no package is installed on the Android device.  To use an offline or
centrally managed workstation, install the requirements manually and disable
the bootstrap check:

```powershell
$env:SENTINEL_AUTO_INSTALL = "0"
python -m pip install -r requirements.txt
python app.py
```

`python-magic` may require a libmagic installation on some Windows workstations.
If it is unavailable at runtime, Sentinel-ADF falls back to Python's MIME
file guesser; it does not treat that fallback as a forensic file-type proof.

The default host output directory is `evidence_packages`. It can be changed without changing device behavior:

```powershell
$env:SENTINEL_OUTPUT_DIR = "D:\Cases\Sentinel-ADF"
# Optional:
$env:SENTINEL_ADB_PATH = "C:\Android\platform-tools\adb.exe"
python app.py
```

The dashboard binds to `127.0.0.1` only. Do not expose it through a proxy or network tunnel during an examination without a separate security review.

## ADB detection troubleshooting

A USB cable only provides a physical connection; it does not make a phone an
ADB device. Verify the host-side result before starting an examination:

```powershell
adb devices -l
```

The expected state is `device`. If the state is `unauthorized`, unlock the
phone, enable **Developer options > USB debugging**, and accept the **Allow USB
debugging?** RSA prompt. If there is no row at all, use a data-capable cable,
select File Transfer/Android Auto in the USB notification, install the OEM USB
driver on Windows, and try another USB port. Restarting the host ADB server can
help after the driver or authorization state changes:

```powershell
adb kill-server
adb start-server
adb devices -l
```

Sentinel-ADF now reports `unauthorized`, `offline`, missing `adb`, and an empty
ADB device list separately instead of showing every case as "no authorized ADB
device". It also checks the standard Android SDK `platform-tools` directory.
For a non-standard installation, set the full executable path before launching:

```powershell
$env:SENTINEL_ADB_PATH = "C:\Android\platform-tools\adb.exe"
python app.py
```

## Operation

1. Connect the device and verify the ADB authorization prompt on the device.
2. Start the dashboard with `python app.py` and open the displayed local URL.
3. Enter operator, case, and authorization-reference information.
4. Check the authorization checkbox. Every action button remains disabled until it is checked, and callbacks repeat the check server-side.
5. Click **Detect device**. The dashboard records model, Android release/API, full serial in custody data, root result, encryption probe, and the selected tier. The UI displays only a truncated serial.
6. Click **Acquire evidence**. Empty provider output is recorded as absence of evidence. API 31+ restrictions are recorded as a limitation and trigger the public-storage/package fallback.
7. Review the tables and the audit stream. Messaging rows include their database and one of `LIVE`, `WAL-PENDING`, `FREELIST`, or `CARVED-UNALLOC` provenance labels.
8. Click **Export evidence ZIP**. The final audit state is sealed, `MANIFEST.sha256` is generated, and the ZIP is written on the workstation. The ZIP digest is shown in the dashboard.

The physical image function is intentionally not part of the normal dashboard flow. Any physical read must have a separately documented authorization decision and must stop for FDE/FBE or unknown encryption state.

## Supported artifacts and tier availability

| Artifact | Tier 1 | Tier 2 | Tier 3 / notes |
|---|:---:|:---:|---|
| SMS/MMS provider fields (`_id`, address, date, body, type, read, seen) | API < 31 only | SQLite provider DB plus recovery | Physical image does not defeat encryption |
| Call logs (`number`, date, duration, name, type, country ISO, geocoded location) | API < 31 only | Provider/database access where available | Same limitation |
| Contacts (display name, number, notes, last contacted) | API < 31 only | Contacts database access where available | Same limitation |
| WhatsApp `msgstore.db` / `wa.db` | No | Authorized root, live + WAL + carving | App-level encryption and missing keys remain limitations |
| Signal / Telegram databases | No | Authorized root, live + WAL + carving | Encrypted or inaccessible data is not bypassed |
| Installed packages, permissions, install/update times | Yes, where readable | Yes | APK SHA-256 is recorded when `sha256sum` is permitted |
| Serial, model, Android/API, Android ID | Yes | Yes | IMEI/MEID is attempted through `dumpsys iphonesubinfo` where permitted |
| Wi-Fi, Bluetooth, active network, location diagnostics | Public diagnostics | Adds root-only Wi-Fi config when readable | OEM output differs and is retained as structured raw diagnostics |
| Public `/sdcard/DCIM` media and EXIF/GPS | Yes, where readable | Yes | Workstation-side EXIF parsing; media is not silently modified |
| Selected public Download/Documents files | API 31+ fallback | Yes | Metadata and SHA-256 are written to `public_storage.json` |
| Chrome History | No | Root-only read attempt | FBE/app access can be a hard stop |
| Raw physical/filesystem image | Capability is not present | Only if Tier 3 probe succeeds | Explicit authorization required; encrypted/unknown state is a hard stop |

This table describes attempted access, not a guarantee of recovery. Android version, OEM policy, user lock state, app encryption, permissions, deleted-page reuse, WAL checkpoints, and device state affect coverage.

## Evidence package and integrity

The case directory contains normalized JSON files such as:

- `sms.json`, `call_logs.json`, `contacts.json`
- `messaging.json` with SQLite source/table/provenance
- `packages.json` with permissions and APK hashes where available
- `media_location.json`, `public_storage.json`
- `device_network.json` and `limitations.json`
- `audit_log.jsonl`
- `chain_of_custody.json`
- `MANIFEST.sha256`

`custody.py` uses SHA-256 for files and a previous-entry hash for every audit event. The manifest lists every shipped file **except `MANIFEST.sha256` itself**, because a manifest containing its own digest would be self-referential and unstable. The export status states this explicitly. Verify a case directory programmatically with `custody.verify_manifest(...)` before review.

The chain-of-custody JSON contains `case_id`, operator, full device serial, start/end times, acquisition tier, authorization reference, and ordered events with timestamp, action, artifact, and SHA-256 fields. Preserve the original ZIP and record its displayed ZIP digest in the case record.

## Source-device and coverage limitations

- Device commands are read-only and are audited before execution. The suite does not issue `rm`, `mkdir`, package installation, content-provider writes, database writes, or bootloader operations to Android.
- Host-side parsing uses temporary workstation files only where the Python SQLite library needs a file handle; these are not placed in the evidence directory.
- Non-rooted logical acquisition cannot access app-private encrypted databases.
- Android 12/API 31 and later restricts legacy `content query` and `adb backup` behavior. Sentinel-ADF logs the restriction instead of silently presenting empty data as complete.
- SQLite carving is an equivalent conservative record-carving implementation, not a promise of complete deleted-record recovery. It does not decrypt app databases or reconstruct overwritten pages.
- An empty result means no evidence was returned by that access path; it is not proof of absence.

## Five-module layout

- `config.py` — constants, paths, target URIs/database paths, and legal/read-only notices.
- `custody.py` — SHA-256, append-only hash-chained audit, custody, manifest, and ZIP helpers.
- `acquire.py` — audited ADB/adbutils enumeration, tier detection, read-only collection, and optional guarded raw stream.
- `parse.py` — Pydantic normalization, content/provider parsing, SQLite WAL/freelist/unallocated recovery, EXIF, package, dumpsys, and `.ab` parsing.
- `app.py` — local Gradio Blocks UI, consent gate, progress/audit display, artifact tables, and export orchestration.
