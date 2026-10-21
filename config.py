"""Configuration and non-secret constants for Sentinel-ADF.

The values in this module are intentionally boring: acquisition policy belongs in
code and in the audit trail, not in environment-dependent magic.  All device
access in the project is read-only; the output directory is on the workstation.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Final


def _resolve_adb_path() -> str:
    """Find ADB on PATH or in common Android SDK locations.

    Platform-Tools is not a Python package and must not be downloaded or
    installed silently by a forensic application.  We do, however, recognize
    the standard SDK locations so a user does not have to set an environment
    variable when ``adb.exe`` is already installed.
    """

    configured = os.environ.get("SENTINEL_ADB_PATH", "").strip()
    if configured:
        return configured
    on_path = shutil.which("adb")
    if on_path:
        return on_path

    candidates: list[Path] = []
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(variable, "").strip()
        if value:
            root = Path(value).expanduser()
            candidates.extend((root / "platform-tools" / "adb.exe", root / "platform-tools" / "adb"))
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        candidates.extend(
            (
                Path(local_app_data) / "Android" / "Sdk" / "platform-tools" / "adb.exe",
                Path(local_app_data) / "Android" / "Sdk" / "platform-tools" / "adb",
            )
        )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return "adb"


PROJECT_NAME: Final[str] = "Sentinel-ADF"
ADB_PATH: Final[str] = _resolve_adb_path()
OUTPUT_DIRECTORY: Final[Path] = Path(
    os.environ.get("SENTINEL_OUTPUT_DIR", "evidence_packages")
).expanduser().resolve()

LEGAL_NOTICE: Final[str] = (
    "Sentinel-ADF is for consensual examinations, law-enforcement work supported "
    "by proper legal authority, and authorized security audits only. It does not "
    "bypass encryption, secure boot, Android security controls, or account security. "
    "The operator is responsible for authorization, minimization, and legal review."
)
READ_ONLY_NOTICE: Final[str] = (
    "All device commands issued by Sentinel-ADF are read-only. Files are written "
    "only on the forensic workstation. Physical imaging is disabled unless the "
    "operator explicitly authorizes a documented read-only operation."
)

ARTIFACT_URIS: Final[dict[str, str]] = {
    "sms": "content://sms/",
    "calls": "content://call_log/calls/",
    "contacts": "content://contacts/phones/",
}

DATABASE_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "sms_mms": (
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
    ),
    "contacts": (
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
    ),
    "whatsapp": (
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/data/data/com.whatsapp/databases/wa.db",
    ),
    "signal": (
        "/data/data/org.thoughtcrime.securesms/databases/signal.sqlite",
    ),
    "telegram": (
        "/data/data/org.telegram.messenger/files/cache4.db",
    ),
    "chrome_history": (
        "/data/data/com.android.chrome/app_chrome/Default/History",
    ),
}

PUBLIC_MEDIA_DIRECTORY: Final[str] = "/sdcard/DCIM"
PUBLIC_STORAGE_ROOT: Final[str] = "/sdcard"
WIFI_CONFIG_PATH: Final[str] = "/data/misc/wifi/WifiConfigStore.xml"

# A small allow-list is useful both as documentation and as a guard against
# accidentally turning an evidence tool into a remote command runner.
READ_ONLY_SHELL_BINARIES: Final[frozenset[str]] = frozenset(
    {
        "cat",
        "dumpsys",
        "find",
        "getprop",
        "id",
        "ls",
        "pm",
        "readlink",
        "settings",
        "sha256sum",
        "su",
        "test",
        "which",
    }
)


def ensure_output_directory() -> Path:
    """Create and return the workstation-side evidence directory."""

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIRECTORY


def new_case_directory(case_id: str) -> Path:
    """Create a case directory using a filesystem-safe case identifier."""

    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_id)
    safe = safe.strip("._") or "case"
    root = ensure_output_directory() / safe
    root.mkdir(parents=True, exist_ok=True)
    return root
