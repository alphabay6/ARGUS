"""Read-only Android acquisition and tier detection.

This module deliberately separates device access from parsing.  It never sends a
write command to Android.  Host-side output is returned as buffers (or written
by the caller), allowing the caller to hash evidence immediately after a host
file is created.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

try:  # adbutils is required in production, but keep import errors actionable.
    import adbutils
except ImportError:  # pragma: no cover - exercised on minimal workstations
    adbutils = None  # type: ignore[assignment]

from config import (
    ADB_PATH,
    ARTIFACT_URIS,
    DATABASE_PATHS,
    LEGAL_NOTICE,
    OUTPUT_DIRECTORY,
    PUBLIC_MEDIA_DIRECTORY,
    READ_ONLY_NOTICE,
    WIFI_CONFIG_PATH,
)
from custody import AuditLogger


@dataclass(frozen=True)
class CommandResult:
    """Captured result of a read-only ADB invocation."""

    stdout: bytes
    stderr: bytes
    returncode: int

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def error_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


@dataclass
class DeviceInfo:
    """Device properties and capability decisions recorded in the manifest."""

    serial: str
    model: str = "unknown"
    android_version: str = "unknown"
    sdk: int | None = None
    adb_state: str = "unknown"
    rooted: bool = False
    tier: str = "Tier 1"
    physical_capable: bool = False
    crypto_state: str = "unknown"
    crypto_type: str = "unknown"
    userdata_block_device: str = ""
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "model": self.model,
            "android_version": self.android_version,
            "sdk": self.sdk,
            "adb_state": self.adb_state,
            "rooted": self.rooted,
            "tier": self.tier,
            "physical_capable": self.physical_capable,
            "crypto_state": self.crypto_state,
            "crypto_type": self.crypto_type,
            "userdata_block_device": self.userdata_block_device,
            "limitations": list(self.limitations),
        }


@dataclass
class AcquisitionBundle:
    """Raw host-side buffers and command outputs for the parser layer."""

    device: DeviceInfo
    content_queries: dict[str, str] = field(default_factory=dict)
    system_outputs: dict[str, str] = field(default_factory=dict)
    package_output: str = ""
    package_dumpsys: str = ""
    package_hashes: dict[str, str] = field(default_factory=dict)
    database_buffers: dict[str, bytes] = field(default_factory=dict)
    public_media: dict[str, bytes] = field(default_factory=dict)
    public_files: dict[str, bytes] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


class ADBClient:
    """Small audited wrapper around ADB with no write-capable API."""

    def __init__(self, audit: AuditLogger, *, adb_path: str = ADB_PATH):
        self.audit = audit
        self.adb_path = adb_path
        self.serial: str | None = None
        # Keep the state reported by ``adb devices`` so a connected but
        # unauthorized/offline phone can be explained instead of being reduced
        # to the misleading message "no device".
        self.device_states: list[tuple[str, str]] = []
        self.device_probe_error: str = ""

    def _display(self, args: Sequence[str]) -> str:
        return shlex.join([self.adb_path, *[str(arg) for arg in args]])

    def run(self, args: Sequence[str], *, timeout: int = 120) -> CommandResult:
        """Run an ADB command after logging it as read-only."""

        normalized = [str(arg) for arg in args]
        command = self._display(normalized)
        self.audit.log(
            "adb_command_before_execution",
            details={"command": command, "read_only": True},
        )
        try:
            completed = subprocess.run(
                [self.adb_path, *normalized],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.audit.log(
                "adb_command_failed",
                details={"command": command, "error": str(exc)},
            )
            return CommandResult(b"", str(exc).encode("utf-8"), 1)
        result = CommandResult(completed.stdout, completed.stderr, completed.returncode)
        if result.returncode != 0:
            self.audit.log(
                "adb_command_nonzero",
                details={
                    "command": command,
                    "returncode": result.returncode,
                    "stderr": result.error_text[:1000],
                },
            )
        return result

    def list_devices(self) -> list[str]:
        """Enumerate devices and retain unauthorized/offline states for diagnosis.

        A USB connection alone does not make a device available to ADB.  The
        Android device must have USB debugging enabled, be unlocked, and have
        accepted this workstation's RSA key.  ``adbutils.device_list()`` only
        returns usable devices, so ``adb devices -l`` is also queried to retain
        states such as ``unauthorized`` and ``offline``.
        """

        self.audit.log(
            "adbutils_device_enumeration_before_execution",
            details={"library": "adbutils", "read_only": True},
        )
        adbutils_serials: list[str] = []
        if adbutils is not None:
            try:
                adbutils_serials = [
                    str(device.serial) for device in adbutils.adb.device_list()
                ]
            except Exception as exc:  # adbutils may not use a custom adb binary
                self.audit.log(
                    "adbutils_device_enumeration_failed",
                    details={"error": str(exc)},
                )

        result = self.run(("devices", "-l"), timeout=30)
        self.device_probe_error = result.error_text.strip()
        states: list[tuple[str, str]] = []
        for line in result.text.splitlines()[1:]:
            fields = line.split()
            # ADB prints rows as ``serial state [descriptive fields...]``.
            # Ignore daemon notices and blank lines.
            if fields and len(fields) > 1 and not fields[0].startswith("*"):
                states.append((fields[0], fields[1]))
        self.device_states = states

        command_serials = [serial for serial, state in states if state == "device"]
        if command_serials:
            return command_serials
        # If the configured executable could not be run, adbutils may still
        # have found a device through the default ADB installation.  Preserve
        # the old fallback in that narrow case; normal unauthorized rows must
        # not be hidden by a second enumeration path.
        if not states and result.returncode != 0 and adbutils_serials:
            self.device_states = [(serial, "device") for serial in adbutils_serials]
            return adbutils_serials
        return []

    def bind(self, serial: str) -> None:
        """Select a device serial for subsequent commands."""

        self.serial = serial
        self.audit.log(
            "device_selected",
            details={"serial": serial, "read_only": True},
        )

    def run_device(self, args: Sequence[str], *, timeout: int = 120) -> CommandResult:
        if not self.serial:
            raise RuntimeError("No ADB device has been selected")
        return self.run(("-s", self.serial, *[str(arg) for arg in args]), timeout=timeout)

    def shell(self, *args: str, timeout: int = 120) -> CommandResult:
        """Run a direct, non-interactive read-only shell command."""

        return self.run_device(("shell", *args), timeout=timeout)

    def shell_as_root(self, command: str, *, timeout: int = 120) -> CommandResult:
        """Run one read-only command through ``su -c`` after root detection."""

        return self.run_device(("shell", "su", "-c", command), timeout=timeout)

    def exec_out(self, *args: str, timeout: int = 300) -> CommandResult:
        """Capture binary stdout from a read-only command."""

        return self.run_device(("exec-out", *args), timeout=timeout)

    def read_file(self, remote_path: str, *, as_root: bool = False) -> bytes | None:
        """Read a device file into a host buffer; never creates a device file."""

        if as_root:
            result = self.exec_out("su", "-c", f"cat {shlex.quote(remote_path)}")
        else:
            result = self.exec_out("cat", remote_path)
        if result.returncode != 0:
            self.audit.log(
                "device_file_unavailable",
                artifact=remote_path,
                details={"as_root": as_root, "stderr": result.error_text[:1000]},
            )
            return None
        self.audit.log(
            "device_file_read",
            artifact=remote_path,
            details={"bytes": len(result.stdout), "as_root": as_root},
        )
        return result.stdout


def _first_property(client: ADBClient, name: str) -> str:
    result = client.shell("getprop", name)
    return result.text.strip().splitlines()[0].strip() if result.text.strip() else ""


def _sdk_number(value: str) -> int | None:
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def detect_root(client: ADBClient) -> bool:
    """Detect root only by observing a ``uid=0`` result from ``su id``."""

    result = client.shell("su", "-c", "id", timeout=30)
    rooted = result.returncode == 0 and bool(re.search(r"\buid=0(?:\(|\s|$)", result.text))
    client.audit.log(
        "root_capability_checked",
        details={"root_available": rooted, "observed": result.text.strip()[:500]},
    )
    return rooted


def probe_physical_capability(client: ADBClient, rooted: bool) -> tuple[bool, str, str, str]:
    """Probe raw-image prerequisites without opening or changing a block device."""

    if not rooted:
        return False, "unknown", "unknown", ""
    crypto_state = _first_property(client, "ro.crypto.state") or "unknown"
    crypto_type = _first_property(client, "ro.crypto.type") or "unknown"
    path_result = client.shell_as_root(
        "if test -r /dev/block/by-name/userdata; then "
        "readlink -f /dev/block/by-name/userdata; else echo UNREADABLE; fi",
        timeout=30,
    )
    block_device = path_result.text.strip().splitlines()[-1] if path_result.text.strip() else ""
    hard_stop = crypto_state.lower() in {"encrypted", "unknown"} or crypto_type.lower() in {
        "file",
        "block",
        "unknown",
    }
    capable = (
        not hard_stop
        and bool(block_device)
        and block_device != "UNREADABLE"
        and path_result.returncode == 0
    )
    client.audit.log(
        "physical_capability_probed",
        details={
            "capable": capable,
            "crypto_state": crypto_state,
            "crypto_type": crypto_type,
            "userdata_block_device": block_device,
            "hard_stop": hard_stop,
        },
    )
    return capable, crypto_state, crypto_type, block_device


def discover_device(client: ADBClient) -> DeviceInfo:
    """Enumerate and classify one connected Android device.

    The resulting error distinguishes an absent ADB setup from a phone that is
    physically connected but waiting for authorization.  This is important on
    Windows, where a missing driver or a hidden RSA prompt otherwise looks like
    an acquisition failure.
    """

    devices = client.list_devices()
    if not devices:
        if client.device_states:
            observed = ", ".join(
                f"{serial} ({state})" for serial, state in client.device_states
            )
            if any(state == "unauthorized" for _, state in client.device_states):
                message = (
                    "ADB sees a connected device, but it is unauthorized "
                    f"({observed}). Unlock the phone, enable USB debugging, "
                    "accept the 'Allow USB debugging?' RSA prompt for this "
                    "computer, then click Detect device again. A USB cable alone "
                    "does not authorize ADB."
                )
            elif any(state == "offline" for _, state in client.device_states):
                message = (
                    "ADB sees the device as offline "
                    f"({observed}). Reconnect the cable, keep the phone unlocked, "
                    "verify the USB debugging prompt, and restart the ADB server "
                    "before trying Detect device again."
                )
            elif any(state in {"no", "no-permissions"} for _, state in client.device_states):
                message = (
                    "ADB sees the device but cannot access it "
                    f"({observed}). Check the USB driver/permissions, use a data "
                    "cable, unlock the phone, and accept the USB debugging prompt."
                )
            else:
                message = f"ADB reported no usable device ({observed})."
        elif client.device_probe_error:
            message = (
                f"ADB could not enumerate devices using '{client.adb_path}': "
                f"{client.device_probe_error}. Install Android Platform-Tools, "
                "put adb on PATH, or set SENTINEL_ADB_PATH to adb.exe."
            )
        else:
            message = (
                "ADB reported no connected device. Run 'adb devices -l' to "
                "verify the host result. A USB cable alone is not enough: enable "
                "Developer options and USB debugging, unlock the phone, use a "
                "data cable, and accept the RSA authorization prompt."
            )
        client.audit.log(
            "device_detection_failed",
            details={
                "reason": message,
                "observed_states": [
                    {"serial": serial, "state": state}
                    for serial, state in client.device_states
                ],
                "adb_path": client.adb_path,
            },
        )
        raise RuntimeError(message)
    serial = devices[0]
    client.bind(serial)
    model = _first_property(client, "ro.product.model") or "unknown"
    version = _first_property(client, "ro.build.version.release") or "unknown"
    sdk_text = _first_property(client, "ro.build.version.sdk")
    sdk = _sdk_number(sdk_text)
    rooted = detect_root(client)
    physical, crypto_state, crypto_type, block = probe_physical_capability(client, rooted)
    limitations: list[str] = [
        "Logical acquisition is not a claim that all device data is recoverable.",
        "Encrypted app-private data remains unavailable without an authorized, supported capability.",
    ]
    if sdk is not None and sdk >= 31:
        limitations.append(
            "Android API 31+ restricts legacy content queries and adb backup; public storage "
            "and package metadata are used as a fallback."
        )
    if crypto_state.lower() in {"encrypted", "unknown"}:
        limitations.append(
            "Physical imaging is a hard stop because device encryption state is encrypted or unknown."
        )
    tier = "Tier 3" if physical else ("Tier 2" if rooted else "Tier 1")
    info = DeviceInfo(
        serial=serial,
        model=model,
        android_version=version,
        sdk=sdk,
        adb_state="device",
        rooted=rooted,
        tier=tier,
        physical_capable=physical,
        crypto_state=crypto_state,
        crypto_type=crypto_type,
        userdata_block_device=block,
        limitations=limitations,
    )
    client.audit.log("device_capabilities_assessed", details=info.as_dict())
    return info


def _query_content(client: ADBClient, name: str, uri: str) -> str:
    """Run a legacy provider query and distinguish no-result from failure."""

    result = client.shell("content", "query", "--uri", uri, timeout=120)
    text = result.text
    if "No result found" in text or not text.strip():
        client.audit.log(
            "absence_of_evidence",
            artifact=name,
            details={"uri": uri, "reason": "content provider returned no result"},
        )
        return ""
    if result.returncode != 0:
        client.audit.log(
            "content_query_restricted",
            artifact=name,
            details={"uri": uri, "stderr": result.error_text[:1000]},
        )
        return ""
    client.audit.log("content_query_collected", artifact=name, details={"uri": uri})
    return text


def _package_paths(package_output: str) -> list[tuple[str, str]]:
    paths: list[tuple[str, str]] = []
    for line in package_output.splitlines():
        match = re.match(r"\s*package:(.+?)=(\S+)\s*$", line.strip())
        if match:
            paths.append((match.group(2), match.group(1)))
    return paths


def _collect_package_metadata(client: ADBClient) -> tuple[str, str, dict[str, str]]:
    package_result = client.shell("pm", "list", "packages", "-f", "-i", timeout=180)
    package_output = package_result.text
    dumpsys = client.shell("dumpsys", "package", timeout=240).text
    package_hashes: dict[str, str] = {}
    # APK hashes are obtained by a read-only digest command.  A hash may be
    # unavailable when Android denies access; that limitation is retained.
    for package, apk_path in _package_paths(package_output)[:2000]:
        digest_result = client.shell("sha256sum", apk_path, timeout=30)
        if digest_result.returncode != 0 and client.serial:
            digest_result = client.shell_as_root(f"sha256sum {shlex.quote(apk_path)}", timeout=30)
        digest = digest_result.text.strip().split()[0] if digest_result.returncode == 0 else "UNAVAILABLE"
        if re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            package_hashes[package] = digest.lower()
        client.audit.log(
            "apk_hash_observed",
            artifact=package,
            sha256=digest if re.fullmatch(r"[0-9a-fA-F]{64}", digest) else "",
            details={"apk_path": apk_path, "hash_available": digest != "UNAVAILABLE"},
        )
    return package_output, dumpsys, package_hashes


def acquire_bundle(client: ADBClient, device: DeviceInfo) -> AcquisitionBundle:
    """Collect the tier-appropriate raw buffers and read-only diagnostics."""

    bundle = AcquisitionBundle(device=device, limitations=list(device.limitations))
    bundle.system_outputs["iphonesubinfo"] = client.shell("dumpsys", "iphonesubinfo").text
    bundle.system_outputs["android_id"] = client.shell("settings", "get", "secure", "android_id").text
    bundle.system_outputs["wifi_dumpsys"] = client.shell("dumpsys", "wifi", timeout=180).text
    bundle.system_outputs["bluetooth"] = client.shell("dumpsys", "bluetooth_manager", timeout=120).text
    bundle.system_outputs["network"] = client.shell("dumpsys", "connectivity", timeout=120).text
    bundle.system_outputs["location"] = client.shell("dumpsys", "location", timeout=180).text

    if device.sdk is not None and device.sdk < 31:
        for name, uri in ARTIFACT_URIS.items():
            bundle.content_queries[name] = _query_content(client, name, uri)
    else:
        bundle.limitations.append(
            "Skipped content query and legacy adb backup on API 31+ because modern Android restricts them."
        )
        client.audit.log(
            "modern_android_fallback",
            details={"sdk": device.sdk, "fallback": "public_storage_and_package_metadata"},
        )

    (
        bundle.package_output,
        bundle.package_dumpsys,
        bundle.package_hashes,
    ) = _collect_package_metadata(client)

    if device.rooted:
        for category, paths in DATABASE_PATHS.items():
            for path in paths:
                data = client.read_file(path, as_root=True)
                if data is not None:
                    bundle.database_buffers[path] = data
                wal = client.read_file(f"{path}-wal", as_root=True)
                if wal is not None:
                    bundle.database_buffers[f"{path}-wal"] = wal
                shm = client.read_file(f"{path}-shm", as_root=True)
                if shm is not None:
                    bundle.database_buffers[f"{path}-shm"] = shm
        wifi_config = client.read_file(WIFI_CONFIG_PATH, as_root=True)
        if wifi_config is not None:
            bundle.system_outputs["wifi_config"] = wifi_config.decode("utf-8", errors="replace")
        bundle.system_outputs["accounts"] = client.shell_as_root("dumpsys account", timeout=120).text
    else:
        bundle.limitations.append(
            "Non-rooted logical acquisition cannot access app-private encrypted databases."
        )

    # Public media is listed and read one file at a time, keeping the source
    # untouched.  A size cap prevents a dashboard action from becoming an
    # uncontrolled full-storage copy.
    media_listing = client.shell("find", PUBLIC_MEDIA_DIRECTORY, "-type", "f", timeout=120).text
    for remote in [line.strip() for line in media_listing.splitlines() if line.strip()][:500]:
        if not re.search(r"\.(?:jpe?g|png|webp|heic|mp4|mov|3gp)$", remote, re.I):
            continue
        media = client.read_file(remote)
        if media is not None and len(media) <= 50 * 1024 * 1024:
            bundle.public_media[remote] = media
        elif media is not None:
            bundle.limitations.append(f"Skipped oversized public media file: {remote}")

    # Public, non-media storage is intentionally limited to common user-facing
    # documents.  It supplies the API 31+ fallback without silently copying all
    # of /sdcard.
    public_listing = client.shell(
        "find", "/sdcard/Download", "/sdcard/Documents", "-type", "f", timeout=120
    ).text
    for remote in [line.strip() for line in public_listing.splitlines() if line.strip()][:300]:
        if not re.search(r"\.(?:txt|csv|json|xml|pdf|vcf|log)$", remote, re.I):
            continue
        content = client.read_file(remote)
        if content is not None and len(content) <= 10 * 1024 * 1024:
            bundle.public_files[remote] = content

    client.audit.log(
        "acquisition_buffers_collected",
        details={
            "content_queries": len(bundle.content_queries),
            "database_buffers": len(bundle.database_buffers),
            "public_media_files": len(bundle.public_media),
            "public_files": len(bundle.public_files),
            "tier": device.tier,
        },
    )
    return bundle


def acquire_read_only_physical_image(
    client: ADBClient,
    device: DeviceInfo,
    *,
    authorized: bool,
    max_bytes: int = 0,
) -> bytes | None:
    """Optionally stream a raw image after an explicit authorization decision.

    This function is never called by the normal dashboard flow.  It refuses
    encrypted/unknown devices and requires the caller to document authorization.
    ``dd if=...`` performs no write on Android, but imaging changes the device's
    observable state through normal reads and is therefore visibly audited.
    """

    if not authorized:
        client.audit.log(
            "physical_image_refused",
            details={"reason": "explicit authorization was not supplied"},
        )
        return None
    if device.tier != "Tier 3" or not device.userdata_block_device:
        client.audit.log(
            "physical_image_refused",
            details={"reason": "raw read capability unavailable", "tier": device.tier},
        )
        return None
    if device.crypto_state.lower() in {"encrypted", "unknown"}:
        client.audit.log(
            "physical_image_hard_stop",
            details={"reason": "FDE/FBE or unknown encryption state"},
        )
        return None
    command = (
        f"dd if={shlex.quote(device.userdata_block_device)} bs=4M"
        + (f" count={(max_bytes + 4194303) // 4194304}" if max_bytes else "")
    )
    client.audit.log(
        "physical_image_started",
        artifact=device.userdata_block_device,
        details={"read_only": True, "authorization": "operator supplied"},
    )
    result = client.exec_out("su", "-c", command, timeout=3600)
    if result.returncode != 0:
        client.audit.log(
            "physical_image_failed",
            details={"stderr": result.error_text[:1000]},
        )
        return None
    client.audit.log("physical_image_buffer_collected", details={"bytes": len(result.stdout)})
    return result.stdout


__all__ = [
    "ADBClient",
    "AcquisitionBundle",
    "CommandResult",
    "DeviceInfo",
    "acquire_bundle",
    "acquire_read_only_physical_image",
    "detect_root",
    "discover_device",
]
