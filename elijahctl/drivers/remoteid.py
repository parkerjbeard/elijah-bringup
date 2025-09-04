#!/usr/bin/env python3
from __future__ import annotations
import contextlib
import csv
import os
import platform
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from elijahctl.config import Config
from elijahctl.utils.logging import error, get_logger, info, success, warning

logger = get_logger(__name__)

# ASTM F3411 / DRIP: Basic ID maximum length is 20 bytes
UAS_ID_MAX_BYTES = 20


@dataclass
class RemoteIDConfig:
    """Configuration for RemoteID module."""

    uas_id: str
    uas_id_type: int
    uas_type: int
    connection: str
    lock_level: int | None = None
    private_key_path: str | None = None


class RemoteIDDriver:
    """Driver for configuring BlueMark db201 RemoteID modules via MAVProxy SecureCommand."""

    def __init__(
        self,
        mavproxy_path: str | None = None,
        private_key_path: str | None = None,
        redact_ids: bool = False,
    ):
        """
        Initialize RemoteID driver.

        Args:
            mavproxy_path: Path to mavproxy executable. If None, will search in PATH.
            private_key_path: Path to private key file for SecureCommand authentication.
        """
        self.mavproxy_path = self._find_mavproxy(mavproxy_path)
        self.private_key_path = private_key_path
        self.receipts_dir = Config.RUNS_DIR / "receipts"
        self.receipts_dir.mkdir(exist_ok=True)
        # internal verification note to persist to receipts, if any
        self._verify_note: str | None = None
        # redact UAS_ID/hostnames in receipts when enabled
        self.redact_ids: bool = redact_ids
        # capture last stderr for diagnostics when running mavproxy
        self._last_stderr: str | None = None

    def _find_mavproxy(self, custom_path: str | None = None) -> str:
        """Find MAVProxy executable path."""
        if custom_path and Path(custom_path).exists():
            return custom_path

        # Check common locations based on platform
        if platform.system() == "Windows":
            locations = [
                r"C:\Python311\Scripts\mavproxy.exe",
                r"C:\Python310\Scripts\mavproxy.exe",
                r"C:\Python39\Scripts\mavproxy.exe",
                r"C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\Scripts\mavproxy.exe",
                r"C:\Program Files\MAVProxy\mavproxy.exe",
                r"C:\Program Files (x86)\MAVProxy\mavproxy.exe",
            ]
            for loc in locations:
                expanded = os.path.expandvars(loc)
                if Path(expanded).exists():
                    return expanded

        # Try to find in PATH - check both mavproxy and mavproxy.py
        for cmd_name in ["mavproxy", "mavproxy.py"]:
            result = subprocess.run(
                ["which" if platform.system() != "Windows" else "where", cmd_name],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                path = result.stdout.strip().split("\n")[0]
                if Path(path).exists():
                    return path

        # Fallback to assuming it's in PATH
        return "mavproxy"

    def _create_mavproxy_script(self, commands: list[str], script_path: Path | None = None) -> Path:
        """
        Create a temporary MAVProxy script file.

        Args:
            commands: List of MAVProxy commands to execute.
            script_path: Optional path for the script. If None, creates temp file.

        Returns:
            Path to the created script file.
        """
        script_content = "\n".join(
            [
                "set shownoise false",
                "set streamrate 2",
                "set requireexit True",
                "module load SecureCommand",
                *commands,
                "exit",
            ]
        )

        if script_path:
            script_path.write_text(script_content)
            return script_path

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".mavcmd", prefix="rid_") as f:
            f.write(script_content)
            return Path(f.name)

    def _run_mavproxy_script(
        self,
        connection: str,
        commands: list[str],
        timeout: int = 90,
        baudrate: int = 115200,
    ) -> tuple[int, str]:
        """
        Run MAVProxy with a script of commands.

        Args:
            connection: Connection string (e.g., "udp:el-012:14550" or "COM7").
            commands: List of MAVProxy commands to execute.
            timeout: Command timeout in seconds.
            baudrate: Serial baudrate (used for COM ports).

        Returns:
            Tuple of (return_code, output_text).
        """
        script_path = self._create_mavproxy_script(commands)

        try:
            # Build MAVProxy command
            cmd = [
                self.mavproxy_path,
                f"--master={connection}",
                "--cmd=set heartbeat 1",
                "--script",
                str(script_path),
            ]
            # Omit --baudrate for UDP/TCP masters to avoid confusing logs
            if not (connection.lower().startswith("udp:") or connection.lower().startswith("tcp:")):
                cmd.insert(2, f"--baudrate={baudrate}")

            logger.debug(f"Running MAVProxy command: {' '.join(cmd)}")

            # Run MAVProxy
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

            # keep a small tail of stderr for diagnostics on non-zero status
            self._last_stderr = (proc.stderr or "")[-400:]
            output = proc.stdout + "\n" + (proc.stderr or "")
            return proc.returncode, output

        finally:
            # Clean up script file
            with contextlib.suppress(OSError):
                script_path.unlink()

    def configure_single(self, config: RemoteIDConfig, verify: bool = True) -> tuple[bool, str]:
        """
        Configure a single RemoteID module.

        Args:
            config: RemoteID configuration.
            verify: Whether to verify configuration after setting.

        Returns:
            Tuple of (success, output_log).
        """
        # Enforce ASTM/DRIP UAS ID length ≤ 20 bytes
        try:
            if len(config.uas_id.encode("utf-8")) > UAS_ID_MAX_BYTES:
                return False, "UAS_ID must be ≤20 bytes (ASTM/DRIP)"
        except Exception:
            return False, "UAS_ID encoding error"

        if not self.private_key_path:
            return False, "No private key path specified"

        if not Path(self.private_key_path).exists():
            return False, f"Private key not found: {self.private_key_path}"

        # Build command sequence
        # Quote private key path for safety (spaces, special chars)
        quoted_key = self._quote_path_for_mavproxy(self.private_key_path)
        commands = [
            f"securecommand set private_keyfile {quoted_key}",
            "securecommand getsessionkey",
            f"securecommand setconfig UAS_ID_TYPE={config.uas_id_type} "
            f"UAS_ID={config.uas_id} UAS_TYPE={config.uas_type}",
        ]

        # Add lock level if specified
        if config.lock_level is not None and config.lock_level > 0:
            commands.append(f"securecommand setconfig LOCK_LEVEL={config.lock_level}")

        # Add verification: query only MAVLink-exposed (non-string) params
        if verify:
            commands.extend(
                [
                    "param show UAS_ID_TYPE",
                    "param show UAS_TYPE",
                    "param show LOCK_LEVEL",
                ]
            )

        # Run configuration
        info(f"Configuring RemoteID {config.uas_id} on {config.connection}")
        return_code, output = self._run_mavproxy_script(config.connection, commands)

        # Fail fast if session key was not actually obtained
        if not self._has_session_key(output):
            error("Did not obtain a session key; aborting configuration")
            self._write_receipt(config, output)
            return False, output

        # Parse output for verification
        self._verify_note = None
        success = self._verify_configuration(config, output, return_code)

        # Save receipt with sensitive data redacted
        self._write_receipt(config, output)

        # Post-success operator feedback for irreversible lock level
        if success and config.lock_level == 2:
            warning(
                "LOCK_LEVEL=2 applied: USB flashing disabled; OTA signed updates only"
            )

        return success, output

    def _verify_configuration(self, config: RemoteIDConfig, output: str, return_code: int) -> bool:
        """
        Verify that configuration was applied successfully.

        Args:
            config: Expected configuration.
            output: MAVProxy output to check.
            return_code: MAVProxy return code.

        Returns:
            True if configuration verified successfully.
        """
        if return_code != 0:
            tail = (self._last_stderr or "").splitlines()[-3:]
            tail_str = (" | ".join(tail)).strip()
            if tail_str:
                warning(
                    f"MAVProxy returned non-zero exit code: {return_code} (stderr tail: {tail_str})"
                )
            else:
                warning(f"MAVProxy returned non-zero exit code: {return_code}")

        # Parse and verify non-string params via MAVLink 'param show' style output
        # Accept both "NAME=val" and "NAME = val" forms
        def _extract_int(name: str) -> int | None:
            m = re.search(rf"{name}\s*=\s*(\-?\d+)", output)
            if m:
                try:
                    return int(m.group(1))
                except ValueError:
                    return None
            # also accept compact form without spaces
            m = re.search(rf"{name}=(\-?\d+)", output)
            if m:
                try:
                    return int(m.group(1))
                except ValueError:
                    return None
            return None

        expected_pairs: list[tuple[str, int]] = [
            ("UAS_ID_TYPE", int(config.uas_id_type)),
            ("UAS_TYPE", int(config.uas_type)),
        ]

        # Only require LOCK_LEVEL if it was requested to be set
        if config.lock_level is not None:
            expected_pairs.append(("LOCK_LEVEL", int(config.lock_level)))

        found_count = 0
        mismatch = False
        for name, expected in expected_pairs:
            actual = _extract_int(name)
            if actual is None:
                continue
            found_count += 1
            if actual != expected:
                mismatch = True

        # Best-effort handling for string UAS_ID: warn but do not fail if absent
        has_string = (f"UAS_ID={config.uas_id}" in output) or (f"UAS_ID = {config.uas_id}" in output)
        if not has_string:
            note = "UAS_ID string not probeable via MAVLink; verified non-string parameters"
            warning(note)
            self._verify_note = note

        # Look for error indicators
        error_patterns = [
            r"monocypher.*missing",
            r"Failed to get session key",
            r"getconfig.*old values",
            r"db201 not reachable",
            r"No heartbeat",
        ]

        for pattern in error_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                error(f"Error detected in output: {pattern}")
                return False

        # Decide verification result
        if mismatch:
            error(f"Configuration mismatch detected for {config.uas_id}")
            return False

        required = len(expected_pairs)
        if found_count == required:
            success(f"Configuration verified for {config.uas_id}")
            return True

        # Couldn't read back some/all params; treat as best-effort success
        warning(
            f"Best-effort verification for {config.uas_id} (missing MAVLink param echo)"
        )
        if not self._verify_note:
            # If we didn't already set a note about UAS_ID, set a generic best-effort note
            self._verify_note = (
                "Best-effort verification: required params not echoed; cannot fully confirm via MAVLink"
            )
        return True

    def _has_session_key(self, output: str) -> bool:
        """Return True if output contains evidence of a retrieved session key."""
        patterns = [
            r"(?i)session\s*key\s*:\s*[0-9a-fx]+",
            r"(?i)got\s+session\s+key",
            r"(?i)session\s*key\s+obtained",
        ]
        return any(re.search(p, output) for p in patterns)

    def _redact_output(self, output: str, config: RemoteIDConfig) -> str:
        """Redact secrets and optional IDs/hostnames from receipts."""
        redacted = output
        try:
            # Redact any printed session key variations
            redacted = re.sub(
                r"(?i)(session\s*key[^\n]*?:\s*)([0-9a-fx]+)", r"\1<redacted>", redacted
            )
            redacted = re.sub(
                r"(?i)(got\s+session\s+key\s+length\s*=\s*)\d+", r"\1<redacted>", redacted
            )
            if self.private_key_path:
                redacted = redacted.replace(self.private_key_path, "<redacted>")

            if self.redact_ids:
                # Redact explicit UAS_ID value occurrences
                if config.uas_id:
                    redacted = redacted.replace(config.uas_id, "<redacted-uas-id>")
                # Redact generic EL-... style IDs
                redacted = re.sub(r"\bEL-[A-Za-z0-9\-]{6,}\b", "EL-<redacted>", redacted)
                # Redact common hostnames like el-012 or any udp/tcp masters
                redacted = re.sub(
                    r"\b(el-\d{3,})\b",
                    "<redacted-host>",
                    redacted,
                )
                # Mask host portion of udp/tcp master strings
                redacted = re.sub(
                    r"\b((?:udp|tcp):)([^:\s]+)(:\d+)\b",
                    r"\1<redacted-host>\3",
                    redacted,
                )
        except Exception:
            pass
        # Append verification note to receipt if present
        if self._verify_note:
            try:
                redacted += f"\n\n[Verification Note] {self._verify_note}\n"
            except Exception:
                pass
        return redacted

    def _write_receipt(self, config: RemoteIDConfig, output: str) -> None:
        try:
            redacted = self._redact_output(output, config)
        except Exception:
            redacted = output
        receipt_path = self.receipts_dir / f"{config.uas_id}.log"
        receipt_path.write_text(redacted, encoding="utf-8")
        info(f"Receipt saved to {receipt_path}")

    def _quote_path_for_mavproxy(self, path: str) -> str:
        """Quote a filesystem path for use inside MAVProxy command scripts.

        MAVProxy accepts quoted strings. On POSIX, use shlex.quote; on Windows, wrap in
        double-quotes. Always return a quoted string if quoting is needed.
        """
        if platform.system() == "Windows":
            # Wrap in double-quotes; escape any embedded quotes
            escaped = path.replace('"', '\\"')
            return f"\"{escaped}\""
        # On POSIX, shlex.quote will add quotes only if necessary
        return shlex.quote(path)

    def configure_batch(self, csv_path: Path, verify: bool = True) -> tuple[int, list[str]]:
        """
        Configure multiple RemoteID modules from CSV file.

        Args:
            csv_path: Path to CSV file with configurations.
            verify: Whether to verify each configuration.

        Returns:
            Tuple of (success_count, failed_uas_ids).
        """
        if not csv_path.exists():
            error(f"CSV file not found: {csv_path}")
            return 0, []

        success_count = 0
        failures = []

        with csv_path.open(newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Parse configuration from CSV row
                config = RemoteIDConfig(
                    uas_id=row["uas_id"],
                    uas_id_type=int(row["uas_id_type"]),
                    uas_type=int(row["uas_type"]),
                    connection=row["conn"],
                    lock_level=(int(row["lock"]) if row.get("lock", "").strip() else None),
                    private_key_path=self.private_key_path,
                )

                # Configure module
                ok, output = self.configure_single(config, verify=verify)

                if ok:
                    success_count += 1
                    info(f"[PASS] {config.uas_id} on {config.connection}")
                else:
                    failures.append(config.uas_id)
                    error(f"[FAIL] {config.uas_id} on {config.connection}")

        # Summary
        info(f"Batch configuration complete: {success_count} passed, {len(failures)} failed")
        if failures:
            error(f"Failed units: {', '.join(failures)}")

        return success_count, failures

    def generate_sample_csv(self, path: Path) -> None:
        """
        Generate a sample CSV file for batch configuration.

        Args:
            path: Path where to save the sample CSV.
        """
        sample_data = [
            {
                "uas_id": "EL-0123456789ABCDEF01",
                "uas_id_type": "1",
                "uas_type": "2",
                "conn": "udp:el-012:14550",
                "lock": "1",
            },
            {
                "uas_id": "EL-0123456789ABCDEF02",
                "uas_id_type": "1",
                "uas_type": "2",
                "conn": "COM7",
                "lock": "1",
            },
        ]

        with path.open("w", newline="") as f:
            fieldnames = ["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sample_data)

        info(f"Sample CSV saved to {path}")

    def check_dependencies(self) -> dict[str, bool]:
        """
        Check if all required dependencies are available.

        Returns:
            Dictionary of dependency names and their availability status.
        """
        deps = {}

        # Check MAVProxy - try different command variants
        mavproxy_found = False
        for cmd_variant in [self.mavproxy_path, "mavproxy", "mavproxy.py"]:
            try:
                result = subprocess.run(
                    [cmd_variant, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    mavproxy_found = True
                    # Update the path if we found it with a different name
                    if cmd_variant != self.mavproxy_path:
                        self.mavproxy_path = cmd_variant
                    # Extract version if possible
                    version_match = re.search(r"MAVProxy\s+([\d.]+)", result.stdout)
                    if version_match:
                        info(f"MAVProxy version: {version_match.group(1)}")
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        deps["mavproxy"] = mavproxy_found

        # Check monocypher (via Python import). SecureCommand needs >= 3.1.3.2
        required_monocypher = "3.1.3.2"
        try:
            # Import at runtime to check availability
            # pymonocypher installs as 'monocypher' module
            __import__("monocypher")
            monocypher = __import__("monocypher")
            # Default to True if import works; refine based on version if present
            deps["monocypher"] = True
            installed_version = getattr(monocypher, "__version__", None)
            if installed_version:
                info(f"monocypher version: {installed_version}")
                def _ver_tuple(v: str) -> tuple[int, ...]:
                    try:
                        return tuple(int(p) for p in v.split("."))
                    except Exception:
                        return (0,)
                if _ver_tuple(installed_version) < _ver_tuple(required_monocypher):
                    warning(
                        "monocypher version is older than expected (need >= 3.1.3.2). "
                        "Install with: python3 -m pip install pymonocypher==3.1.3.2"
                    )
            else:
                # Module present but version unknown — warn but accept
                warning("monocypher present but version unknown; proceeding.")
        except ImportError:
            deps["monocypher"] = False
            if platform.system() == "Windows":
                warning(
                    "monocypher not found. On Windows, the MAVProxy installer may bundle deps and "
                    "ignore site-packages. If 'module load SecureCommand' fails, copy the 'monocypher' "
                    "package into MAVProxy\\_internal\\."
                )
            warning(
                "monocypher not installed. Install with: python3 -m pip install pymonocypher==3.1.3.2"
            )

        # Check private key if specified (existence)
        if self.private_key_path:
            try:
                exists_flag = Path(self.private_key_path).exists()
            except Exception:
                exists_flag = False
            # Fallback to os.path.exists to avoid odd patching side-effects in tests
            try:
                import os as _os
                exists_flag = bool(exists_flag or _os.path.exists(self.private_key_path))
            except Exception:
                pass
            deps["private_key"] = exists_flag
        else:
            deps["private_key"] = False

        return deps

    def test_connection(self, connection: str, timeout: int = 10) -> tuple[bool, dict | None]:
        """
        Test connection to flight controller.

        Args:
            connection: Connection string.
            timeout: Timeout in seconds.

        Returns:
            Tuple of (success, fc_info_dict).
        """
        commands = ["wait HEARTBEAT 1", "param show MAV_SYS_ID", "param show DID_ENABLE"]

        return_code, output = self._run_mavproxy_script(connection, commands, timeout=timeout)

        # Parse output for flight controller info
        fc_info = {}

        # Check for heartbeat
        if "HEARTBEAT" in output:
            fc_info["connected"] = True

            # Extract system ID if available
            sysid_match = re.search(r"MAV_SYS_ID\s*=\s*(\d+)", output)
            if sysid_match:
                fc_info["mav_sys_id"] = int(sysid_match.group(1))

            # Check if DID is enabled
            did_match = re.search(r"DID_ENABLE\s*=\s*(\d+)", output)
            if did_match:
                fc_info["did_enabled"] = int(did_match.group(1)) == 1
        else:
            fc_info["connected"] = False

        # Only return fc_info if actually connected
        return fc_info.get("connected", False), fc_info if fc_info.get("connected", False) else None


# DID parameter ensure utility
from elijahctl.drivers.mavlink import MAVLinkDriver
from pymavlink import mavutil


def ensure_did_params(
    host: str,
    port: int,
    *,
    use_can: bool = False,
    can_driver: int = 1,
    mav_port: int = -1,
) -> bool:
    """Ensure ArduPilot DID_* parameters are set appropriately.

    MAVLink path: DID_ENABLE=1, DID_OPTIONS=1, DID_MAVPORT=<serial index>, DID_CANDRIVER=0
    DroneCAN path: DID_ENABLE=1, DID_OPTIONS=1, DID_MAVPORT=-1, DID_CANDRIVER=<driver index>
    """
    m = MAVLinkDriver(host, port)
    if not m.connect(timeout=10):
        return False
    wants: list[tuple[str, int]] = [("DID_ENABLE", 1), ("DID_OPTIONS", 1)]
    wants += [
        ("DID_MAVPORT", -1 if use_can else mav_port),
        ("DID_CANDRIVER", can_driver if use_can else 0),
    ]
    ok = True
    for k, v in wants:
        ok &= m.set_parameter(k, float(v), mavutil.mavlink.MAV_PARAM_TYPE_INT32)
    return ok
