from __future__ import annotations
import os
import re
import tarfile
import time
import json
import socket
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import paramiko
import contextlib

from ..config import Config
from ..drivers.microhard import MicrohardDriver
from ..utils.logging import get_logger, info, success, warning, error
from ..utils.network import ip_on_local_network, get_interface_info


logger = get_logger(__name__)


def _ensure_session_dir(ip: str, label: Optional[str] = None) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    base = Config.STATE_DIR / "diagnostics" / "microhard" / f"{ts}-{ip}"
    if label:
        base = base.with_name(f"{ts}-{ip}-{label}")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _choose_server_ip_for_radio(radio_ip: str) -> Optional[str]:
    """Best-effort: return a local interface IP on same subnet as radio."""
    try:
        if ip_on_local_network(radio_ip):
            # crude but local: pick any iface whose /24 shares first three octets
            iface_info = get_interface_info()
            r_parts = radio_ip.split(".")
            for _, meta in iface_info.items():
                ip = (meta.get("ip") or "").split("/")[0]
                if ip and ip.split(".")[:3] == r_parts[:3]:
                    return ip
    except Exception:
        pass
    return None


def dump_atl(driver: MicrohardDriver, out_dir: Path) -> Tuple[bool, str]:
    """Run ATL (list AT commands) and save output to disk."""
    ok, out = driver._ssh_execute_at_session(["ATL"])  # noqa: SLF001
    outfile = out_dir / "atl_dump.txt"
    try:
        outfile.write_text(out or "")
    except Exception:
        pass
    return ok, out


def brute_force_probe(driver: MicrohardDriver, out_dir: Path) -> Dict[str, str]:
    """Probe a small set of plausible, undocumented AT tokens and capture responses."""
    candidates = [
        "ATL",
        "AT+MRFRPT?",
        "AT+MRFRPTOPT?",
        "AT+MRFRPTOPT2?",
        "AT+MRFRPTNET?",
        "AT+MRFRPTNETOPT?",
        "AT+MRFNETOPT?",
    ]
    results: Dict[str, str] = {}
    for cmd in candidates:
        ok, out = driver._ssh_execute_at_session([cmd])  # noqa: SLF001
        results[cmd] = out
        # Be gentle on the CLI
        time.sleep(0.1)
    # Write a simple report
    rep = out_dir / "brute_force.txt"
    with rep.open("w") as f:
        for cmd, out in results.items():
            f.write(f"$ {cmd}\n")
            f.write((out or "").strip() + "\n\n")
    return results


def configure_mrfrpt_and_save(driver: MicrohardDriver, server_ip: str, port: int = 20200, interval_ms: int = 1000, rf: int = 1, net: int = 1) -> Tuple[bool, str]:
    """Enable Radio Stats stream to host via AT+MRFRPT and save config (AT&W)."""
    cmd = f"AT+MRFRPT=1,{server_ip},{int(port)},{int(interval_ms)},{int(rf)},{int(net)}"
    ok, out = driver._ssh_execute_at_session([cmd, "AT&W"])  # noqa: SLF001
    return ok, out


def capture_udp_json(port: int, duration_sec: int, out_file: Path) -> int:
    """Listen on UDP `port` and write any UTF-8 JSON lines to out_file.

    Returns count of packets captured.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.bind(("0.0.0.0", int(port)))
    end_by = time.time() + max(1, duration_sec)
    count = 0
    with out_file.open("w") as f:
        while time.time() < end_by:
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                # Ensure one-line output; store raw if not JSON
                s = data.decode("utf-8", errors="ignore").strip()
                # Normalize to JSON line if looks like JSON; else write as-is
                if s.startswith("{") or s.startswith("["):
                    f.write(s + "\n")
                else:
                    f.write(json.dumps({"raw": s}) + "\n")
                count += 1
            except Exception:
                continue
    try:
        sock.close()
    except Exception:
        pass
    return count


def backup_config_via_ssh(driver: MicrohardDriver, out_dir: Path, label: str = "backup") -> Optional[Path]:
    """Create a config backup on the radio and fetch it via SFTP.

    Uses `sysupgrade -b` when available; falls back to a tar.gz of /etc/config.
    Returns path to local backup file or None on failure.
    """
    remote_path = f"/tmp/elijah-{int(time.time())}.tgz"
    ok, out = driver._ssh_execute(
        f"(which sysupgrade >/dev/null 2>&1 && sysupgrade -b {remote_path}) || (tar czf {remote_path} /etc/config 2>/dev/null || true) && echo __OK__"
    )
    if not ok or "__OK__" not in out:
        error("Failed to create backup archive on device")
        return None

    # Use paramiko SFTP to fetch
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            driver.ip,
            username=driver.username,
            password=driver.password,
            timeout=Config.SSH_TIMEOUT,
            banner_timeout=5,
            auth_timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
        sftp = client.open_sftp()
        local_path = out_dir / f"{label}.tar.gz"
        sftp.get(remote_path, str(local_path))
        # Cleanup remote file
        with contextlib.suppress(Exception):
            sftp.remove(remote_path)
        sftp.close()
        client.close()
        success(f"Fetched backup to {local_path}")
        return local_path
    except Exception as e:
        error(f"SFTP fetch failed: {e}")
        return None


def diff_backups(a: Path, b: Path, out_file: Path) -> bool:
    """Extract two backup tarballs and write a textual diff of /etc/config files."""
    import tempfile
    import difflib

    def extract(tar_path: Path, dst: Path):
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(dst)

    with tempfile.TemporaryDirectory() as dtmp:
        dir_a = Path(dtmp) / "a"
        dir_b = Path(dtmp) / "b"
        dir_a.mkdir(parents=True, exist_ok=True)
        dir_b.mkdir(parents=True, exist_ok=True)
        extract(a, dir_a)
        extract(b, dir_b)

        # Gather file lists under etc/config
        files_a = sorted((dir_a / "etc" / "config").glob("**/*"))
        files_b = sorted((dir_b / "etc" / "config").glob("**/*"))
        rels = sorted({p.relative_to(dir_a) for p in files_a if p.is_file()} | {p.relative_to(dir_b) for p in files_b if p.is_file()})

        lines: List[str] = []
        for rel in rels:
            pa = dir_a / rel
            pb = dir_b / rel
            if pa.exists() and pb.exists():
                try:
                    ta = pa.read_text(errors="ignore").splitlines()
                    tb = pb.read_text(errors="ignore").splitlines()
                except Exception:
                    continue
                if ta != tb:
                    lines.append(f"--- {rel}\n+++ {rel}\n")
                    diff = difflib.unified_diff(ta, tb, fromfile=str(rel), tofile=str(rel), lineterm="")
                    for dl in diff:
                        lines.append(dl + "\n")
            elif pa.exists() and not pb.exists():
                lines.append(f"- only in A: {rel}\n")
            elif pb.exists() and not pa.exists():
                lines.append(f"- only in B: {rel}\n")

        out_file.write_text("".join(lines) if lines else "(no differences)\n")
        return True


def run_full_probe(
    driver: MicrohardDriver,
    duration_sec: int = 10,
    server_ip: Optional[str] = None,
    port: int = 20200,
    interval_ms: int = 1000,
    label: Optional[str] = None,
) -> Path:
    """Run ATL dump, brute-force probe, MRFRPT enable, and UDP capture once.

    Returns the session directory path containing artifacts.
    """
    sess = _ensure_session_dir(driver.ip, label=label)
    info(f"Session dir: {sess}")

    # 1) ATL
    ok, _ = dump_atl(driver, sess)
    if ok:
        success("ATL dump captured")
    else:
        warning("ATL did not return expected prompt; proceeding")

    # 2) Brute force a few tokens
    brute_force_probe(driver, sess)
    success("Brute-force probe complete")

    # 3) Setup MRFRPT and capture
    host_ip = server_ip or _choose_server_ip_for_radio(driver.ip)
    if not host_ip:
        warning("Could not determine a local host IP on radio subnet; set --server-ip to capture")
        return sess

    ok, _ = configure_mrfrpt_and_save(driver, host_ip, port=port, interval_ms=interval_ms)
    if not ok:
        warning("AT+MRFRPT configuration may have failed; attempting capture anyway")

    out_json = sess / "udp_capture.jsonl"
    n = capture_udp_json(port, duration_sec, out_json)
    info(f"Captured {n} UDP packets to {out_json}")
    return sess
