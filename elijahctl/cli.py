#!/usr/bin/env python3
from __future__ import annotations
import json
import re
import logging
import sys
from pathlib import Path

import click

from .checklist import ChecklistManager
from .config import Config, JetsonConfig, RadioConfig, RadioRole, UniFiConfig
from .drivers.jetson import JetsonDriver
from .drivers.mavlink import MAVLinkDriver
from .drivers.mh_profile import detect_profile
from .drivers.microhard import MicrohardDriver
from .diagnostics.microhard_diag import (
    run_full_probe,
    dump_atl,
    brute_force_probe,
    configure_mrfrpt_and_save,
    capture_udp_json,
    backup_config_via_ssh,
    diff_backups,
)
from .drivers.remoteid import RemoteIDConfig, RemoteIDDriver, ensure_did_params
from .drivers.unifi import UniFiDriver
from .health.checks import HealthCheck
from .utils.logging import confirm, error, info, print_dict, setup_logging, success, warning
from .utils.network import (
    discover_services,
    find_mac_in_leases,
    get_interface_info,
    ip_on_local_network,
)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--log-file", type=click.Path(), help="Log to file")
def cli(verbose: bool, log_file: str | None):
    log_path = Path(log_file) if log_file else None
    setup_logging(verbose, log_path)
    Config.init_directories()


@cli.command()
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
def discover(ip: str):
    info(f"Discovering services at {ip}")
    if not ip_on_local_network(ip):
        warning("Target IP is not within any local interface network")
        info("Ensure your host has an interface on the same subnet (e.g., 192.168.168.0/24)")
        iface_info = get_interface_info()
        if iface_info:
            print_dict(iface_info, "Local Interfaces")
    services = discover_services(ip, 2.0)
    print_dict(services, "Available Services")


@cli.command("radio-profile")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
def radio_profile(ip: str):
    """Detect and show Microhard UCI profile."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, Config.DEFAULT_MICROHARD_PASS)
    try:
        driver.discover()
        ok, out = driver._ssh_execute("uci show 2>/dev/null || true")
        profile = detect_profile(out if ok else "")
        print_dict({"profile": profile.name if profile else "unknown"}, "Microhard UCI profile")
    except Exception as e:
        error(f"Profile detection failed: {e}")
        sys.exit(1)


@cli.command()
@click.option("--role", type=click.Choice(["air", "ground"]), required=True, help="Radio role")
@click.option("--drone-id", help="Drone ID (e.g., 012)")
@click.option("--sysid", type=int, help="MAV_SYS_ID (required for air role)")
@click.option("--aes-key", envvar="AES_KEY", required=True, help="AES-128 encryption key")
@click.option(
    "--microhard-pass",
    envvar="MICROHARD_PASS",
    default="admin",
    help="Current Microhard admin password (default: admin for factory)",
)
@click.option("--tailscale-key", envvar="TAILSCALE_KEY", help="Tailscale auth key (for air role)")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--yes", is_flag=True, help="Run without interactive prompts")
def provision(
    role: str,
    drone_id: str | None,
    sysid: int | None,
    aes_key: str,
    microhard_pass: str,
    tailscale_key: str | None,
    ip: str,
    yes: bool,
):

    # Prompt for drone ID if not provided
    if not drone_id:
        drone_id = click.prompt("Enter drone ID (e.g., 012)", type=str)
        if not drone_id:
            error("Drone ID is required")
            sys.exit(1)

    # Prompt for sysid if air role and not provided
    if role == "air" and not sysid:
        sysid = click.prompt("Enter MAV_SYS_ID for air radio", type=int)
        if not sysid:
            error("--sysid is required for air radio provisioning")
            sys.exit(1)

    radio_config = RadioConfig(
        role=RadioRole.AIR if role == "air" else RadioRole.GROUND,
        drone_id=drone_id,
        hostname="",
        description="",
        aes_key=aes_key,
    )

    # Add debug logging for password
    logger = logging.getLogger(__name__)
    logger.debug(
        f"Creating MicrohardDriver with IP={ip}, user={Config.DEFAULT_MICROHARD_USER}, pass={'*' * len(microhard_pass) if microhard_pass else 'None'}"
    )
    logger.debug(
        f"Password provided (length={len(microhard_pass) if microhard_pass else 0}), value masked"
    )

    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)

    if driver.provision(radio_config):
        success(f"{role.capitalize()} radio provisioned successfully")

        if (
            role == "air"
            and sysid
            and tailscale_key
            and (yes or confirm("Provision Jetson companion computer?"))
        ):
            jetson_config = JetsonConfig(
                drone_id=drone_id,
                device_name=f"el-{drone_id}",
                sysid=sysid,
                tailscale_auth_key=tailscale_key,
                microhard_password=microhard_pass,
            )

            jetson_driver = JetsonDriver(jetson_config)
            if jetson_driver.provision():
                success("Jetson provisioned successfully")

                if yes or confirm("Set FC MAV_SYS_ID?"):
                    mavlink = MAVLinkDriver(f"el-{drone_id}", 14550)
                    if mavlink.set_sysid(sysid):
                        success(f"MAV_SYS_ID set to {sysid}")
    else:
        error("Radio provisioning failed")
        sys.exit(1)


@cli.command()
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--user", default="admin", help="Radio username")
@click.option("--microhard-pass", default="admin", help="Radio password")
@click.option("--force", is_flag=True, help="Do not prompt for confirmation")
def reset_radio(ip: str, user: str, microhard_pass: str, force: bool):
    if not force and not confirm(f"This will reset the radio at {ip}. Continue?"):
        info("Reset cancelled")
        return

    driver = MicrohardDriver(ip, user, microhard_pass)
    if driver.safe_reset():
        success("Radio reset successfully")
    else:
        error("Radio reset failed")
        sys.exit(1)


@cli.command()
@click.option("--jetson", required=True, help="Jetson hostname or IP")
@click.option("--fw", type=click.Path(exists=True), help="Firmware file path")
def flash_fc(jetson: str, fw: str | None):
    if fw:
        fw_path = Path(fw)
        info(f"Uploading firmware {fw_path.name} to {jetson}")
        warning("Note: Actual flashing must be done via ARK UI or QGC")
    else:
        info("No firmware specified. Please upload manually via ARK UI")


@cli.command()
@click.option("--jetson", required=True, help="Jetson hostname or IP")
@click.option("--radio-ip", help='Radio IP address or "auto"')
@click.option(
    "--video", default="udp:5600", help="Video probe (e.g., udp:5600, rtsp://host/stream, tcp:5600)"
)
@click.option("--timeout", default=5, help="Per-check timeout seconds")
@click.option("--save", type=click.Path(), help="Save results to file")
def health(jetson: str, radio_ip: str | None, video: str, timeout: int, save: str | None):
    # Implement 'auto' discovery using cached MAC from prior discovery if available
    if radio_ip and radio_ip.strip().lower() == "auto":
        mac_path = Config.STATE_DIR / "last_radio_mac.txt"
        if mac_path.exists():
            mac = mac_path.read_text().strip()
            auto_ip = find_mac_in_leases(mac)
            if auto_ip:
                radio_ip = auto_ip
                info(f"Discovered radio IP by MAC {mac}: {auto_ip}")
            else:
                warning("Unable to discover radio IP automatically; proceeding without radio_ip")
                radio_ip = None
        else:
            warning("No cached radio MAC found; use --radio-ip <addr>")
            radio_ip = None

    Config.HEALTH_CHECK_TIMEOUT = timeout
    health_check = HealthCheck(jetson, radio_ip, video)
    results = health_check.run_all_checks()

    if save:
        filepath = health_check.save_results(save)
        success(f"Results saved to {filepath}")
    else:
        health_check.save_results()

    passed = sum(1 for r in results if r.status)
    total = len(results)

    if passed == total:
        success(f"All health checks passed ({passed}/{total})")
    elif passed > total / 2:
        warning(f"Some health checks failed ({passed}/{total})")
    else:
        error(f"Most health checks failed ({passed}/{total})")


@cli.command()
@click.option("--controller", required=True, help="UniFi controller URL")
@click.option("--user", required=True, help="UniFi username")
@click.option("--pass", "password", required=True, help="UniFi password")
@click.option("--site", default="default", help="UniFi site name")
@click.option("--name", default="rainmakerGCSX", help="AP device name")
@click.option("--ip", default="10.101.252.1/16", help="Static IP address")
@click.option("--disable-24ghz/--keep-24ghz", default=True, help="Disable 2.4 GHz")
@click.option("--disable-autolink/--keep-autolink", default=True, help="Disable Auto-Link")
def unifi(
    controller: str,
    user: str,
    password: str,
    site: str,
    name: str,
    ip: str,
    disable_24ghz: bool,
    disable_autolink: bool,
):

    config = UniFiConfig(
        controller_url=controller,
        username=user,
        password=password,
        device_name=name,
        site=site,
        static_ip=ip.split("/")[0],
        netmask=ip.split("/")[1] if "/" in ip else "24",
        disable_24ghz=disable_24ghz,
        disable_autolink=disable_autolink,
    )

    driver = UniFiDriver(config)
    if driver.provision():
        success("UniFi AP configured successfully")
    else:
        error("UniFi configuration failed")
        sys.exit(1)


@cli.command()
@click.option("--update", type=click.Path(exists=True), help="JSON file with checklist data")
@click.option("--drone-id", required=True, help="Drone ID")
@click.option(
    "--phase", type=click.Choice(["hitl", "insitu"]), default="hitl", help="Checklist phase"
)
@click.option("--export", type=click.Path(), help="Export checklist to JSON file")
def checklist(update: str | None, drone_id: str, phase: str, export: str | None):
    manager = ChecklistManager()

    if update:
        with open(update) as f:
            data = json.load(f)

        if phase == "hitl":
            manager.load_hitl_checklist(data)
        else:
            manager.load_insitu_checklist(data)

        is_complete, missing = manager.validate_completeness(phase)

        if is_complete:
            manager.append_to_csv(drone_id)
            run_file = manager.save_run_record(drone_id, phase)
            success(f"Checklist saved to {run_file}")

            labels = manager.generate_labels(drone_id)
            print_dict(labels, "Generated Labels")
        else:
            warning(f"Checklist incomplete. Missing fields: {', '.join(missing)}")

    if export:
        data = {
            "drone_id": drone_id,
            "phase": phase,
            "hitl": manager.current_hitl.to_dict() if manager.current_hitl else None,
            "insitu": manager.current_insitu.to_dict() if manager.current_insitu else None,
        }
        with open(export, "w") as f:
            json.dump(data, f, indent=2)
        success(f"Checklist exported to {export}")


@cli.command()
@click.option("--host", required=True, help="Host to connect to")
@click.option("--sysid", type=int, required=True, help="System ID to set")
@click.option("--port", default=14550, help="MAVLink port")
def set_sysid(host: str, sysid: int, port: int):
    mavlink = MAVLinkDriver(host, port)

    if mavlink.set_sysid(sysid):
        success(f"MAV_SYS_ID set to {sysid}")
    else:
        error("Failed to set MAV_SYS_ID")
        sys.exit(1)


@cli.group()
def remoteid():
    """RemoteID (db201) configuration commands."""


@remoteid.command("configure")
@click.option("--uas-id", required=True, help="UAS ID string (e.g., EL-0123456789ABCDEF01)")
@click.option("--uas-id-type", type=int, default=1, help="UAS ID type (1=Serial Number)")
@click.option("--uas-type", type=int, default=2, help="UAS type (2=Multirotor)")
@click.option(
    "--connection", "-c", required=True, help="Connection string (e.g., udp:el-012:14550 or COM7)"
)
@click.option(
    "--lock-level", type=int, help="Lock level (0=unlocked, 1=param lock, 2=permanent lock)"
)
@click.option(
    "--private-key", envvar="RID_PRIVATE_KEY", required=True, help="Path to private key file"
)
@click.option("--mavproxy-path", envvar="MAVPROXY_PATH", help="Path to MAVProxy executable")
@click.option("--no-verify", is_flag=True, help="Skip verification after configuration")
@click.option(
    "--confirm-lock-level-2",
    is_flag=True,
    help="Required to allow LOCK_LEVEL=2 (permanent eFuses change)",
)
@click.option("--ensure-did", is_flag=True, help="Pre/Post ensure DID_* params on FC")
@click.option("--use-can", is_flag=True, help="Use DroneCAN path for DID params (vs MAVLink)")
@click.option("--did-mavport", type=int, default=-1, help="DID_MAVPORT value when using MAVLink path")
@click.option("--did-candriver", type=int, default=1, help="DID_CANDRIVER index when using CAN path")
@click.option("--redact-ids/--no-redact-ids", default=True, help="Redact UAS_ID/hostnames in receipts")
def remoteid_configure(
    uas_id: str,
    uas_id_type: int,
    uas_type: int,
    connection: str,
    lock_level: int | None,
    private_key: str,
    mavproxy_path: str | None,
    no_verify: bool,
    confirm_lock_level_2: bool,
    ensure_did: bool,
    use_can: bool,
    did_mavport: int,
    did_candriver: int,
    redact_ids: bool,
):
    """Configure a single RemoteID module."""
    # Early validation: ASTM/DRIP limit is 20 bytes
    try:
        if len(uas_id.encode("utf-8")) > 20:
            error("UAS_ID must be ≤20 bytes (ASTM/DRIP)")
            sys.exit(1)
    except Exception:
        error("UAS_ID encoding error")
        sys.exit(1)

    if lock_level == 2 and not confirm_lock_level_2:
        error("LOCK_LEVEL=2 requires --confirm-lock-level-2 (irreversible eFuses change)")
        sys.exit(1)
    driver = RemoteIDDriver(
        mavproxy_path=mavproxy_path, private_key_path=private_key, redact_ids=redact_ids
    )

    # Check dependencies
    deps = driver.check_dependencies()
    # Only enforce required booleans here
    required_keys = ["mavproxy", "monocypher", "private_key"]
    if not all(deps.get(k, False) for k in required_keys):
        error("Missing dependencies:")
        for dep in required_keys:
            if not deps.get(dep, False):
                error(f"  - {dep}: Not available")
        sys.exit(1)

    config = RemoteIDConfig(
        uas_id=uas_id,
        uas_id_type=uas_id_type,
        uas_type=uas_type,
        connection=connection,
        lock_level=lock_level,
        private_key_path=private_key,
    )

    # Optionally ensure DID params pre-flight
    if ensure_did:
        m = re.match(r"^(udp|tcp):([^:]+):(\d+)$", connection, re.IGNORECASE)
        if not m:
            error("--ensure-did requires a UDP/TCP connection string like udp:host:14550")
            sys.exit(1)
        host, port = m.group(2), int(m.group(3))
        if not ensure_did_params(host, port, use_can=use_can, can_driver=did_candriver, mav_port=did_mavport):
            error("Failed to ensure DID_* parameters before configuration")
            sys.exit(1)

    ok, output = driver.configure_single(config, verify=not no_verify)

    if ok:
        success(f"RemoteID {uas_id} configured successfully")
        if lock_level == 2:
            # extra operator feedback for permanent lock
            warning("LOCK_LEVEL=2 applied: USB flashing disabled; OTA signed updates only")
    else:
        error(f"Failed to configure RemoteID {uas_id}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            error("Output:")
            print(output)
        sys.exit(1)

    # Optionally ensure DID params post-flight
    if ensure_did:
        m = re.match(r"^(udp|tcp):([^:]+):(\d+)$", connection, re.IGNORECASE)
        if m:
            host, port = m.group(2), int(m.group(3))
            if not ensure_did_params(
                host, port, use_can=use_can, can_driver=did_candriver, mav_port=did_mavport
            ):
                warning("Post-flight ensure of DID_* parameters did not fully apply")


@remoteid.command("batch")
@click.option(
    "--csv", "-f", required=True, type=click.Path(exists=True), help="CSV file with configurations"
)
@click.option(
    "--private-key", envvar="RID_PRIVATE_KEY", required=True, help="Path to private key file"
)
@click.option("--mavproxy-path", envvar="MAVPROXY_PATH", help="Path to MAVProxy executable")
@click.option("--no-verify", is_flag=True, help="Skip verification after configuration")
@click.option(
    "--confirm-lock-level-2", is_flag=True, help="Required to allow any LOCK_LEVEL=2 entries in CSV"
)
@click.option("--ensure-did", is_flag=True, help="Pre/Post ensure DID_* params on FC for each row")
@click.option("--use-can", is_flag=True, help="Use DroneCAN path for DID params (vs MAVLink)")
@click.option("--did-mavport", type=int, default=-1, help="DID_MAVPORT value when using MAVLink path")
@click.option("--did-candriver", type=int, default=1, help="DID_CANDRIVER index when using CAN path")
@click.option("--redact-ids/--no-redact-ids", default=True, help="Redact UAS_ID/hostnames in receipts")
def remoteid_batch(
    csv: str,
    private_key: str,
    mavproxy_path: str | None,
    no_verify: bool,
    confirm_lock_level_2: bool,
    ensure_did: bool,
    use_can: bool,
    did_mavport: int,
    did_candriver: int,
    redact_ids: bool,
):
    """Configure multiple RemoteID modules from CSV file."""
    driver = RemoteIDDriver(
        mavproxy_path=mavproxy_path, private_key_path=private_key, redact_ids=redact_ids
    )

    # Check dependencies
    deps = driver.check_dependencies()
    if not all(deps.values()):
        error("Missing dependencies:")
        for dep, available in deps.items():
            if not available:
                error(f"  - {dep}: Not available")
        sys.exit(1)

    csv_path = Path(csv)

    # Pre-scan CSV for any LOCK_LEVEL=2 entries
    try:
        with csv_path.open(newline="") as f:
            import csv as _csv

            reader = _csv.DictReader(f)
            has_lock2 = any((row.get("lock", "").strip() == "2") for row in reader)
        if has_lock2 and not confirm_lock_level_2:
            error(
                "CSV contains LOCK_LEVEL=2 entries; pass --confirm-lock-level-2 to proceed (irreversible)"
            )
            sys.exit(1)
    except Exception:
        # If CSV can't be read here, let downstream handling surface the error
        pass
    if not ensure_did:
        success_count, failures = driver.configure_batch(csv_path, verify=not no_verify)
    else:
        # Custom batch to support per-row DID ensure before/after
        if not csv_path.exists():
            error(f"CSV file not found: {csv_path}")
            sys.exit(1)
        success_count = 0
        failures: list[str] = []
        import csv as _csv
        with csv_path.open(newline="") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                try:
                    conn = row["conn"]
                    uas_id = row["uas_id"]
                    # preflight ensure
                    m = re.match(r"^(udp|tcp):([^:]+):(\d+)$", conn, re.IGNORECASE)
                    if not m:
                        error(f"Row {uas_id}: --ensure-did requires UDP/TCP connection, got {conn}")
                        failures.append(uas_id)
                        continue
                    host, port = m.group(2), int(m.group(3))
                    if not ensure_did_params(
                        host, port, use_can=use_can, can_driver=did_candriver, mav_port=did_mavport
                    ):
                        error(f"Row {uas_id}: failed to ensure DID_* before configure")
                        failures.append(uas_id)
                        continue

                    cfg = RemoteIDConfig(
                        uas_id=uas_id,
                        uas_id_type=int(row["uas_id_type"]),
                        uas_type=int(row["uas_type"]),
                        connection=conn,
                        lock_level=(int(row["lock"]) if row.get("lock", "").strip() else None),
                        private_key_path=private_key,
                    )
                    ok, _out = driver.configure_single(cfg, verify=not no_verify)
                    if not ok:
                        failures.append(uas_id)
                        continue

                    # postflight ensure
                    if not ensure_did_params(
                        host, port, use_can=use_can, can_driver=did_candriver, mav_port=did_mavport
                    ):
                        warning(f"Row {uas_id}: DID_* post-ensure did not fully apply")
                    success_count += 1
                except Exception as e:
                    error(f"Row {row.get('uas_id','?')}: exception {e}")
                    failures.append(row.get("uas_id", "?"))

    if failures:
        error(f"Batch configuration completed with failures: {len(failures)} units failed")
        sys.exit(1)
    else:
        success(f"All {success_count} units configured successfully")


@remoteid.command("test-connection")
@click.option(
    "--connection", "-c", required=True, help="Connection string (e.g., udp:el-012:14550 or COM7)"
)
@click.option("--mavproxy-path", envvar="MAVPROXY_PATH", help="Path to MAVProxy executable")
def remoteid_test_connection(connection: str, mavproxy_path: str | None):
    """Test connection to flight controller."""
    driver = RemoteIDDriver(mavproxy_path=mavproxy_path)

    info(f"Testing connection to {connection}")
    connected, fc_info = driver.test_connection(connection)

    if connected and fc_info:
        success("Connection successful")
        print_dict(fc_info, "Flight Controller Info")
    else:
        error(f"Failed to connect to {connection}")
        sys.exit(1)


@remoteid.command("sample-csv")
@click.option("--output", "-o", default="remoteid_sample.csv", help="Output CSV file path")
def remoteid_sample_csv(output: str):
    """Generate a sample CSV file for batch configuration."""
    driver = RemoteIDDriver()
    output_path = Path(output)
    driver.generate_sample_csv(output_path)
    success(f"Sample CSV generated: {output_path}")


@remoteid.command("check-deps")
@click.option("--mavproxy-path", envvar="MAVPROXY_PATH", help="Path to MAVProxy executable")
@click.option("--private-key", envvar="RID_PRIVATE_KEY", help="Path to private key file")
@click.option("--force", is_flag=True, help="Ignore monocypher version check")
def remoteid_check_deps(mavproxy_path: str | None, private_key: str | None, force: bool):
    """Check RemoteID configuration dependencies."""
    driver = RemoteIDDriver(mavproxy_path=mavproxy_path, private_key_path=private_key)
    deps = driver.check_dependencies()

    all_available = all(deps.values())
    print_dict(deps, "RemoteID Dependencies")

    # Enforce monocypher minimum version unless forced
    min_required = "3.1.3.2"
    too_old = False
    try:
        import monocypher as _mono  # type: ignore

        ver = getattr(_mono, "__version__", None)
        if ver:
            def _vt(v: str):
                try:
                    return tuple(int(p) for p in v.split('.'))
                except Exception:
                    return (0,)
            if _vt(ver) < _vt(min_required):
                too_old = True
    except Exception:
        pass

    if too_old and not force:
        error(
            f"monocypher version too old (< {min_required}). Install: python3 -m pip install pymonocypher=={min_required}"
        )
        sys.exit(1)

    if not all_available:
        warning("Some dependencies are missing. Install them before using RemoteID commands.")
        if not deps.get("monocypher", False):
            info("Install monocypher with: python3 -m pip install pymonocypher==3.1.3.2")
        sys.exit(1)
    else:
        success("All dependencies are available")


@cli.group()
def microhard():
    """Microhard-specific utilities and diagnostics."""


@microhard.group(name="diag")
def diagnostics():
    """Diagnostics to probe AT commands and stats."""


@diagnostics.command("run")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--microhard-pass", envvar="MICROHARD_PASS", default="admin", help="Radio password")
@click.option("--duration", default=10, help="UDP capture duration (seconds)")
@click.option("--server-ip", help="Host IP for UDP (defaults to iface on radio subnet)")
@click.option("--port", default=20200, help="UDP port to capture")
@click.option("--interval", default=1000, help="AT+MRFRPT interval (ms)")
@click.option("--label", help="Suffix label for session dir")
def microhard_testing_run(ip: str, microhard_pass: str, duration: int, server_ip: str | None, port: int, interval: int, label: str | None):
    """Run ATL dump, brute-force probe, MRFRPT enable, and UDP capture."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    driver.discover()
    session_dir = run_full_probe(driver, duration_sec=duration, server_ip=server_ip, port=port, interval_ms=interval, label=label)
    success(f"Testing session complete: {session_dir}")


@diagnostics.command("atl")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--microhard-pass", envvar="MICROHARD_PASS", default="admin", help="Radio password")
def microhard_testing_atl(ip: str, microhard_pass: str):
    """Dump ATL (list AT commands) to a session directory and print a summary."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    driver.discover()
    from .diagnostics.microhard_diag import _ensure_session_dir  # local import to avoid export
    sess = _ensure_session_dir(ip, label="atl")
    ok, out = dump_atl(driver, sess)
    if ok:
        success(f"ATL dump saved to {sess / 'atl_dump.txt'}")
    else:
        error("ATL failed or returned no output")


@diagnostics.command("brute")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--microhard-pass", envvar="MICROHARD_PASS", default="admin", help="Radio password")
def microhard_testing_bruteforce(ip: str, microhard_pass: str):
    """Try a small set of undocumented MRFRPT tokens and log responses."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    driver.discover()
    from .diagnostics.microhard_diag import _ensure_session_dir 
    sess = _ensure_session_dir(ip, label="brute")
    brute_force_probe(driver, sess)
    success(f"Brute-force results saved to {sess / 'brute_force.txt'}")


@diagnostics.command("capture")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--microhard-pass", envvar="MICROHARD_PASS", default="admin", help="Radio password")
@click.option("--server-ip", help="Host IP to receive UDP (defaults to iface on radio subnet)")
@click.option("--port", default=20200, help="UDP port")
@click.option("--interval", default=1000, help="AT+MRFRPT interval (ms)")
@click.option("--duration", default=10, help="Capture duration per phase (seconds)")
@click.option("--two-phase/--single", default=False, help="Capture before and after a manual UI toggle")
def microhard_testing_capture(ip: str, microhard_pass: str, server_ip: str | None, port: int, interval: int, duration: int, two_phase: bool):
    """Enable MRFRPT, capture UDP JSON to files; optionally guide a before/after toggle."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    driver.discover()
    from .diagnostics.microhard_diag import _ensure_session_dir
    sess = _ensure_session_dir(ip, label="capture")

    # Configure MRFRPT to this host
    host_ip = server_ip
    if not host_ip:
        # Best-effort choice handled in helper inside run_full_probe path
        from .diagnostics.microhard_diag import _choose_server_ip_for_radio
        host_ip = _choose_server_ip_for_radio(ip)
    if not host_ip:
        error("Unable to determine --server-ip; specify it explicitly")
        sys.exit(1)

    ok, _ = configure_mrfrpt_and_save(driver, host_ip, port=port, interval_ms=interval)
    if not ok:
        warning("AT+MRFRPT may not have applied; continuing to listen anyway")

    # Phase A
    a_path = sess / "udp_before.jsonl"
    n_a = capture_udp_json(port, duration, a_path)
    info(f"Captured {n_a} packets to {a_path}")

    if two_phase:
        info("Now toggle 'Associated IP' in the Web UI, then press Enter...")
        try:
            input()
        except Exception:
            pass
        b_path = sess / "udp_after.jsonl"
        n_b = capture_udp_json(port, duration, b_path)
        info(f"Captured {n_b} packets to {b_path}")
    success(f"UDP capture complete: {sess}")


@diagnostics.command("backup")
@click.option("--ip", default=Config.DEFAULT_MICROHARD_IP, help="Radio IP address")
@click.option("--microhard-pass", envvar="MICROHARD_PASS", default="admin", help="Radio password")
@click.option("--label", default="backup", help="Label for backup file name")
def microhard_testing_backup(ip: str, microhard_pass: str, label: str):
    """Fetch a config backup tarball via SSH and save locally."""
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    driver.discover()
    from .diagnostics.microhard_diag import _ensure_session_dir
    sess = _ensure_session_dir(ip, label="backup")
    out = backup_config_via_ssh(driver, sess, label=label)
    if out:
        success(f"Backup saved to {out}")
    else:
        error("Backup failed")
        sys.exit(1)


@diagnostics.command("diff")
@click.argument("a", type=click.Path(exists=True))
@click.argument("b", type=click.Path(exists=True))
@click.option("--out", type=click.Path(), help="Write diff to file (default: alongside A)")
def microhard_testing_diff(a: str, b: str, out: str | None):
    """Diff two backup tarballs and print/write differences in /etc/config."""
    a_p, b_p = Path(a), Path(b)
    out_p = Path(out) if out else a_p.with_suffix(a_p.suffix + ".diff.txt")
    ok = diff_backups(a_p, b_p, out_p)
    if ok:
        success(f"Diff written to {out_p}")
        try:
            click.echo(out_p.read_text())
        except Exception:
            pass
    else:
        error("Diff failed")


@cli.command()
def version():
    from . import __version__

    click.echo(f"elijahctl version {__version__}")


def main():
    try:
        cli()
    except KeyboardInterrupt:
        error("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
