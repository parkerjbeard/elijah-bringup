#!/usr/bin/env python3
import click
import json
import sys
import os
import logging
from pathlib import Path
from typing import Optional

from .config import (
    Config, RadioConfig, RadioRole, JetsonConfig, 
    UniFiConfig, HitlChecklist
)
from .drivers.microhard import MicrohardDriver
from .drivers.jetson import JetsonDriver
from .drivers.mavlink import MAVLinkDriver
from .drivers.unifi import UniFiDriver
from .health.checks import HealthCheck
from .checklist import ChecklistManager
from .utils.logging import (
    setup_logging, info, success, error, warning, 
    confirm, print_dict
)
from .utils.network import discover_services, find_mac_in_leases, ip_on_local_network, get_interface_info
from .drivers.mh_profile import detect_profile

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--log-file', type=click.Path(), help='Log to file')
def cli(verbose: bool, log_file: Optional[str]):
    log_path = Path(log_file) if log_file else None
    setup_logging(verbose, log_path)
    Config.init_directories()

@cli.command()
@click.option('--ip', default=Config.DEFAULT_MICROHARD_IP, help='Radio IP address')
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
@click.option('--ip', default=Config.DEFAULT_MICROHARD_IP, help='Radio IP address')
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
@click.option('--role', type=click.Choice(['air', 'ground']), required=True, help='Radio role')
@click.option('--drone-id', help='Drone ID (e.g., 012)')
@click.option('--sysid', type=int, help='MAV_SYS_ID (required for air role)')
@click.option('--aes-key', envvar='AES_KEY', required=True, help='AES-128 encryption key')
@click.option('--microhard-pass', envvar='MICROHARD_PASS', default='admin', help='Current Microhard admin password (default: admin for factory)')
@click.option('--tailscale-key', envvar='TAILSCALE_KEY', help='Tailscale auth key (for air role)')
@click.option('--ip', default=Config.DEFAULT_MICROHARD_IP, help='Radio IP address')
@click.option('--yes', is_flag=True, help='Run without interactive prompts')
def provision(role: str, drone_id: Optional[str], sysid: Optional[int], 
             aes_key: str, microhard_pass: str, 
             tailscale_key: Optional[str], ip: str, yes: bool):
    
    # Prompt for drone ID if not provided
    if not drone_id:
        drone_id = click.prompt('Enter drone ID (e.g., 012)', type=str)
        if not drone_id:
            error("Drone ID is required")
            sys.exit(1)
    
    # Prompt for sysid if air role and not provided
    if role == 'air' and not sysid:
        sysid = click.prompt('Enter MAV_SYS_ID for air radio', type=int)
        if not sysid:
            error("--sysid is required for air radio provisioning")
            sys.exit(1)
    
    radio_config = RadioConfig(
        role=RadioRole.AIR if role == 'air' else RadioRole.GROUND,
        drone_id=drone_id,
        hostname="",
        description="",
        aes_key=aes_key
    )
    
    # Add debug logging for password
    logger = logging.getLogger(__name__)
    logger.debug(f"Creating MicrohardDriver with IP={ip}, user={Config.DEFAULT_MICROHARD_USER}, pass={'*' * len(microhard_pass) if microhard_pass else 'None'}")
    logger.debug(f"Password provided (length={len(microhard_pass) if microhard_pass else 0}), value masked")
    
    driver = MicrohardDriver(ip, Config.DEFAULT_MICROHARD_USER, microhard_pass)
    
    if driver.provision(radio_config):
        success(f"{role.capitalize()} radio provisioned successfully")
        
        if role == 'air' and sysid and tailscale_key and (yes or confirm("Provision Jetson companion computer?")):
                jetson_config = JetsonConfig(
                    drone_id=drone_id,
                    device_name=f"el-{drone_id}",
                    sysid=sysid,
                    tailscale_auth_key=tailscale_key,
                    microhard_password=microhard_pass
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
@click.option('--ip', default=Config.DEFAULT_MICROHARD_IP, help='Radio IP address')
@click.option('--user', default='admin', help='Radio username')
@click.option('--microhard-pass', default='admin', help='Radio password')
@click.option('--force', is_flag=True, help='Do not prompt for confirmation')
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
@click.option('--jetson', required=True, help='Jetson hostname or IP')
@click.option('--fw', type=click.Path(exists=True), help='Firmware file path')
def flash_fc(jetson: str, fw: Optional[str]):
    if fw:
        fw_path = Path(fw)
        info(f"Uploading firmware {fw_path.name} to {jetson}")
        warning("Note: Actual flashing must be done via ARK UI or QGC")
    else:
        info("No firmware specified. Please upload manually via ARK UI")

@cli.command()
@click.option('--jetson', required=True, help='Jetson hostname or IP')
@click.option('--radio-ip', help='Radio IP address or "auto"')
@click.option('--video', default='udp:5600', help='Video probe (e.g., udp:5600, rtsp://host/stream, tcp:5600)')
@click.option('--timeout', default=5, help='Per-check timeout seconds')
@click.option('--save', type=click.Path(), help='Save results to file')
def health(jetson: str, radio_ip: Optional[str], video: str, timeout: int, save: Optional[str]):
    # Implement 'auto' discovery using cached MAC from prior discovery if available
    if radio_ip and radio_ip.strip().lower() == 'auto':
        mac_path = Config.STATE_DIR / 'last_radio_mac.txt'
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
@click.option('--controller', required=True, help='UniFi controller URL')
@click.option('--user', required=True, help='UniFi username')
@click.option('--pass', 'password', required=True, help='UniFi password')
@click.option('--site', default='default', help='UniFi site name')
@click.option('--name', default='rainmakerGCSX', help='AP device name')
@click.option('--ip', default='10.101.252.1/16', help='Static IP address')
@click.option('--disable-24ghz/--keep-24ghz', default=True, help='Disable 2.4 GHz')
@click.option('--disable-autolink/--keep-autolink', default=True, help='Disable Auto-Link')
def unifi(controller: str, user: str, password: str, site: str, name: str, 
         ip: str, disable_24ghz: bool, disable_autolink: bool):
    
    config = UniFiConfig(
        controller_url=controller,
        username=user,
        password=password,
        device_name=name,
        site=site,
        static_ip=ip.split('/')[0],
        netmask=ip.split('/')[1] if '/' in ip else '24',
        disable_24ghz=disable_24ghz,
        disable_autolink=disable_autolink
    )
    
    driver = UniFiDriver(config)
    if driver.provision():
        success("UniFi AP configured successfully")
    else:
        error("UniFi configuration failed")
        sys.exit(1)

@cli.command()
@click.option('--update', type=click.Path(exists=True), help='JSON file with checklist data')
@click.option('--drone-id', required=True, help='Drone ID')
@click.option('--phase', type=click.Choice(['hitl', 'insitu']), default='hitl', help='Checklist phase')
@click.option('--export', type=click.Path(), help='Export checklist to JSON file')
def checklist(update: Optional[str], drone_id: str, phase: str, export: Optional[str]):
    manager = ChecklistManager()
    
    if update:
        with open(update, 'r') as f:
            data = json.load(f)
        
        if phase == 'hitl':
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
            'drone_id': drone_id,
            'phase': phase,
            'hitl': manager.current_hitl.to_dict() if manager.current_hitl else None,
            'insitu': manager.current_insitu.to_dict() if manager.current_insitu else None
        }
        with open(export, 'w') as f:
            json.dump(data, f, indent=2)
        success(f"Checklist exported to {export}")

@cli.command()
@click.option('--host', required=True, help='Host to connect to')
@click.option('--sysid', type=int, required=True, help='System ID to set')
@click.option('--port', default=14550, help='MAVLink port')
def set_sysid(host: str, sysid: int, port: int):
    mavlink = MAVLinkDriver(host, port)
    
    if mavlink.set_sysid(sysid):
        success(f"MAV_SYS_ID set to {sysid}")
    else:
        error("Failed to set MAV_SYS_ID")
        sys.exit(1)

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

if __name__ == '__main__':
    main()
