import socket
import subprocess
import re
import time
import ipaddress
from typing import Optional, Dict, List, Tuple
import shutil
from pathlib import Path
import platform
import os
import json


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.gaierror, socket.error):
        return False


def discover_services(ip: str = "192.168.168.1", timeout: float = 2.0) -> Dict[str, bool]:
    """Probe common Microhard services on the target IP.

    Includes SSH (22), Telnet (23), HTTP (80) and HTTPS (443).
    """
    return {
        "ssh": port_open(ip, 22, timeout),
        "telnet": port_open(ip, 23, timeout),
        "http": port_open(ip, 80, timeout),
        "https": port_open(ip, 443, timeout),
    }


def ping_host(host: str, count: int = 3, timeout: int = 2) -> Tuple[bool, Optional[float]]:
    """Cross-platform reachability check using TCP connect RTT (no system ping).

    Attempts to connect to common ports and returns success with average RTT
    across successes. This avoids Linux/macOS ping flag differences.
    """
    ports = (22, 80, 443)
    rtts: List[float] = []
    ok = False
    for _ in range(count):
        start = time.perf_counter()
        connected = False
        for p in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                res = sock.connect_ex((host, p))
                sock.close()
                if res == 0:
                    connected = True
                    break
            except Exception:
                continue
        elapsed = (time.perf_counter() - start) * 1000.0
        if connected:
            ok = True
            rtts.append(elapsed)
        time.sleep(0.1)
    return (ok, (sum(rtts) / len(rtts)) if rtts else None)


def _parse_arp_cache(mac_lower: str) -> Optional[str]:
    """Parse ARP cache using available tools.

    Prefer `arp -an` when present, else fall back to `ip neigh` on Linux.
    """
    # First try `arp -an`
    try:
        if shutil.which("arp"):
            result = subprocess.run(["arp", "-an"], capture_output=True, text=True)
            pattern = r"\(([0-9.]+)\)\s+at\s+([0-9a-f:]{17})"
            for match in re.finditer(pattern, result.stdout, re.IGNORECASE):
                ip, mac = match.groups()
                if mac.lower() == mac_lower:
                    return ip
    except Exception:
        pass
    # Fallback: `ip neigh`
    try:
        if shutil.which("ip"):
            result = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
            # Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            for line in result.stdout.splitlines():
                m = re.search(
                    r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]{17})", line, re.IGNORECASE
                )
                if m:
                    ip, mac = m.groups()
                    if mac.lower() == mac_lower:
                        return ip
    except Exception:
        pass
    return None


def _iter_hosts_limited(
    network: ipaddress.IPv4Network, seed_ip: Optional[ipaddress.IPv4Address] = None
):
    """Yield host IPs to probe. For /24, yield all hosts. For larger nets, only seed /24."""
    # For large networks, constrain to the /24 that contains seed_ip (if provided)
    if network.prefixlen <= 16 and seed_ip and seed_ip in network:
        constrained = ipaddress.ip_network(f"{seed_ip}/24", strict=False)
        for h in constrained.hosts():
            yield h
        return
    # For /24 or smaller (>=/24), scan all hosts
    for h in network.hosts():
        yield h


def _local_networks() -> List[ipaddress.IPv4Interface]:
    nets: List[ipaddress.IPv4Interface] = []
    system = platform.system()
    try:
        # Prefer `ip -o -f inet addr show` on Linux
        if shutil.which("ip"):
            result = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show"], capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        iface = ipaddress.ip_interface(parts[3])
                        nets.append(iface)
                    except ValueError:
                        continue
        elif system == "Darwin" and shutil.which("ifconfig"):
            # Parse `ifconfig` on macOS: lines like 'inet 192.168.1.10 netmask 0xffffff00 ...'
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            current_iface = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                m_iface = re.match(r"^(\w+):", line)
                if m_iface:
                    current_iface = m_iface.group(1)
                    continue
                if line.startswith("inet ") and current_iface:
                    parts = line.split()
                    try:
                        ip_str = parts[1]
                        # Netmask may be hex form (e.g., 0xffffff00)
                        mask_str = None
                        if "netmask" in parts:
                            mi = parts.index("netmask")
                            mask_str = parts[mi + 1]
                        prefix = 24
                        if mask_str:
                            if mask_str.startswith("0x"):
                                # Convert hex to dotted and then to prefix
                                mask_int = int(mask_str, 16)
                                mask_bytes = mask_int.to_bytes(4, byteorder="big")
                                mask_dotted = ".".join(str(b) for b in mask_bytes)
                                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask_dotted}").prefixlen
                            else:
                                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
                        nets.append(ipaddress.ip_interface(f"{ip_str}/{prefix}"))
                    except Exception:
                        continue
    except Exception:
        pass
    return nets


def ip_on_local_network(ip: str) -> bool:
    """Return True if `ip` is within any local interface network.

    Useful to warn when the target is unreachable because the host lacks
    an interface on the same subnet (e.g., 192.168.168.0/24).
    """
    try:
        ip_addr = ipaddress.ip_address(ip)
        if not isinstance(ip_addr, ipaddress.IPv4Address):
            return False
        for iface in _local_networks():
            if ip_addr in iface.network:
                return True
    except Exception:
        pass
    return False


def find_mac_in_leases(mac_address: str, subnet: Optional[str] = None) -> Optional[str]:
    """
    Deterministic lookup when ELIJAH_SIM_LEASES_FILE is set, else fall back to
    local ARP warm + parse. Optionally constrain to a CIDR for the ARP warm.
    """
    mac_lower = mac_address.lower()

    # Simulation shim: use a file mapping MAC -> IP when provided
    try:
        sim_path = os.environ.get("ELIJAH_SIM_LEASES_FILE")
        if sim_path:
            p = Path(sim_path)
            if p.exists():
                mapping = json.loads(p.read_text())
                ip = mapping.get(mac_lower) or mapping.get(mac_lower.upper())
                if ip:
                    return ip
    except Exception:
        # Fall through to ARP-based discovery
        pass

    # First quick pass: check existing ARP cache
    try:
        subprocess.run(["arp", "-a"], capture_output=True, check=False)
    except Exception:
        pass
    ip_found = _parse_arp_cache(mac_lower)
    if ip_found:
        return ip_found

    # Build candidate networks
    candidates: List[ipaddress.IPv4Network] = []
    seed_ip: Optional[ipaddress.IPv4Address] = None

    # Subnet provided explicitly
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                candidates.append(net)
        except Exception:
            pass

    # Local interface networks
    for iface in _local_networks():
        candidates.append(iface.network)
        seed_ip = iface.ip

    # De-duplicate
    unique = []
    seen = set()
    for n in candidates:
        s = (n.network_address.exploded, n.prefixlen)
        if s not in seen:
            unique.append(n)
            seen.add(s)

    # Probe sweep (limited) to warm ARP using UDP packets
    for net in unique:
        try:
            for host in _iter_hosts_limited(net, seed_ip=seed_ip):
                ip_str = str(host)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.1)
                    sock.sendto(b"\x00", (ip_str, 9))
                    sock.close()
                except Exception:
                    pass
        except Exception:
            continue

    # Allow a brief moment for ARP cache population after probes
    try:
        time.sleep(0.25)
    except Exception:
        pass

    # Read ARP cache again
    return _parse_arp_cache(mac_lower)


def scan_network_for_device(
    mac_prefix: Optional[str] = None, subnet: str = "192.168.168.0/24"
) -> List[Dict[str, str]]:
    devices = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)

        for ip in network.hosts():
            ip_str = str(ip)
            if port_open(ip_str, 80, timeout=0.5) or port_open(ip_str, 22, timeout=0.5):
                if mac_prefix:
                    mac = (get_mac_address(ip_str) or "").lower()
                    if not mac.startswith(mac_prefix.lower()):
                        continue
                devices.append({"ip": ip_str, "reachable": True})
    except:
        pass

    return devices


def get_mac_address(ip: str) -> Optional[str]:
    """Return MAC for a given IP using ARP or `ip neigh`.

    Works even when `arp` (net-tools) is missing by falling back to `ip neigh`.
    """
    # Warm ARP via UDP packet to a discard-like port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.sendto(b"\x00", (ip, 9))
        sock.close()
    except Exception:
        pass

    # Try `arp -n <ip>` first when available
    try:
        if shutil.which("arp"):
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            mac_match = re.search(
                r"([0-9a-f]{2}(:[0-9a-f]{2}){5})",
                result.stdout,
                re.IGNORECASE,
            )
            if mac_match:
                return mac_match.group(1)
    except Exception:
        pass

    # Fallback: `ip neigh show to <ip>`
    try:
        if shutil.which("ip"):
            result = subprocess.run(
                ["ip", "neigh", "show", "to", ip], capture_output=True, text=True
            )
            m = re.search(r"lladdr\s+([0-9a-f:]{17})", result.stdout, re.IGNORECASE)
            if m:
                return m.group(1)
    except Exception:
        pass

    return None


def wait_for_host(host: str, port: int = 22, timeout: int = 60, interval: int = 2) -> bool:
    start_time = time.time()

    while time.time() - start_time < timeout:
        if port_open(host, port, timeout=2):
            return True
        time.sleep(interval)

    return False


def get_interface_info() -> Dict[str, Dict[str, str]]:
    interfaces: Dict[str, Dict[str, str]] = {}
    system = platform.system()
    try:
        if shutil.which("ip"):
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            current_iface = None
            for line in result.stdout.split("\n"):
                iface_match = re.match(r"^(\d+):\s+(\w+):", line)
                if iface_match:
                    current_iface = iface_match.group(2)
                    interfaces[current_iface] = {}
                elif current_iface:
                    ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if ip_match:
                        interfaces[current_iface]["ip"] = ip_match.group(1)
                    mac_match = re.search(r"link/ether\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                    if mac_match:
                        interfaces[current_iface]["mac"] = mac_match.group(1)
        elif system == "Darwin" and shutil.which("ifconfig"):
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            current_iface = None
            for line in result.stdout.split("\n"):
                m_iface = re.match(r"^(\w+):", line)
                if m_iface:
                    current_iface = m_iface.group(1)
                    interfaces[current_iface] = {}
                    continue
                if current_iface:
                    ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        # Prefix length parsing omitted here; for display only
                        interfaces[current_iface]["ip"] = ip_match.group(1)
                    mac_match = re.search(r"ether\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                    if mac_match:
                        interfaces[current_iface]["mac"] = mac_match.group(1)
    except Exception:
        pass
    return interfaces
