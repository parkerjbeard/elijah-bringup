import time
import json
import telnetlib
import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
import requests
import paramiko
from requests.exceptions import RequestException, Timeout

from ..config import RadioConfig, RadioRole, Config
from .mh_profile import MHProfile, detect_profile
from ..utils.network import (
    port_open, discover_services, get_mac_address, 
    find_mac_in_leases, wait_for_host
)
from ..utils.logging import get_logger, info, success, error, warning

logger = get_logger(__name__)

@dataclass
class MicrohardConnection:
    ip: str
    ssh_available: bool
    http_available: bool
    telnet_available: bool
    mac_address: Optional[str] = None

class MicrohardDriver:
    def __init__(self, ip: str = Config.DEFAULT_MICROHARD_IP, 
                 username: str = Config.DEFAULT_MICROHARD_USER,
                 password: str = Config.DEFAULT_MICROHARD_PASS):
        self.ip = ip
        self.username = username
        self.password = password
        self.session_token = None
        self.original_mac = None
        self.staged_config = {}
        self.profile: Optional[MHProfile] = None
        # Semantic radio/stats parameters staged independent of UCI layout
        self._radio_params: Dict[str, Any] = {}
        self._stats_params: Dict[str, Any] = {}
        
    def _detect_profile_via_http(self) -> Optional[MHProfile]:
        """Best-effort Microhard profile detection over HTTP using LuCI RPC.

        Tries to fetch the `mh_radio` config with `uci.get_all`. If present, we
        assume the placeholder mapping (until a live map is confirmed).
        """
        try:
            url = f"http://{self.ip}/cgi-bin/luci/rpc/uci"
            payload = {"id": 1, "method": "get_all", "params": ["mh_radio"]}
            r = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
            if r.ok:
                j = r.json()
                if j:
                    # Presence is enough to select our placeholder mapping
                    return MHProfile(
                        name="mh_radio_v1",
                        uci_keys={
                            # Semantic -> (config, section, option)
                            "role": ("mh_radio", "@mh[0]", "mode"),
                            "freq_mhz": ("mh_radio", "@mh[0]", "freq_mhz"),
                            "bw_mhz": ("mh_radio", "@mh[0]", "bw_mhz"),
                            "net_id": ("mh_radio", "@mh[0]", "net_id"),
                            "aes_key": ("mh_radio", "@mh[0]", "aes_key"),
                            # Network keys (when switching to DHCP client)
                            "dhcp_proto": ("network", "lan", "proto"),
                            # Radio stats block (if present on the build)
                            "stats_enable": ("mh_stats", "@stats[0]", "enable"),
                            "stats_port": ("mh_stats", "@stats[0]", "port"),
                            "stats_interval": ("mh_stats", "@stats[0]", "interval"),
                            "stats_fields": ("mh_stats", "@stats[0]", "fields"),
                        },
                    )
        except Exception as e:
            logger.debug(f"HTTP profile detect failed: {e}")
        return None

    def discover(self, timeout: float = 2.0) -> MicrohardConnection:
        logger.info(f"Discovering Microhard radio at {self.ip}")
        services = discover_services(self.ip, timeout)
        
        if not any(services.values()):
            error(f"No services found at {self.ip}")
            error("Please power-cycle the radio and switch together, then try again")
            raise ConnectionError(f"Cannot reach Microhard radio at {self.ip}")
        
        mac = get_mac_address(self.ip)
        if mac:
            self.original_mac = mac
            logger.debug(f"Radio MAC address: {mac}")
        
        connection = MicrohardConnection(
            ip=self.ip,
            ssh_available=services['ssh'],
            http_available=services['http'],
            telnet_available=services['telnet'],
            mac_address=mac
        )
        # Persist MAC for later discovery (health --radio-ip auto)
        try:
            if mac:
                from pathlib import Path
                path = Config.STATE_DIR / "last_radio_mac.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, 'w') as f:
                    f.write(mac.strip())
        except Exception:
            pass
        
        info(f"Found services - SSH: {services['ssh']}, HTTP: {services['http']}, Telnet: {services['telnet']}")
        return connection
    
    def _ssh_execute(self, command: str) -> Tuple[bool, str]:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.ip,
                username=self.username,
                password=self.password,
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')
            
            client.close()
            
            if error_output:
                logger.warning(f"SSH stderr: {error_output}")
            
            return True, output
            
        except Exception as e:
            logger.error(f"SSH execution failed: {e}")
            return False, str(e)
    
    def _ubus_login(self) -> Optional[str]:
        try:
            url = f"http://{self.ip}/cgi-bin/luci/rpc/auth"
            payload = {"id": 1, "method": "login", "params": [self.username, self.password]}
            response = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
            response.raise_for_status()
            j = response.json()
            # Guard on error payloads
            if isinstance(j, dict) and "error" in j:
                logger.error(f"ubus login error: {j['error']}")
                return None
            token: Optional[str] = None
            # Accept both list-wrapped and flat shapes
            if isinstance(j.get("result"), list) and len(j["result"]) > 1:
                token = j["result"][1].get("ubus_rpc_session")
            if not token:
                token = j.get("ubus_rpc_session")
            if token:
                logger.debug(f"Got ubus session token: {token[:8]}...")
            return token
        except Exception as e:
            logger.error(f"ubus login failed: {e}")
            return None
    
    def _ubus_call(self, service: str, method: str, params: Dict[str, Any]) -> Optional[Dict]:
        if not self.session_token:
            self.session_token = self._ubus_login()
            if not self.session_token:
                return None
        
        try:
            url = f"http://{self.ip}/ubus"
            payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "call",
                "params": [self.session_token, service, method, params]
            }
            
            response = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
            response.raise_for_status()
            j = response.json()
            if isinstance(j, dict) and "error" in j:
                logger.error(f"ubus error: {j['error']}")
                return None
            return j
            
        except Exception as e:
            logger.error(f"ubus call failed: {e}")
            return None
    
    def _stage_system_config(self, config: RadioConfig):
        self.staged_config['system'] = {
            '@system[0]': {
                'hostname': config.hostname,
                'description': config.description
            }
        }
        logger.debug(f"Staged system config: hostname={config.hostname}")
    
    def _stage_radio_params(self, config: RadioConfig):
        # Stage semantic radio params; mapping to UCI happens during apply via profile
        self._radio_params = {
            'role': config.mode,
            'freq_mhz': int(config.frequency),
            'bw_mhz': int(config.bandwidth),
            'net_id': config.net_id,
            'aes_key': config.aes_key,
        }
        logger.debug(
            f"Staged radio params: role={config.mode}, freq={config.frequency}, bw={config.bandwidth}, net={config.net_id}"
        )
    
    def _stage_network_config(self, config: RadioConfig):
        if config.dhcp_client:
            self.staged_config['network'] = {
                'lan': {
                    'proto': 'dhcp'
                }
            }
            logger.debug("Staged network config: DHCP client")
    
    def _stage_radio_stats_config(self, config: RadioConfig):
        if config.radio_stats_enabled:
            self._stats_params = {
                'enable': '1',
                'port': str(config.radio_stats_port),
                'interval': str(config.radio_stats_interval),
                'fields': 'rf,rssi,snr,associated_ip',
            }
            logger.debug(f"Staged radio stats (semantic): port={config.radio_stats_port}")
    
    def _freq_to_channel(self, freq: int) -> int:
        channel_map = {
            2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5,
            2437: 6, 2442: 7, 2447: 8, 2452: 9, 2457: 10,
            2462: 11, 2467: 12, 2472: 13, 2484: 14
        }
        return channel_map.get(freq, 4)
    
    def stage_config(self, config: RadioConfig):
        info(f"Staging configuration for {config.role.value} radio")
        
        self.staged_config = {}
        self._stage_system_config(config)
        # Do NOT stage generic OpenWrt wireless fields; map via Microhard profile during apply
        self._stage_network_config(config)
        self._stage_radio_stats_config(config)
        self._stage_radio_params(config)
        
        success(f"Configuration staged for {config.hostname}")

    def _detect_profile_via_ssh(self) -> Optional[MHProfile]:
        ok, out = self._ssh_execute("uci show 2>/dev/null || true")
        if ok:
            prof = detect_profile(out)
            if prof:
                logger.debug(f"Detected Microhard profile: {prof.name}")
            else:
                logger.warning("Unknown Microhard UCI layout; profile detection failed")
            return prof
        return None

    def _apply_profile_sets_ssh(self, kv: Dict[str, Any]) -> bool:
        if not self.profile:
            self.profile = self._detect_profile_via_ssh()
        if not self.profile:
            error("Cannot apply radio params: unknown Microhard UCI layout")
            return False
        # Execute uci set for each mapped key
        for semantic_key, value in kv.items():
            if semantic_key not in self.profile.uci_keys:
                continue
            cfg, section, option = self.profile.uci_keys[semantic_key]
            cmd = f"uci set {cfg}.{section}.{option}='{value}'"
            success_flag, output = self._ssh_execute(cmd)
            if not success_flag:
                error(f"Failed to set {cfg}.{section}.{option}: {output}")
                return False
        return True

    def _apply_profile_sets_http(self, kv: Dict[str, Any]) -> bool:
        if not self.profile:
            # Try to detect profile via HTTP (LuCI RPC)
            self.profile = self._detect_profile_via_http()
        if not self.profile:
            error("Cannot apply radio params: unknown Microhard UCI layout")
            return False
        for semantic_key, value in kv.items():
            if semantic_key not in self.profile.uci_keys:
                continue
            cfg, section, option = self.profile.uci_keys[semantic_key]
            result = self._ubus_call("uci", "set", {
                "config": cfg,
                "section": section,
                "values": {option: value},
            })
            if not result:
                error(f"Failed to set {cfg}.{section}.{option} via HTTP")
                return False
        return True
    
    def apply_via_ssh(self) -> bool:
        info("Applying configuration via SSH")
        # Apply staged generic configs (system/network)
        for config_type, sections in self.staged_config.items():
            for section, values in sections.items():
                for key, value in values.items():
                    if section.startswith('@'):
                        cmd = f"uci set {config_type}.{section}.{key}='{value}'"
                    else:
                        cmd = f"uci set {config_type}.{section}.{key}='{value}'"
                    
                    success_flag, output = self._ssh_execute(cmd)
                    if not success_flag:
                        error(f"Failed to set {key}: {output}")
                        return False
        # Apply radio params and stats via profile mapping
        if self._radio_params:
            if not self._apply_profile_sets_ssh({
                'role': self._radio_params.get('role'),
                'freq_mhz': self._radio_params.get('freq_mhz'),
                'bw_mhz': self._radio_params.get('bw_mhz'),
                'net_id': self._radio_params.get('net_id'),
                'aes_key': self._radio_params.get('aes_key'),
            }):
                return False
        if self._stats_params:
            if not self._apply_profile_sets_ssh({
                'stats_enable': self._stats_params.get('enable'),
                'stats_port': self._stats_params.get('port'),
                'stats_interval': self._stats_params.get('interval'),
                'stats_fields': self._stats_params.get('fields'),
            }):
                return False

        # Commit configs written above
        for config_type in self.staged_config.keys():
            cmd = f"uci commit {config_type}"
            success_flag, output = self._ssh_execute(cmd)
            if not success_flag:
                error(f"Failed to commit {config_type}: {output}")
                return False
        # Also commit Microhard-specific configs if profile detected
        if self.profile:
            commit_targets = {cfg for (_, (cfg, _, _)) in self.profile.uci_keys.items()}
            for cfg in commit_targets:
                success_flag, output = self._ssh_execute(f"uci commit {cfg}")
                if not success_flag:
                    error(f"Failed to commit {cfg}: {output}")
                    return False
        
        success("Configuration committed via SSH")
        return True
    
    def apply_via_http(self) -> bool:
        info("Applying configuration via HTTP/ubus")
        
        if not self.session_token:
            self.session_token = self._ubus_login()
            if not self.session_token:
                error("Failed to authenticate with radio")
                return False
        
        # Apply staged generic configs (system/network)
        for config_type, sections in self.staged_config.items():
            for section, values in sections.items():
                result = self._ubus_call("uci", "set", {
                    "config": config_type,
                    "section": section,
                    "values": values
                })
                
                if not result:
                    error(f"Failed to set {config_type}.{section}")
                    return False
        # Apply radio params and stats via profile mapping
        if self._radio_params:
            if not self._apply_profile_sets_http({
                'role': self._radio_params.get('role'),
                'freq_mhz': self._radio_params.get('freq_mhz'),
                'bw_mhz': self._radio_params.get('bw_mhz'),
                'net_id': self._radio_params.get('net_id'),
                'aes_key': self._radio_params.get('aes_key'),
            }):
                return False
        if self._stats_params:
            if not self._apply_profile_sets_http({
                'stats_enable': self._stats_params.get('enable'),
                'stats_port': self._stats_params.get('port'),
                'stats_interval': self._stats_params.get('interval'),
                'stats_fields': self._stats_params.get('fields'),
            }):
                return False

        for config_type in self.staged_config.keys():
            result = self._ubus_call("uci", "commit", {"config": config_type})
            if not result:
                error(f"Failed to commit {config_type}")
                return False
        # Commit Microhard-specific configs if profile detected
        if self.profile:
            commit_targets = {cfg for (_, (cfg, _, _)) in self.profile.uci_keys.items()}
            for cfg in commit_targets:
                result = self._ubus_call("uci", "commit", {"config": cfg})
                if not result:
                    error(f"Failed to commit {cfg}")
                    return False
        
        success("Configuration committed via HTTP")
        return True
    
    def apply_config(self, prefer_ssh: bool = True) -> bool:
        if not self.staged_config:
            warning("No configuration staged")
            return False
        
        connection = self.discover()
        
        if prefer_ssh and connection.ssh_available:
            result = self.apply_via_ssh()
        elif connection.http_available:
            result = self.apply_via_http()
        else:
            error("No suitable connection method available")
            return False
        
        if result:
            info("Configuration applied successfully")
            self.staged_config = {}
            # Clear staged semantic once applied
            self._radio_params = {}
            self._stats_params = {}
        
        return result
    
    def reboot(self) -> bool:
        info("Rebooting radio...")
        
        connection = self.discover()
        
        if connection.ssh_available:
            success_flag, output = self._ssh_execute("sync; reboot")
            if success_flag:
                success("Reboot command sent via SSH")
                return True
        
        if connection.http_available and self.session_token:
            result = self._ubus_call("system", "reboot", {})
            if result:
                success("Reboot command sent via HTTP")
                return True
        
        error("Failed to send reboot command")
        return False
    
    def wait_for_dhcp_flip(self, timeout: int = 120) -> Optional[str]:
        if not self.original_mac:
            warning("No original MAC address recorded")
            return None
        
        info(f"Waiting for radio to get DHCP address (MAC: {self.original_mac})")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Try to warm ARP on the current /24 at least before reading
            new_ip = find_mac_in_leases(self.original_mac)
            if new_ip and new_ip != self.ip:
                success(f"Radio obtained new IP: {new_ip}")
                self.ip = new_ip
                return new_ip
            time.sleep(2)
        
        warning("Timeout waiting for DHCP flip")
        return None
    
    def safe_reset(self) -> bool:
        info("Performing safe reset via AT commands")
        
        connection = self.discover()
        if not connection.telnet_available:
            error("Telnet not available for safe reset")
            return False
        
        try:
            tn = telnetlib.Telnet(self.ip, 23, Config.TELNET_TIMEOUT)
            
            tn.read_until(b"login: ", timeout=5)
            tn.write(self.username.encode() + b"\n")
            
            tn.read_until(b"Password: ", timeout=5)
            tn.write(self.password.encode() + b"\n")
            
            time.sleep(1)
            
            tn.write(b"AT+MSRTF=0\r\n")
            time.sleep(1)
            
            tn.write(b"AT+MSRTF=1\r\n")
            time.sleep(1)
            
            tn.close()
            
            success("Safe reset completed")
            return True
            
        except Exception as e:
            error(f"Safe reset failed: {e}")
            return False
    
    def provision(self, config: RadioConfig) -> bool:
        try:
            connection = self.discover()
            info(f"Provisioning {config.role.value} radio: {config.hostname}")
            
            self.stage_config(config)
            
            if not self.apply_config():
                error("Failed to apply configuration")
                return False
            
            if not self.reboot():
                warning("Reboot command may have failed")
            
            time.sleep(12)
            
            if config.dhcp_client:
                new_ip = self.wait_for_dhcp_flip()
                if new_ip:
                    info(f"Radio accessible at new IP: {new_ip}")
                else:
                    warning("Could not determine new IP address")
            
            success(f"Radio {config.hostname} provisioned successfully")
            return True
            
        except Exception as e:
            error(f"Provisioning failed: {e}")
            return False
