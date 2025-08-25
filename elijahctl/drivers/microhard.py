import time
import shlex
import json
import logging
import asyncio
import contextlib
import socket
from typing import Optional, Dict, Any, Tuple
import telnetlib3
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

_SENSITIVE_KEYS = ("password", "pass", "key", "secret", "token", "ubus_rpc_session", "aes")

def _mask_value(v: Any) -> Any:
    if isinstance(v, str):
        if not v:
            return v
        if len(v) <= 4:
            return "****"
        return v[:2] + "***" + v[-2:]
    return v

def _mask_dict(obj: Any) -> Any:
    try:
        if isinstance(obj, dict):
            masked = {}
            for k, v in obj.items():
                if any(s in str(k).lower() for s in _SENSITIVE_KEYS):
                    masked[k] = _mask_value(v)
                else:
                    masked[k] = _mask_dict(v)
            return masked
        if isinstance(obj, list):
            return [_mask_dict(v) for v in obj]
    except Exception:
        pass
    return obj

def _mask_cmd(cmd: str) -> str:
    try:
        s = cmd.strip()
        if s.startswith("uci set ") and "=" in s:
            left, right = s.split("=", 1)
            option = left.split(".")[-1].strip().lower()
            if any(t in option for t in _SENSITIVE_KEYS):
                return left + "=******"
        return cmd
    except Exception:
        return cmd

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
        """Detect Microhard UCI profile over HTTP using ubus with auth.

        Uses ubus session login and a uci get (or get_all) to confirm the
        presence of mh_radio, then returns our placeholder mapping.
        """
        try:
            if not self.session_token:
                self.session_token = self._ubus_login()
            if not self.session_token:
                return None
            logger.debug("Attempting HTTP profile detect via uci.get_all mh_radio")
            j = self._ubus_call("uci", "get_all", {"config": "mh_radio"})
            if j:
                logger.debug("HTTP profile detect succeeded; using mh_radio_v1 placeholder mapping")
                return MHProfile(
                    name="mh_radio_v1",
                    uci_keys={
                        # Semantic -> (config, section, option)
                        "role": ("mh_radio", "@mh[0]", "mode"),
                        "freq_mhz": ("mh_radio", "@mh[0]", "freq_mhz"),
                        "bw_mhz": ("mh_radio", "@mh[0]", "bw_mhz"),
                        "net_id": ("mh_radio", "@mh[0]", "net_id"),
                        "aes_key": ("mh_radio", "@mh[0]", "aes_key"),
                        # New mappings: TX power and encryption switch
                        "tx_power": ("mh_radio", "@mh[0]", "tx_power"),
                        "encrypt_enable": ("mh_radio", "@mh[0]", "encrypt"),
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
                try:
                    import os
                    os.chmod(path, 0o600)
                except Exception:
                    pass
        except Exception:
            pass
        
        info(f"Found services - SSH: {services['ssh']}, HTTP: {services['http']}, Telnet: {services['telnet']}")
        return connection
    
    def _ssh_execute(self, command: str, *, try_exec_first: bool = True) -> Tuple[bool, str]:
        try:
            logger.debug(f"SSH connecting to {self.ip} as {self.username} with password: {'*' * len(self.password)}")
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
            # Fast path: try non-interactive exec first (cheap and simple commands)
            if try_exec_first:
                try:
                    logger.debug(f"SSH exec_command: {_mask_cmd(command)}")
                    stdin, stdout, stderr = client.exec_command(command)
                    # Paramiko’s stdout is ready when returned; drain with a bounded wait
                    end_by = time.time() + 10
                    while not stdout.channel.exit_status_ready() and time.time() < end_by:
                        time.sleep(0.05)
                    rc = stdout.channel.recv_exit_status()
                    out = stdout.read().decode("utf-8", errors="ignore")
                    err = stderr.read().decode("utf-8", errors="ignore")
                    if rc == 0 and (out or not err):
                        client.close()
                        return True, out.strip()
                except Exception as e:
                    logger.debug(f"exec_command path failed, falling back to shell: {e}")

            # Fallback: interactive shell to get out of Microhard CLI into BusyBox
            logger.debug(f"SSH invoking shell for command: {_mask_cmd(command)}")
            channel = client.invoke_shell()
            channel.settimeout(10.0)
            
            # Wait for initial prompt and detect if we're in CLI or shell
            time.sleep(1)
            initial_output = ""
            if channel.recv_ready():
                initial_output = channel.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"Initial prompt: {initial_output[-50:]}")  # Log last 50 chars to see prompt
            
            # Check if we're in the Microhard CLI (UserDevice> prompt)
            if "UserDevice>" in initial_output or "ERROR: Invalid command" in initial_output:
                logger.debug("Detected Microhard CLI, entering Linux shell")
                # Try common commands to enter shell
                for shell_cmd in ["sh", "shell", "system", "/bin/sh"]:
                    channel.send(f"{shell_cmd}\n")
                    time.sleep(0.5)
                    if channel.recv_ready():
                        shell_output = channel.recv(4096).decode('utf-8', errors='ignore')
                        if "#" in shell_output or "$" in shell_output or "~" in shell_output:
                            logger.debug(f"Successfully entered shell with '{shell_cmd}'")
                            break
                        elif "ERROR" not in shell_output:
                            # Might have worked but no prompt yet
                            break
            
            # Now execute the actual command inside the shell
            channel.send(f"{command}\n")
            time.sleep(1)  # Give command time to execute
            
            # Collect output
            output = ""
            retries = 0
            while retries < 5:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    retries = 0  # Reset retries if we got data
                else:
                    time.sleep(0.2)
                    retries += 1
            
            # Clean up and close
            channel.send("exit\n")
            time.sleep(0.2)
            if "UserDevice>" in output:  # We're back in CLI
                channel.send("exit\n")  # Exit CLI too
            channel.close()
            client.close()
            
            # Clean output - remove command echo and prompts
            lines = output.split('\n')
            cleaned_lines = []
            for line in lines:
                # Skip lines that are just the command echo or prompts
                if line.strip() == command:
                    continue
                if line.strip() in ['#', '$', 'UserDevice>', '']:
                    continue
                if "UserDevice>" in line and len(line.strip()) < 20:
                    continue
                cleaned_lines.append(line)
            
            output = '\n'.join(cleaned_lines).strip()
            
            logger.debug(f"SSH command completed, output length: {len(output)}")
            return True, output
            
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed for {self.username}@{self.ip}: {e}")
            logger.debug(f"Attempted credentials - username: {self.username}, password length: {len(self.password)}")
            return False, f"Authentication failed: {e}"
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {e}")
            return False, f"SSH error: {e}"
        except socket.timeout as e:
            logger.error(f"SSH command timed out: {command}")
            return False, f"Command timed out: {e}"
        except Exception as e:
            logger.error(f"SSH execution failed: {e}")
            return False, str(e)
    
    def _ubus_login(self) -> Optional[str]:
        """Authenticate to the device, preferring LuCI RPC then falling back to raw ubus."""
        # First try LuCI RPC auth proxy
        try:
            url = f"http://{self.ip}/cgi-bin/luci/rpc/auth"
            payload = {"id": 1, "method": "login", "params": [self.username, self.password]}
            logger.debug(f"HTTP POST {url} payload={_mask_dict(payload)}")
            response = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
            if response.ok:
                j = response.json()
                logger.debug(f"HTTP auth proxy response: {_mask_dict(j)}")
                if isinstance(j, dict) and "result" in j:
                    res = j.get("result")
                    # Some builds: [0, {ubus_rpc_session: ...}]
                    if isinstance(res, list) and len(res) > 1 and isinstance(res[1], dict):
                        token = res[1].get("ubus_rpc_session")
                        if token:
                            return token
                    # Others: flat dict
                    token = j.get("ubus_rpc_session")
                    if token:
                        return token
        except Exception:
            pass
        # Fallback: raw ubus session login
        try:
            url = f"http://{self.ip}/ubus"
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "call",
                "params": [
                    "00000000000000000000000000000000",
                    "session",
                    "login",
                    {"username": self.username, "password": self.password},
                ],
            }
            logger.debug(f"HTTP POST {url} payload={_mask_dict(payload)}")
            response = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
            if response.ok:
                j = response.json()
                logger.debug(f"ubus login response: {_mask_dict(j)}")
                res = j.get("result")
                if isinstance(res, list) and len(res) > 1:
                    code = res[0]
                    data = res[1] if isinstance(res[1], dict) else {}
                    token = data.get("ubus_rpc_session")
                    if code == 0 and token:
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
        
        def do_call(token: str) -> Optional[Dict]:
            try:
                url = f"http://{self.ip}/ubus"
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "call",
                    "params": [token, service, method, params],
                }
                logger.debug(f"ubus call {service}.{method} params={_mask_dict(params)}")
                response = requests.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
                if not response.ok:
                    logger.debug(f"ubus call HTTP status {response.status_code}")
                    return None
                j = response.json()
                logger.debug(f"ubus call response: {_mask_dict(j)}")
                # Handle top-level error or non-zero result code
                if isinstance(j, dict):
                    if "error" in j:
                        return None
                    res = j.get("result")
                    if isinstance(res, list) and len(res) > 0 and isinstance(res[0], int) and res[0] != 0:
                        return None
                return j
            except Exception:
                return None

        # First attempt
        j = do_call(self.session_token)
        if j is not None:
            return j
        # Retry once after re-login (possible expired session)
        self.session_token = self._ubus_login()
        if not self.session_token:
            return None
        return do_call(self.session_token)
    
    def _uci_add_http(self, config: str, type_: str) -> Optional[str]:
        """Add a dynamic section via ubus uci.add and return its section id (e.g., cfg0abc)."""
        j = self._ubus_call("uci", "add", {"config": config, "type": type_})
        try:
            res = j.get("result", []) if isinstance(j, dict) else []
            if len(res) > 1 and isinstance(res[1], dict):
                return res[1].get("section")
        except Exception:
            pass
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
        encrypt_enable = "1" if str(config.encryption).lower().startswith("aes") else "0"
        self._radio_params = {
            'role': config.mode,
            'freq_mhz': int(config.frequency),
            'bw_mhz': int(config.bandwidth),
            'net_id': config.net_id,
            'aes_key': config.aes_key,
            'tx_power': int(config.tx_power),
            'encrypt_enable': encrypt_enable,
        }
        logger.debug(
            f"Staged radio params: role={config.mode}, freq={config.frequency}, bw={config.bandwidth}, net={config.net_id}, tx_power={config.tx_power}, encrypt={encrypt_enable}"
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
        logger.debug("Detecting profile via SSH: uci show")
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
        # Ensure dynamic sections exist when we refer to @stats[0]
        if any(sk.startswith("stats_") for sk in kv):
            ok, out = self._ssh_execute(
                "uci -q show mh_stats | grep -q \"@stats\\[0\\]\" || uci add mh_stats stats && uci commit mh_stats"
            )
            if not ok:
                warning("Could not ensure mh_stats section exists; proceeding anyway")
        # Execute uci set for each mapped key
        for semantic_key, value in kv.items():
            if semantic_key not in self.profile.uci_keys:
                continue
            cfg, section, option = self.profile.uci_keys[semantic_key]
            val = shlex.quote(str(value))
            cmd = f"uci set {cfg}.{section}.{option}={val}"
            logger.debug(f"SSH applying mapped set: {_mask_cmd(cmd)}")
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
        stats_section = "@stats[0]"
        if any(sk.startswith("stats_") for sk in kv):
            # Ensure mh_stats section exists; prefer explicit add via ubus
            logger.debug("Ensuring mh_stats stats section exists (ubus add)")
            added = self._uci_add_http("mh_stats", "stats") if hasattr(self, "_uci_add_http") else None
            if added:
                stats_section = added
            else:
                # Last resort: try touching @stats[0] if already present
                self._ubus_call("uci", "set", {
                    "config": "mh_stats", "section": stats_section, "values": {"enable": "0"}
                })
        for semantic_key, value in kv.items():
            if semantic_key not in self.profile.uci_keys:
                continue
            cfg, section, option = self.profile.uci_keys[semantic_key]
            if section.startswith("@stats[") and semantic_key.startswith("stats_"):
                section = stats_section
            logger.debug(f"HTTP applying mapped set {cfg}.{section}.{option}={_mask_value(str(value))}")
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
        logger.debug(f"Using SSH credentials - username: {self.username}, password: {'*' * len(self.password)}")
        
        # First test SSH connectivity with a simple command
        logger.debug("Testing SSH connectivity with 'echo test' command")
        test_success, test_output = self._ssh_execute("echo test")
        if not test_success:
            error(f"SSH connection test failed: {test_output}")
            return False
        logger.debug(f"SSH test successful: {test_output.strip()}")
        
        # Apply staged generic configs (system/network)
        for config_type, sections in self.staged_config.items():
            for section, values in sections.items():
                for key, value in values.items():
                    val = shlex.quote(str(value))
                    if section.startswith('@'):
                        cmd = f"uci set {config_type}.{section}.{key}={val}"
                    else:
                        cmd = f"uci set {config_type}.{section}.{key}={val}"
                    logger.debug(f"SSH applying set: {_mask_cmd(cmd)}")
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
                'tx_power': self._radio_params.get('tx_power'),
                'encrypt_enable': self._radio_params.get('encrypt_enable'),
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
            logger.debug(f"SSH commit: {cmd}")
            success_flag, output = self._ssh_execute(cmd)
            if not success_flag:
                error(f"Failed to commit {config_type}: {output}")
                return False
        # Also commit Microhard-specific configs if profile detected
        if self.profile:
            commit_targets = {cfg for (_, (cfg, _, _)) in self.profile.uci_keys.items()}
            for cfg in commit_targets:
                logger.debug(f"SSH commit: uci commit {cfg}")
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
                logger.debug(f"HTTP set {config_type}.{section} values={_mask_dict(values)}")
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
                'tx_power': self._radio_params.get('tx_power'),
                'encrypt_enable': self._radio_params.get('encrypt_enable'),
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
            logger.debug(f"HTTP commit: {config_type}")
            result = self._ubus_call("uci", "commit", {"config": config_type})
            if not result:
                error(f"Failed to commit {config_type}")
                return False
        # Commit Microhard-specific configs if profile detected
        if self.profile:
            commit_targets = {cfg for (_, (cfg, _, _)) in self.profile.uci_keys.items()}
            for cfg in commit_targets:
                logger.debug(f"HTTP commit: {cfg}")
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
        
        logger.debug("Beginning apply_config; discovering connection methods")
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
            logger.debug("Sending reboot via SSH")
            success_flag, output = self._ssh_execute("sync; reboot")
            if success_flag:
                success("Reboot command sent via SSH")
                return True
        
        if connection.http_available and self.session_token:
            logger.debug("Sending reboot via HTTP/ubus")
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
        
        async def _do_telnet_reset(host: str, username: str, password: str) -> None:
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, 23, encoding="utf8"),
                timeout=Config.TELNET_TIMEOUT,
            )
            try:
                # Telnet may expose either Microhard CLI or require login first
                info(f"Telnet: session opened to {host}:23; detecting prompt type")
                
                # Send a newline and wait a bit to see what prompt we get
                writer.write("\r\n"); await writer.drain()
                await asyncio.sleep(0.5)
                
                # Try to read any initial output
                initial_data = ""
                try:
                    initial_data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    if isinstance(initial_data, bytes):
                        initial_data = initial_data.decode("utf-8", errors="ignore")
                    logger.debug(f"Initial telnet response: {initial_data[-100:]}")
                except asyncio.TimeoutError:
                    logger.debug("No initial response from telnet")
                
                # Check if we need to login or are already at a prompt
                if "login:" in initial_data.lower() or "username:" in initial_data.lower():
                    info("Telnet: Login prompt detected, authenticating")
                    writer.write(username + "\r\n"); await writer.drain()
                    await asyncio.sleep(0.5)
                    
                    # Wait for password prompt
                    try:
                        pw_data = await asyncio.wait_for(reader.read(256), timeout=2)
                        if isinstance(pw_data, bytes):
                            pw_data = pw_data.decode("utf-8", errors="ignore")
                    except asyncio.TimeoutError:
                        pw_data = ""
                    
                    if "password:" in pw_data.lower():
                        writer.write(password + "\r\n"); await writer.drain()
                        await asyncio.sleep(0.5)
                
                # Now look for any prompt (UserDevice>, #, $, etc)
                writer.write("\r\n"); await writer.drain()
                await asyncio.sleep(0.5)
                
                # Read whatever prompt we have
                prompt_data = ""
                try:
                    prompt_data = await asyncio.wait_for(reader.read(256), timeout=2)
                    if isinstance(prompt_data, bytes):
                        prompt_data = prompt_data.decode("utf-8", errors="ignore")
                    logger.debug(f"Prompt data: {prompt_data[-50:]}")
                except asyncio.TimeoutError:
                    logger.debug("No prompt received")
                
                # Determine if we're in CLI or shell
                if "UserDevice>" in prompt_data or "#" in prompt_data or "$" in prompt_data:
                    if "UserDevice>" in prompt_data:
                        info("Telnet: Microhard CLI prompt detected")
                    else:
                        info("Telnet: Shell prompt detected")
                else:
                    # Try one more newline to get a prompt
                    writer.write("\r\n"); await writer.drain()
                    await asyncio.sleep(0.5)
                    info("Telnet: Proceeding with AT commands")

                async def send_and_wait_ok(cmd: str, timeout: float = 5.0) -> bool:
                    info(f"Telnet: sending {cmd}")
                    writer.write(cmd + "\r\n"); await writer.drain()
                    # Read until OK or ERROR
                    end_by = asyncio.get_event_loop().time() + timeout
                    buf = ""
                    while asyncio.get_event_loop().time() < end_by:
                        try:
                            chunk = await asyncio.wait_for(reader.read(128), timeout=0.5)
                        except Exception:
                            chunk = b""
                        if chunk:
                            # Normalize to text
                            if isinstance(chunk, (bytes, bytearray)):
                                chunk = chunk.decode("utf-8", errors="ignore")
                            buf += chunk
                            logger.debug(f"Response buffer: {buf[-100:]}")
                            if "OK" in buf:
                                info(f"Telnet: OK received for {cmd}")
                                return True
                            if "ERROR" in buf:
                                warning(f"Telnet: ERROR received for {cmd}")
                                return False
                    tail = buf[-120:] if buf else ""
                    warning(f"Telnet: timeout waiting for OK after {cmd}; tail='{tail}'")
                    # If we didn't get OK/ERROR but got some response, assume it worked
                    if len(buf) > 0:
                        info(f"Telnet: Got response but no OK/ERROR, assuming success")
                        return True
                    return False

                # Try ordered fallback variants
                variants = [
                    ("AT+MSRTF", True),  # preferred two-step reset
                    ("AT+MSRT", True),   # alternative two-step
                    ("AT&F", False),     # factory reset (last resort)
                ]

                for base, two_step in variants:
                    info(f"Telnet: attempting reset variant {base}")
                    if two_step:
                        ok1 = await send_and_wait_ok(f"{base}=0")
                        if not ok1:
                            info(f"Telnet: {base}=0 not acknowledged; trying next variant")
                            continue
                        ok2 = await send_and_wait_ok(f"{base}=1")
                        if ok2:
                            info(f"Telnet: reset acknowledged using variant {base}")
                            break
                        else:
                            info(f"Telnet: {base}=1 not acknowledged; trying next variant")
                            continue
                    else:
                        # Single-command factory reset
                        ok = await send_and_wait_ok(base)
                        if ok:
                            warning("Used AT&F factory reset variant; settings may revert to full factory defaults")
                            info("Telnet: reset acknowledged using variant AT&F")
                            break
                else:
                    # None of the variants ACKed
                    raise RuntimeError("No reset variant acknowledged with OK")
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        try:
            # Run the async telnet interaction
            asyncio.run(_do_telnet_reset(self.ip, self.username, self.password))
            success("Safe reset completed")
            return True
        except Exception as e:
            logger.exception("Safe reset failed during Telnet interaction")
            error(f"Safe reset failed: {e!r}")
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
