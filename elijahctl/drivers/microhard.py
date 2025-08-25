import time
import shlex
import json
import re
import logging
import asyncio
import contextlib
import socket
from typing import Optional, Dict, Any, Tuple
import telnetlib3
from dataclasses import dataclass
import requests
import paramiko
import urllib3
from requests.exceptions import RequestException, Timeout

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        
    # Choose https if 443 is open; otherwise http.
    def _http_base(self) -> str:
        try:
            if port_open(self.ip, 443, timeout=0.3):
                return f"https://{self.ip}"
        except Exception:
            pass
        return f"http://{self.ip}"

    def _resolve_section_id_http(self, config: str, type_: str, index: int = 0) -> Optional[str]:
        """Resolve @type[index] to a concrete UCI section id via ubus uci.get_all."""
        j = self._ubus_call("uci", "get_all", {"config": config})
        try:
            # Expected shape: {"result":[0,{"values":{"cfgXXXX":{"._":...,".type":"type", ...}, ...}}]}
            res = j.get("result", []) if isinstance(j, dict) else []
            if len(res) > 1 and isinstance(res[1], dict):
                values = res[1].get("values") or {}
                candidates = [sid for sid, sec in values.items() if isinstance(sec, dict) and sec.get(".type") == type_]
                if len(candidates) > index:
                    return candidates[index]
        except Exception:
            pass
        return None

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
            logger.debug(f"SSH credentials - user: '{self.username}', pass_len: {len(self.password)} (value masked)")
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
            logger.debug("Common issues:")
            logger.debug("  1. Check if password is correct (default: 'admin')")
            logger.debug("  2. Verify username is 'admin'")
            logger.debug("  3. Ensure radio is at factory defaults or password hasn't been changed")
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

    def _ssh_execute_at_session(self, commands: list[str]) -> Tuple[bool, str]:
        """Run a sequence of AT commands inside the Microhard SSH CLI.

        - Opens a persistent interactive shell via paramiko and verifies the
          proprietary CLI prompt ("UserDevice>").
        - Sends each command with a trailing newline and reads responses until
          either "OK" (success) or "ERROR" (failure) or timeout per-command.
        - Aggregates all output and returns (success, aggregated_output).

        This is required because the Microhard SSH endpoint drops directly into
        a CLI that only accepts AT commands and does not provide a Linux shell.
        """
        try:
            logger.debug(f"SSH(AT) connecting to {self.ip} as {self.username}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.ip,
                username=self.username,
                password=self.password,
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )

            chan = client.invoke_shell()
            # Use a modest read timeout; we'll still loop with our own deadline
            try:
                chan.settimeout(1.0)
            except Exception:
                pass

            # Nudge the CLI to print a prompt, then verify it's the Microhard CLI
            agg_out = ""
            start = time.time()
            deadline = start + 5.0
            try:
                chan.send("\n")
            except Exception:
                pass
            while time.time() < deadline:
                if chan.recv_ready():
                    chunk = chan.recv(4096).decode("utf-8", errors="ignore")
                    agg_out += chunk
                    if "UserDevice>" in agg_out:
                        break
                else:
                    time.sleep(0.05)
            if "UserDevice>" not in agg_out:
                logger.error("Did not observe Microhard CLI prompt 'UserDevice>' after login")
                try:
                    chan.close()
                finally:
                    client.close()
                return False, agg_out.strip()

            # Helper to send a single AT command and wait for OK/ERROR
            def send_and_wait(cmd: str, timeout: float = 5.0) -> Tuple[bool, str]:
                buf = ""
                try:
                    chan.send(cmd + "\n")
                except Exception as e:
                    return False, f"send failed: {e}"
                end_by = time.time() + timeout
                last_any = time.time()
                while time.time() < end_by:
                    if chan.recv_ready():
                        try:
                            data = chan.recv(4096)
                            if not data:
                                time.sleep(0.02)
                                continue
                            chunk = data.decode("utf-8", errors="ignore")
                        except Exception:
                            chunk = ""
                        if chunk:
                            buf += chunk
                            last_any = time.time()
                            # Check for terminal responses
                            if "ERROR" in buf:
                                return False, buf
                            if "OK" in buf:
                                return True, buf
                            # Special handling for AT&W command success
                            if cmd.strip().upper() == "AT&W" and "restarting" in buf.lower():
                                return True, buf
                    else:
                        # Small sleep to avoid busy loop
                        time.sleep(0.05)
                
                # If the channel is no longer active after sending AT&W, consider it a success
                if cmd.strip().upper() == "AT&W" and not chan.active:
                    return True, buf
                # Timed out waiting for an explicit OK/ERROR
                return False, buf

            # Execute the sequence
            for cmd in commands:
                info(f"AT: {cmd}")
                ok, resp = send_and_wait(cmd)
                agg_out += resp
                if not ok:
                    warning(f"AT command failed or timed out: {cmd}")
                    try:
                        chan.close()
                    finally:
                        client.close()
                    return False, agg_out.strip()

            # All commands OK; close channel and return
            try:
                chan.close()
            finally:
                client.close()
            return True, agg_out.strip()

        except paramiko.AuthenticationException as e:
            logger.error(f"SSH(AT) authentication failed for {self.username}@{self.ip}: {e}")
            return False, f"Authentication failed: {e}"
        except Exception as e:
            logger.error(f"SSH(AT) session error: {e}")
            return False, str(e)

    async def _telnet_execute_at_session_async(self, commands: list[str], *, per_cmd_timeout: float = 5.0) -> Tuple[bool, str]:
        """Async helper: run AT commands over Telnet using telnetlib3.

        - Opens a telnet connection on port 23.
        - If login prompts appear, sends username/password.
        - Ensures prompt then iterates through commands, waiting for OK/ERROR.
        Returns (success, aggregated_output).
        """
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(self.ip, 23, encoding="utf8"),
            timeout=Config.TELNET_TIMEOUT,
        )
        buf_all = ""
        try:
            # Provoke prompt and perform login handshake until we see UserDevice>
            writer.write("\r\n"); await writer.drain()
            await asyncio.sleep(0.3)
            sent_user = False
            sent_pass = False
            end_by = asyncio.get_event_loop().time() + 8.0
            while asyncio.get_event_loop().time() < end_by:
                try:
                    chunk = await asyncio.wait_for(reader.read(256), timeout=0.5)
                except asyncio.TimeoutError:
                    chunk = ""
                if chunk:
                    if isinstance(chunk, (bytes, bytearray)):
                        chunk = chunk.decode("utf-8", errors="ignore")
                    buf_all += chunk
                    low = buf_all.lower()
                    if not sent_user and ("login:" in low or "username:" in low):
                        writer.write(self.username + "\r\n"); await writer.drain()
                        sent_user = True
                        continue
                    if sent_user and not sent_pass and ("password:" in low):
                        writer.write(self.password + "\r\n"); await writer.drain()
                        sent_pass = True
                        continue
                    if "login incorrect" in low:
                        return False, buf_all
                    if "UserDevice>" in buf_all:
                        break
                else:
                    writer.write("\r\n"); await writer.drain()
            else:
                return False, buf_all

            async def send_wait_ok(cmd: str) -> Tuple[bool, str]:
                local_buf = ""
                writer.write(cmd + "\r\n"); await writer.drain()
                deadline = asyncio.get_event_loop().time() + per_cmd_timeout
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        chunk = await asyncio.wait_for(reader.read(128), timeout=0.5)
                    except asyncio.TimeoutError:
                        chunk = ""
                    if chunk:
                        if isinstance(chunk, (bytes, bytearray)):
                            chunk = chunk.decode("utf-8", errors="ignore")
                        local_buf += chunk
                        if "login incorrect" in local_buf.lower():
                            return False, local_buf
                        if "ERROR" in local_buf:
                            return False, local_buf
                        if "OK" in local_buf:
                            return True, local_buf
                return False, local_buf

            for cmd in commands:
                info(f"AT(telnet): {cmd}")
                ok, out = await send_wait_ok(cmd)
                buf_all += out
                if not ok:
                    return False, buf_all
            return True, buf_all
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _telnet_execute_at_session(self, commands: list[str], *, per_cmd_timeout: float = 5.0) -> Tuple[bool, str]:
        try:
            return asyncio.run(self._telnet_execute_at_session_async(commands, per_cmd_timeout=per_cmd_timeout))
        except Exception as e:
            logger.error(f"Telnet AT session error: {e}")
            return False, str(e)

    def _build_at_commands_from_staged(self) -> list:
        """Translate staged_config and semantic params into AT command list."""
        at_cmds: list[str] = []
        # System
        try:
            hostname = self.staged_config.get('system', {}).get('@system[0]', {}).get('hostname')
            if hostname:
                at_cmds.append(f"AT+MSMNAME={hostname}")
            if self.staged_config.get('system', {}).get('@system[0]', {}).get('description'):
                warning("System description is not supported via AT; skipping")
        except Exception:
            pass
        # Wireless
        if self._radio_params:
            role = str(self._radio_params.get('role') or '').strip()
            mode_val = 0 if role.lower() == 'master' else 1
            at_cmds.append(f"AT+MWVMODE={mode_val}")
            try:
                freq = int(self._radio_params.get('freq_mhz'))
                at_cmds.append(f"AT+MWFREQ={freq}")
            except Exception:
                warning("Invalid frequency in staged params; skipping")
            try:
                bw = int(self._radio_params.get('bw_mhz'))
                bw_code_map = {5: 0, 10: 1, 20: 2, 40: 3}
                bw_code = bw_code_map.get(bw, 0)
                if bw_code == 0 and bw != 5:
                    warning(f"Unsupported bandwidth {bw} MHz; using 5 MHz (code 0)")
                at_cmds.append(f"AT+MWBAND={bw_code}")
            except Exception:
                warning("Invalid bandwidth in staged params; skipping")
            net_id = self._radio_params.get('net_id')
            if net_id:
                at_cmds.append(f"AT+MWNETWORKID={net_id}")
            try:
                txp = int(self._radio_params.get('tx_power'))
                warning(f"Skipping TX power setting (value: {txp}) - command not supported on this model")
                # at_cmds.append(f"AT+MWTXPOWER={txp}")
            except Exception:
                warning("Invalid tx_power in staged params; skipping")
            encrypt_enable = str(self._radio_params.get('encrypt_enable') or '0').strip()
            aes_key = self._radio_params.get('aes_key')
            if encrypt_enable == '1' and aes_key:
                at_cmds.append(f"AT+MWVENCRYPT=1,{aes_key}")
            else:
                at_cmds.append("AT+MWVENCRYPT=0")
        # Network
        try:
            if self.staged_config.get('network', {}).get('lan', {}).get('proto') == 'dhcp':
                at_cmds.append("AT+MNIFACE=lan,EDIT,0")
        except Exception:
            pass
        # Stats
        if self._stats_params:
            try:
                enabled = str(self._stats_params.get('enable') or '0')
                port = int(self._stats_params.get('port') or 22222)
                interval = int(self._stats_params.get('interval') or 1000)
                if enabled == '1':
                    # Per docs: Status, Server IP, Port, Interval, RF flag, Network flag
                    # Using radio's own IP as placeholder - Jetson service will configure actual destination
                    at_cmds.append(f"AT+MRFRPT=1,{self.ip},{port},{interval},1,1")
                else:
                    at_cmds.append("AT+MRFRPT=0")
            except Exception:
                warning("Invalid stats params; skipping AT+MRFRPT")
        # Save
        at_cmds.append("AT&W")
        return at_cmds
    
    def _ubus_login(self) -> Optional[str]:
        """Authenticate to the device, preferring LuCI RPC then falling back to raw ubus."""
        # Create session with SSL verification disabled for weak/self-signed certificates
        session = requests.Session()
        session.verify = False
        base = self._http_base()
        
        # First try LuCI RPC auth proxy
        try:
            url = f"{base}/cgi-bin/luci/rpc/auth"
            payload = {"id": 1, "method": "login", "params": [self.username, self.password]}
            logger.debug(f"HTTP POST {url} payload={_mask_dict(payload)}")
            response = session.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
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
            url = f"{base}/ubus"
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
            response = session.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
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
        
        # Create session with SSL verification disabled
        session = requests.Session()
        session.verify = False
        base = self._http_base()
        
        def do_call(token: str) -> Optional[Dict]:
            try:
                url = f"{base}/ubus"
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "call",
                    "params": [token, service, method, params],
                }
                logger.debug(f"ubus call {service}.{method} params={_mask_dict(params)}")
                response = session.post(url, json=payload, timeout=Config.HTTP_TIMEOUT)
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
            # Resolve any '@type[idx]' to concrete section id
            if section.startswith("@"):
                m = re.match(r"@([A-Za-z0-9_]+)\[(\d+)\]", section)
                if m:
                    type_ = m.group(1)
                    idx = int(m.group(2))
                    resolved = self._resolve_section_id_http(cfg, type_, idx)
                    if not resolved:
                        # Create if missing
                        new_sid = self._uci_add_http(cfg, type_)
                        if new_sid:
                            resolved = new_sid
                    if not resolved:
                        error(f"Failed to resolve UCI section for {cfg}.{section}")
                        return False
                    section = resolved
            sval = str(value)
            logger.debug(f"HTTP applying mapped set {cfg}.{section}.{option}={_mask_value(sval)}")
            result = self._ubus_call("uci", "set", {
                "config": cfg,
                "section": section,
                "values": {option: sval},
            })
            if not result:
                error(f"Failed to set {cfg}.{section}.{option} via HTTP")
                return False
        return True
    
    def apply_via_ssh(self) -> bool:
        info("Applying configuration via SSH (AT CLI)")
        logger.debug(f"Using SSH credentials - username: {self.username}, password: {'*' * len(self.password)}")
        # Build AT command sequence from staged params
        at_cmds = self._build_at_commands_from_staged()

        ok, out = self._ssh_execute_at_session(at_cmds)
        if not ok:
            error(f"AT apply failed: {out[-200:] if out else out}")
            return False

        success("Configuration applied and saved via AT commands")
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
                # Resolve dynamic selectors like @system[0] to concrete section ids
                orig_section = section
                if isinstance(section, str) and section.startswith('@'):
                    m = re.match(r"@([A-Za-z0-9_]+)\[(\d+)\]", section)
                    if m:
                        type_ = m.group(1)
                        idx = int(m.group(2))
                        resolved = self._resolve_section_id_http(config_type, type_, idx)
                        if not resolved:
                            new_sid = self._uci_add_http(config_type, type_)
                            if new_sid:
                                resolved = new_sid
                        section = resolved or section
                logger.debug(f"HTTP set {config_type}.{section} values={_mask_dict(values)} (from {orig_section})")
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
            if not result and connection.http_available:
                warning("SSH failed, attempting HTTP/ubus fallback")
                result = self.apply_via_http()
                if result:
                    success("Configuration applied via HTTP fallback")
            if not result and connection.telnet_available:
                warning("SSH/HTTP failed, attempting Telnet AT fallback")
                at_cmds = self._build_at_commands_from_staged()
                result, _ = self._telnet_execute_at_session(at_cmds)
                if result:
                    success("Configuration applied via Telnet AT fallback")
        elif connection.http_available:
            info("Using HTTP/ubus for configuration")
            result = self.apply_via_http()
            if not result and connection.telnet_available:
                warning("HTTP failed, attempting Telnet AT fallback")
                at_cmds = self._build_at_commands_from_staged()
                result, _ = self._telnet_execute_at_session(at_cmds)
                if result:
                    success("Configuration applied via Telnet AT fallback")
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
        info("Rebooting radio via AT command")

        connection = self.discover()

        # Prefer SSH AT session
        if connection.ssh_available:
            try:
                ok, out = self._ssh_execute_at_session(["AT+MSREB"])
                if ok:
                    success("Reboot command acknowledged via SSH AT")
                    return True
                # Some firmware may reboot immediately without sending OK; treat as best-effort
                warning("SSH AT reboot may have been issued without OK; proceeding")
                return True
            except Exception as e:
                logger.debug(f"SSH AT reboot path failed: {e}")

        # Fallback to Telnet AT session
        if connection.telnet_available:
            try:
                ok, out = self._telnet_execute_at_session(["AT+MSREB"]) 
                if ok:
                    success("Reboot command acknowledged via Telnet AT")
                    return True
                warning("Telnet AT reboot may have been issued without OK; proceeding")
                return True
            except Exception as e:
                logger.debug(f"Telnet AT reboot path failed: {e}")

        error("Failed to send reboot command via available methods")
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
                
                # Try to reach the CLI prompt with basic auth handshake
                writer.write("\r\n"); await writer.drain()
                await asyncio.sleep(0.3)
                buf = ""
                sent_user = False
                sent_pass = False
                end_by = asyncio.get_event_loop().time() + 8.0
                while asyncio.get_event_loop().time() < end_by:
                    try:
                        chunk = await asyncio.wait_for(reader.read(256), timeout=0.5)
                    except asyncio.TimeoutError:
                        chunk = ""
                    if chunk:
                        if isinstance(chunk, (bytes, bytearray)):
                            chunk = chunk.decode("utf-8", errors="ignore")
                        buf += chunk
                        low = buf.lower()
                        if not sent_user and ("login:" in low or "username:" in low):
                            info("Telnet: Login prompt detected, authenticating")
                            writer.write(username + "\r\n"); await writer.drain()
                            sent_user = True
                            continue
                        if sent_user and not sent_pass and ("password:" in low):
                            writer.write(password + "\r\n"); await writer.drain()
                            sent_pass = True
                            # continue reading until prompt
                            continue
                        if "login incorrect" in low:
                            raise RuntimeError("Telnet login incorrect")
                        if "UserDevice>" in buf:
                            info("Telnet: Microhard CLI prompt detected")
                            break
                    else:
                        # Nudge prompt
                        writer.write("\r\n"); await writer.drain()
                else:
                    # Timed out waiting for CLI prompt
                    raise RuntimeError("No CLI prompt on Telnet after auth")

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
                            if "login incorrect" in chunk.lower():
                                warning("Telnet: login failed during command")
                                return False
                            if "OK" in buf:
                                info(f"Telnet: OK received for {cmd}")
                                return True
                            if "ERROR" in buf:
                                warning(f"Telnet: ERROR received for {cmd}")
                                return False
                    tail = buf[-120:] if buf else ""
                    warning(f"Telnet: timeout waiting for OK after {cmd}; tail='{tail}'")
                    return False

                async def send_and_confirm(cmd: str, timeout: float = 5.0) -> bool:
                    """Send command and handle confirmation prompts."""
                    info(f"Telnet: sending {cmd}")
                    writer.write(cmd + "\r\n"); await writer.drain()
                    # Read response
                    end_by = asyncio.get_event_loop().time() + timeout
                    buf = ""
                    while asyncio.get_event_loop().time() < end_by:
                        try:
                            chunk = await asyncio.wait_for(reader.read(128), timeout=0.5)
                        except Exception:
                            chunk = b""
                        if chunk:
                            if isinstance(chunk, (bytes, bytearray)):
                                chunk = chunk.decode("utf-8", errors="ignore")
                            buf += chunk
                            logger.debug(f"Response buffer: {buf[-200:]}")
                            
                            # Check for confirmation prompts
                            if "Please confirm action" in buf or "confirm" in buf.lower():
                                info("Telnet: Confirmation requested, sending AT+MSRTF=1")
                                writer.write("AT+MSRTF=1\r\n"); await writer.drain()
                                # Clear buffer to avoid re-triggering confirmation
                                buf = ""
                                # Continue reading for OK
                                continue
                            
                            if "OK" in buf:
                                info(f"Telnet: OK received for {cmd}")
                                return True
                            if "ERROR" in buf:
                                warning(f"Telnet: ERROR received for {cmd}")
                                return False
                    warning(f"Telnet: timeout for {cmd}")
                    return False

                # Try reset with confirmation handling
                info("Telnet: attempting reset AT+MSRTF")
                ok = await send_and_confirm("AT+MSRTF=0", timeout=8.0)
                if ok:
                    info("Telnet: reset acknowledged")
                else:
                    # Try alternative reset commands
                    warning("AT+MSRTF failed, trying alternatives")
                    for cmd in ["AT+MSRT", "AT&F"]:
                        info(f"Telnet: attempting {cmd}")
                        ok = await send_and_wait_ok(cmd)
                        if ok:
                            info(f"Telnet: reset acknowledged using {cmd}")
                            break
                    else:
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
    
    def change_password(self, new_password: str) -> bool:
        """Change the device password using the Microhard AT CLI over SSH.

        Replaces prior shell/uci attempts. Sends MSPWD followed by a single
        save with AT&W.
        """
        info("Changing device password via AT CLI")
        logger.debug(f"Changing password to length {len(new_password)} (value masked)")

        # Per manual: AT+MSPWD=<new>,<confirm>
        cmds = [
            f"AT+MSPWD={new_password},{new_password}",
            "AT&W",
        ]
        ok, out = self._ssh_execute_at_session(cmds)
        if ok:
            success("Password changed and saved")
            self.password = new_password
            # Give device a moment to flush NVRAM
            time.sleep(2)
            return True
        # Fallback to Telnet AT if available
        try:
            connection = self.discover()
        except Exception:
            connection = MicrohardConnection(self.ip, False, False, False)
        if getattr(connection, 'telnet_available', False):
            warning("SSH failed; attempting password change via Telnet AT")
            ok2, out2 = self._telnet_execute_at_session(cmds)
            if ok2:
                success("Password changed and saved via Telnet AT")
                self.password = new_password
                time.sleep(2)
                return True

        error("Password change failed via AT CLI")
        # Prefer Telnet error output if available
        tail = ""
        if 'out2' in locals() and out2:
            tail = out2[-200:]
        elif out:
            tail = out[-200:]
        if tail:
            logger.debug(f"AT password change output: {tail}")
        return False
    
    def provision(self, config: RadioConfig) -> bool:
        try:
            connection = self.discover()
            info(f"Provisioning {config.role.value} radio: {config.hostname}")
            
            # If we're using factory default password, change it to target password
            if self.password == Config.DEFAULT_MICROHARD_PASS and Config.TARGET_MICROHARD_PASS != Config.DEFAULT_MICROHARD_PASS:
                info("Detected factory default password, changing to deployment password")
                old_password = self.password
                if self.change_password(Config.TARGET_MICROHARD_PASS):
                    success("Password updated to deployment standard")
                    # Smoke test: verify new password works for SSH; retry with increasing delay
                    for attempt in range(3):
                        if attempt > 0:
                            time.sleep(2.0 * attempt)  # Increasing delay: 0s, 2s, 4s
                        ok, _ = self._ssh_execute("echo ok")
                        if ok:
                            break
                    else:
                        error("Re-login with new password failed; aborting to avoid lockout")
                        # Restore old password in driver state so operator can retry
                        self.password = old_password
                        return False
                else:
                    warning("Could not change password, continuing with factory default")
            
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
