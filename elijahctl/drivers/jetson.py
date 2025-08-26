import subprocess
import json
import time
import logging
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
import os
import shutil
import paramiko

from ..config import JetsonConfig, Config
from ..utils.network import ping_host, wait_for_host
from ..utils.logging import get_logger, info, success, error, warning, create_progress

logger = get_logger(__name__)

class JetsonDriver:
    def __init__(self, config: JetsonConfig):
        self.config = config
        self.ssh_client = None
        self.tailscale_dns_name: Optional[str] = None
        # defaults for non-interactive runs
        self.ssh_pass = os.environ.get("JETSON_SSH_PASS", "jetson")
        self.become_pass = os.environ.get("JETSON_BECOME_PASS", self.ssh_pass)
        
    def _run_ansible_playbook(self) -> Tuple[bool, str]:
        info(f"Running Ansible playbook for {self.config.device_name}")
        
        cmd = [
            "ansible-playbook",
            "-i", "all,",
            os.environ.get("ELIJAH_PLAYBOOK", "deploy_companion.yml"),
            "-T", "60",
            "-e", f"ansible_host={self.config.ansible_host}",
            "-e", f"ansible_user={self.config.ansible_user}",
            "-e", f"device_name={self.config.device_name}",
            "-e", f"sysid={self.config.sysid}",
            "-e", f"tailscale_auth_key={self.config.tailscale_auth_key}",
            "-e", f"microhard_password={self.config.microhard_password}"
        ]

        # Use sshpass if available for non-interactive auth; otherwise fall back to interactive prompts
        if shutil.which("sshpass"):
            cmd = ["sshpass", "-p", self.ssh_pass] + cmd + ["--extra-vars", f"ansible_become_pass={self.become_pass}"]
        else:
            cmd += ["--ask-pass", "--ask-become-pass"]
        
        try:
            # Ensure Ansible uses our repo config (pipelining + mux)
            env = os.environ.copy()
            repo_root = Path(__file__).resolve().parents[2]
            cfg_path = repo_root / "ansible.cfg"
            if cfg_path.exists():
                env["ANSIBLE_CONFIG"] = str(cfg_path)
            env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")
            # Prefer multiplexing even when sshpass is present
            env.setdefault("ANSIBLE_SSH_ARGS", "-o ControlMaster=auto -o ControlPersist=60s -o ServerAliveInterval=15 -o ServerAliveCountMax=2")
            with create_progress() as progress:
                task = progress.add_task("Running Ansible playbook...", total=None)
                
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
                
                if "--ask-pass" in cmd:
                    stdout, stderr = process.communicate(
                        input=f"{self.ssh_pass}\n{self.become_pass}\n",
                        timeout=300
                    )
                else:
                    stdout, stderr = process.communicate(timeout=600)
                
                progress.remove_task(task)
            
            if process.returncode == 0:
                success("Ansible playbook completed successfully")
                return True, stdout
            else:
                error(f"Ansible playbook failed with return code {process.returncode}")
                if stderr:
                    logger.error(f"Ansible stderr: {stderr}")
                return False, stderr
                
        except subprocess.TimeoutExpired:
            error("Ansible playbook timed out")
            return False, "Timeout"
        except Exception as e:
            error(f"Failed to run Ansible playbook: {e}")
            return False, str(e)
    
    def _check_tailscale_status(self) -> Tuple[bool, Optional[Dict]]:
        info("Checking Tailscale status")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.config.ansible_host,
                username=self.config.ansible_user,
                password="jetson",
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            stdin, stdout, stderr = client.exec_command("tailscale status --json")
            output = stdout.read().decode('utf-8')
            
            client.close()
            
            if output:
                status = json.loads(output)
                
                if status.get("Self", {}).get("DNSName", "").startswith(self.config.device_name):
                    # Cache the exact DNSName for later reachability checks
                    self.tailscale_dns_name = status.get("Self", {}).get("DNSName")
                    success(f"Tailscale node {self.config.device_name} is online")
                    return True, status
                else:
                    warning(f"Tailscale node name mismatch")
                    return False, status
            
            return False, None
            
        except Exception as e:
            error(f"Failed to check Tailscale status: {e}")
            return False, None
    
    def _upload_firmware(self, firmware_path: Optional[Path] = None) -> bool:
        if not firmware_path:
            info("No firmware path provided, skipping upload")
            return True
        
        info(f"Uploading firmware to {self.config.device_name}")
        dest_dir = f"/home/{self.config.ansible_user}/firmware/"
        remote = f"{self.config.ansible_user}@{self.config.ansible_host}:{dest_dir}"

        # Ensure destination directory exists (one-time SSH with mux)
        ssh_base = [
            "ssh",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=60s",
            "-o", "StrictHostKeyChecking=no",
        ]
        try:
            subprocess.run(ssh_base + [f"{self.config.ansible_user}@{self.config.ansible_host}", "mkdir -p", dest_dir], check=False)
        except Exception:
            pass

        try:
            if shutil.which("rsync"):
                cmd = [
                    "rsync", "-azP",
                    "-e", " ".join(ssh_base),
                    str(firmware_path),
                    remote,
                ]
            else:
                cmd = [
                    "scp", "-C",
                    "-o", "ControlMaster=auto",
                    "-o", "ControlPersist=60s",
                    "-o", "StrictHostKeyChecking=no",
                    str(firmware_path),
                    remote,
                ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                success(f"Firmware uploaded: {dest_dir}{firmware_path.name}")
                return True
            else:
                logger.error(f"Upload failed: {r.stderr}")
                return False
        except Exception as e:
            error(f"Failed to upload firmware: {e}")
            return False
    
    def _verify_services(self) -> Dict[str, bool]:
        info("Verifying Jetson services")
        services = {}
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.config.ansible_host,
                username=self.config.ansible_user,
                password="jetson",
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            services_env = os.environ.get("ELIJAH_SERVICES")
            if services_env:
                names = [s.strip() for s in services_env.split(",") if s.strip()]
                checks = [(n, f"systemctl is-active {n}") for n in names]
            else:
                checks = [
                    ("mavlink-router", "systemctl is-active mavlink-router"),
                    ("radio-stats", "systemctl is-active radio-stats"),
                    ("seraph", "systemctl is-active seraph"),
                    ("elijah", "systemctl is-active elijah")
                ]
            
            for service_name, command in checks:
                stdin, stdout, stderr = client.exec_command(command)
                output = stdout.read().decode('utf-8').strip()
                services[service_name] = output == "active"
                
                if services[service_name]:
                    success(f"{service_name} service is active")
                else:
                    warning(f"{service_name} service is not active")
            
            client.close()
            
        except Exception as e:
            error(f"Failed to verify services: {e}")
        
        return services
    
    def provision(self, firmware_path: Optional[Path] = None) -> bool:
        try:
            info(f"Starting Jetson provisioning for {self.config.device_name}")
            
            reachable, _ = ping_host(self.config.ansible_host)
            if not reachable:
                error(f"Cannot reach Jetson at {self.config.ansible_host}")
                error("Please ensure Jetson is connected to router via USB")
                return False
            
            success_flag, output = self._run_ansible_playbook()
            if not success_flag:
                error("Ansible provisioning failed")
                return False
            
            time.sleep(5)
            
            ts_ok, ts_status = self._check_tailscale_status()
            if not ts_ok:
                warning("Tailscale verification failed - this is expected if radio is not connected")
            
            services = self._verify_services()
            if not services.get("mavlink-router"):
                warning("MAVLink router service not active")
            
            if firmware_path and firmware_path.exists():
                if not self._upload_firmware(firmware_path):
                    warning("Firmware upload failed - manual upload may be required")
            
            success(f"Jetson {self.config.device_name} provisioned successfully")
            info("Next steps:")
            info("1. Upload FC firmware via ARK UI if not already done")
            info("2. Move Jetson Ethernet from router to Microhard radio")
            
            return True
            
        except Exception as e:
            error(f"Jetson provisioning failed: {e}")
            return False
    
    def switch_to_microhard(self) -> bool:
        info("Verifying Jetson connection through Microhard radio")
        
        tailscale_name = self.tailscale_dns_name or f"{self.config.device_name}.tail-scale.ts.net"
        
        if wait_for_host(tailscale_name, port=22, timeout=30):
            success(f"Jetson reachable via Tailscale: {tailscale_name}")
            return True
        else:
            warning("Cannot reach Jetson via Tailscale")
            warning("Please ensure:")
            warning("1. Jetson Ethernet is connected to Microhard radio")
            warning("2. Microhard radio is configured and powered")
            warning("3. Tailscale is running on Jetson")
            return False
