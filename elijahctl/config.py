from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path
import json
import os
from datetime import datetime
from enum import Enum

class RadioRole(Enum):
    AIR = "air"
    GROUND = "ground"

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class RadioConfig:
    role: RadioRole
    drone_id: str
    hostname: str
    description: str
    frequency: int = 2427
    bandwidth: int = 5
    net_id: str = "rainmaker"
    mode: str = ""
    tx_power: int = 30
    encryption: str = "AES-128"
    aes_key: str = ""
    dhcp_client: bool = True
    radio_stats_enabled: bool = True
    radio_stats_port: int = 22222
    radio_stats_interval: int = 1000
    
    def __post_init__(self):
        if self.role == RadioRole.AIR:
            self.mode = "Slave"
            self.hostname = f"elijah-{self.drone_id}-air"
            self.description = f"Elijah {self.drone_id} Air Radio"
        else:
            self.mode = "Master"
            self.hostname = f"rainmaker-ground-{self.drone_id}"
            self.description = f"Rainmaker Ground Radio {self.drone_id}"

@dataclass
class JetsonConfig:
    drone_id: str
    device_name: str = ""
    sysid: int
    ansible_host: str = "192.168.55.1"
    ansible_user: str = "jetson"
    tailscale_auth_key: str = ""
    microhard_password: str = ""
    
    def __post_init__(self):
        if not self.device_name:
            self.device_name = f"el-{self.drone_id}"

@dataclass
class UniFiConfig:
    controller_url: str
    username: str
    password: str
    site: str = "default"
    device_name: str = "rainmakerGCSX"
    static_ip: str = "10.101.252.1"
    netmask: str = "16"
    disable_24ghz: bool = True
    disable_autolink: bool = True
    verify_tls: bool = False

@dataclass
class HitlChecklist:
    serial_qr: str
    air_radio_fw_kept_factory: bool
    air_radio_configured: bool
    remoteid_configured: bool
    remoteid_serial_20d: str
    remoteid_faa_entered: bool
    jetson_git_hash: str
    px4_fw_ref: str
    param_set_version: str
    sysid_set: int
    seraph_hitl_ok: bool
    esc_fw_ref: str
    esc_params_ref: str
    motor_map_ok: bool
    ads_power_ok: bool
    arm_no_props_ok: bool
    arm_safety_param_ok: bool
    elrs_configured: Optional[bool]
    hitl_signed_by: str
    hitl_date: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "serial_qr": self.serial_qr,
            "air_radio_fw_kept_factory": self.air_radio_fw_kept_factory,
            "air_radio_configured": self.air_radio_configured,
            "remoteid_configured": self.remoteid_configured,
            "remoteid_serial_20d": self.remoteid_serial_20d,
            "remoteid_faa_entered": self.remoteid_faa_entered,
            "jetson_git_hash": self.jetson_git_hash,
            "px4_fw_ref": self.px4_fw_ref,
            "param_set_version": self.param_set_version,
            "sysid_set": self.sysid_set,
            "seraph_hitl_ok": self.seraph_hitl_ok,
            "esc_fw_ref": self.esc_fw_ref,
            "esc_params_ref": self.esc_params_ref,
            "motor_map_ok": self.motor_map_ok,
            "ads_power_ok": self.ads_power_ok,
            "arm_no_props_ok": self.arm_no_props_ok,
            "arm_safety_param_ok": self.arm_safety_param_ok,
            "elrs_configured": self.elrs_configured,
            "hitl_signed_by": self.hitl_signed_by,
            "hitl_date": self.hitl_date
        }

@dataclass
class InsituChecklist:
    installed_in_vehicle: bool
    seraph_insitu_ok: bool
    insitu_signed_by: str
    insitu_date: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "installed_in_vehicle": self.installed_in_vehicle,
            "seraph_insitu_ok": self.seraph_insitu_ok,
            "insitu_signed_by": self.insitu_signed_by,
            "insitu_date": self.insitu_date
        }

@dataclass
class HealthCheckResult:
    component: str
    status: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status,
            "message": self.message,
            "data": self.data,
            "timestamp": self.timestamp
        }

class Config:
    BASE_DIR = Path.home() / ".elijahctl"
    STATE_DIR = BASE_DIR / "state"
    RUNS_DIR = STATE_DIR / "runs"
    INVENTORY_DIR = BASE_DIR / "inventory"
    LOGS_DIR = BASE_DIR / "logs"
    
    DEFAULT_MICROHARD_IP = "192.168.168.1"
    DEFAULT_MICROHARD_USER = "admin"
    DEFAULT_MICROHARD_PASS = "admin"
    
    SSH_TIMEOUT = 10
    HTTP_TIMEOUT = 10
    TELNET_TIMEOUT = 5
    MAVLINK_TIMEOUT = 10
    HEALTH_CHECK_TIMEOUT = 5
    
    @classmethod
    def init_directories(cls):
        for dir_path in [cls.BASE_DIR, cls.STATE_DIR, cls.RUNS_DIR, 
                         cls.INVENTORY_DIR, cls.LOGS_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def load_secrets(cls) -> Dict[str, str]:
        secrets_file = cls.BASE_DIR / "secrets.json"
        if secrets_file.exists():
            with open(secrets_file, 'r') as f:
                return json.load(f)
        return {}
    
    @classmethod
    def save_secrets(cls, secrets: Dict[str, str]):
        secrets_file = cls.BASE_DIR / "secrets.json"
        with open(secrets_file, 'w') as f:
            json.dump(secrets, f, indent=2)
        os.chmod(secrets_file, 0o600)
