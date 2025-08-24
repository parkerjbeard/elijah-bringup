import time
import logging
from typing import Optional, Dict, Any, Tuple
from pymavlink import mavutil

from ..config import Config
from ..utils.logging import get_logger, info, success, error, warning

logger = get_logger(__name__)

class MAVLinkDriver:
    def __init__(self, host: str, port: int = 14550):
        self.host = host
        self.port = port
        self.connection = None
        self.target_system = None
        self.target_component = None
        
    def connect(self, timeout: int = Config.MAVLINK_TIMEOUT) -> bool:
        info(f"Connecting to MAVLink at {self.host}:{self.port}")

        attempts = [
            f"udp:0.0.0.0:{self.port}",
            f"udpin:0.0.0.0:{self.port}",
            f"udpout:{self.host}:{self.port}",
        ]

        for conn_str in attempts:
            try:
                # Close any prior connection to avoid socket leaks
                self.close()
                logger.debug(f"Trying MAVLink connection: {conn_str}")
                self.connection = mavutil.mavlink_connection(conn_str)
                logger.debug(f"Waiting for heartbeat (timeout={timeout}s)")
                heartbeat = self.connection.wait_heartbeat(timeout=timeout)
                if heartbeat:
                    self.target_system = self.connection.target_system
                    self.target_component = self.connection.target_component
                    success(
                        f"Connected ({conn_str}) → system {self.target_system}, component {self.target_component}"
                    )
                    autopilot_name = self._get_autopilot_name(heartbeat.autopilot)
                    info(f"Autopilot: {autopilot_name}, Type: {heartbeat.type}")
                    return True
            except Exception as e:
                warning(f"MAVLink connection failed for {conn_str}: {e}")

        error("No heartbeat received on any transport")
        return False
    
    def _get_autopilot_name(self, autopilot_id: int) -> str:
        autopilot_names = {
            0: "Generic",
            1: "Reserved",
            2: "Slugs",
            3: "ArduPilot",
            4: "OpenPilot",
            5: "Generic WP Only",
            6: "Generic WP and Simple Nav",
            7: "Generic Mission Full",
            8: "Invalid",
            9: "PPZ",
            10: "UDB",
            11: "FlexiPilot",
            12: "PX4",
            13: "SMACCMPilot",
            14: "AutoQuad",
            15: "Armazila",
            16: "Aerob",
            17: "ASLUAV",
            18: "SmartAP",
            19: "AirRails"
        }
        return autopilot_names.get(autopilot_id, f"Unknown ({autopilot_id})")
    
    def set_parameter(self, param_name: str, value: float, 
                     param_type: int = mavutil.mavlink.MAV_PARAM_TYPE_INT32) -> bool:
        if not self.connection:
            error("No MAVLink connection established")
            return False
        
        info(f"Setting parameter {param_name} = {value}")
        
        try:
            param_id_bytes = param_name.encode('utf-8')
            if len(param_id_bytes) < 16:
                param_id_bytes += b'\x00' * (16 - len(param_id_bytes))
            
            self.connection.mav.param_set_send(
                self.target_system,
                self.target_component,
                param_id_bytes,
                float(value),
                param_type
            )
            
            start_time = time.time()
            while time.time() - start_time < 5:
                msg = self.connection.recv_match(type='PARAM_VALUE', blocking=True, timeout=1)
                if msg and msg.param_id.strip('\x00') == param_name:
                    if abs(msg.param_value - value) < 0.001:
                        success(f"Parameter {param_name} set to {value}")
                        return True
                    else:
                        warning(f"Parameter value mismatch: expected {value}, got {msg.param_value}")
            
            warning(f"No confirmation received for parameter {param_name}")
            return False
            
        except Exception as e:
            error(f"Failed to set parameter: {e}")
            return False
    
    def get_parameter(self, param_name: str) -> Optional[float]:
        if not self.connection:
            error("No MAVLink connection established")
            return None
        
        try:
            param_id_bytes = param_name.encode('utf-8')
            if len(param_id_bytes) < 16:
                param_id_bytes += b'\x00' * (16 - len(param_id_bytes))
            
            self.connection.mav.param_request_read_send(
                self.target_system,
                self.target_component,
                param_id_bytes,
                -1
            )
            
            msg = self.connection.recv_match(type='PARAM_VALUE', blocking=True, timeout=5)
            if msg and msg.param_id.strip('\x00') == param_name:
                return msg.param_value
            
            return None
            
        except Exception as e:
            error(f"Failed to get parameter: {e}")
            return None
    
    def reboot_flight_controller(self) -> bool:
        if not self.connection:
            error("No MAVLink connection established")
            return False
        
        info("Sending reboot command to flight controller")
        
        try:
            self.connection.mav.command_long_send(
                self.target_system,
                self.target_component,
                mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
                0,
                1, 0, 0, 0, 0, 0, 0
            )
            
            msg = self.connection.recv_match(type='COMMAND_ACK', blocking=True, timeout=3)
            if msg and msg.command == mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN:
                if msg.result == mavutil.mavlink.MAV_RESULT_ACCEPTED:
                    success("Reboot command accepted")
                    return True
                else:
                    warning(f"Reboot command result: {msg.result}")
            
            return True
            
        except Exception as e:
            error(f"Failed to send reboot command: {e}")
            return False
    
    def wait_for_heartbeat_after_reboot(self, timeout: int = 30) -> bool:
        info("Waiting for flight controller to reboot...")
        time.sleep(5)
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Close before retrying to avoid accumulating sockets
                self.close()
                if self.connect(timeout=5):
                    success("Flight controller rebooted successfully")
                    return True
            except:
                pass
            time.sleep(1)
        
        error("Timeout waiting for flight controller to reboot")
        return False
    
    def set_sysid(self, sysid: int) -> bool:
        info(f"Setting MAV_SYS_ID to {sysid}")
        
        if not self.connection:
            if not self.connect():
                return False
        
        if not self.set_parameter("MAV_SYS_ID", float(sysid), 
                                 mavutil.mavlink.MAV_PARAM_TYPE_INT32):
            error("Failed to set MAV_SYS_ID parameter")
            return False
        
        if not self.reboot_flight_controller():
            warning("Reboot command may have failed")
        
        if not self.wait_for_heartbeat_after_reboot():
            error("Flight controller did not come back online after reboot")
            return False
        
        new_value = self.get_parameter("MAV_SYS_ID")
        if new_value and int(new_value) == sysid:
            success(f"MAV_SYS_ID verified as {sysid}")
            return True
        else:
            error(f"MAV_SYS_ID verification failed: expected {sysid}, got {new_value}")
            return False
    
    def get_heartbeat_info(self) -> Optional[Dict[str, Any]]:
        if not self.connection:
            return None
        
        try:
            msg = self.connection.recv_match(type='HEARTBEAT', blocking=True, timeout=5)
            if msg:
                return {
                    "system_id": msg.get_srcSystem(),
                    "component_id": msg.get_srcComponent(),
                    "type": msg.type,
                    "autopilot": self._get_autopilot_name(msg.autopilot),
                    "base_mode": msg.base_mode,
                    "custom_mode": msg.custom_mode,
                    "system_status": msg.system_status,
                    "mavlink_version": msg.mavlink_version
                }
        except:
            pass
        
        return None
    
    def monitor_heartbeats(self, duration: int = 5) -> Tuple[bool, int]:
        if not self.connection:
            error("No MAVLink connection established")
            return False, 0
        
        info(f"Monitoring heartbeats for {duration} seconds")
        
        start_time = time.time()
        heartbeat_count = 0
        
        while time.time() - start_time < duration:
            msg = self.connection.recv_match(type='HEARTBEAT', blocking=True, timeout=1)
            if msg:
                heartbeat_count += 1
        
        rate = heartbeat_count / duration
        success(f"Received {heartbeat_count} heartbeats ({rate:.1f} Hz)")
        
        return rate >= 0.5, heartbeat_count
    
    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None
