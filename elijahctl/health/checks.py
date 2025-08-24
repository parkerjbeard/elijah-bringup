import socket
import json
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from datetime import datetime
import paramiko
import os

from ..config import Config, HealthCheckResult
from ..drivers.mavlink import MAVLinkDriver
from ..utils.network import ping_host
from ..utils.logging import get_logger, info, success, error, warning, create_progress

logger = get_logger(__name__)

class HealthCheck:
    def __init__(self, jetson_host: str, radio_ip: Optional[str] = None, video: str = "udp:5600"):
        self.jetson_host = jetson_host
        self.radio_ip = radio_ip
        self.video_spec = video
        self.results = []
        
    def _add_result(self, component: str, status: bool, message: str, 
                   data: Optional[Dict] = None) -> HealthCheckResult:
        result = HealthCheckResult(
            component=component,
            status=status,
            message=message,
            data=data
        )
        self.results.append(result)
        
        if status:
            success(f"{component}: {message}")
        else:
            error(f"{component}: {message}")
        
        return result
    
    def check_connectivity(self) -> Dict[str, HealthCheckResult]:
        info("Checking network connectivity")
        results = {}
        
        jetson_ok, jetson_rtt = ping_host(self.jetson_host)
        if jetson_ok:
            results["jetson"] = self._add_result(
                "Jetson Connectivity",
                True,
                f"Reachable (RTT: {jetson_rtt:.1f}ms)" if jetson_rtt else "Reachable",
                {"rtt": jetson_rtt}
            )
        else:
            results["jetson"] = self._add_result(
                "Jetson Connectivity",
                False,
                "Not reachable"
            )
        
        if self.radio_ip:
            radio_ok, radio_rtt = ping_host(self.radio_ip)
            if radio_ok:
                results["radio"] = self._add_result(
                    "Radio Connectivity",
                    True,
                    f"Reachable (RTT: {radio_rtt:.1f}ms)" if radio_rtt else "Reachable",
                    {"rtt": radio_rtt}
                )
            else:
                results["radio"] = self._add_result(
                    "Radio Connectivity",
                    False,
                    "Not reachable"
                )
        
        return results
    
    def check_tailscale(self) -> HealthCheckResult:
        info("Checking Tailscale status")
        
        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.jetson_host,
                username="jetson",
                password="jetson",
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            stdin, stdout, stderr = client.exec_command("tailscale status --json")
            output = stdout.read().decode('utf-8')
            
            if output:
                status = json.loads(output)
                self_info = status.get("Self", {})
                
                if self_info.get("Online"):
                    dns_name = self_info.get("DNSName", "")
                    return self._add_result(
                        "Tailscale",
                        True,
                        f"Online ({dns_name})",
                        {"dns_name": dns_name, "online": True}
                    )
                else:
                    return self._add_result(
                        "Tailscale",
                        False,
                        "Not online"
                    )
            
        except Exception as e:
            logger.error(f"Tailscale check failed: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass
        
        return self._add_result(
            "Tailscale",
            False,
            "Check failed"
        )
    
    def check_radio_stats(self, timeout: int = 5) -> HealthCheckResult:
        info("Checking radio stats stream")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 22222))
            sock.settimeout(timeout)
            
            start_time = time.time()
            packet_count = 0
            last_packet = None
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    packet_data = data.decode('utf-8', errors='ignore').lower()
                    packet_count += 1
                    last_packet = packet_data
                    
                    if "rssi" in packet_data and "snr" in packet_data:
                        rssi_match = packet_data.find("rssi")
                        snr_match = packet_data.find("snr")
                        
                        if rssi_match >= 0 and snr_match >= 0:
                            sock.close()
                            return self._add_result(
                                "Radio Stats",
                                True,
                                f"Receiving data ({packet_count} packets)",
                                {"packets": packet_count, "sample": packet_data[:100]}
                            )
                except socket.timeout:
                    break
            
            sock.close()
            
            if packet_count > 0:
                return self._add_result(
                    "Radio Stats",
                    False,
                    f"Received {packet_count} packets but missing required fields",
                    {"packets": packet_count}
                )
            
        except Exception as e:
            logger.error(f"Radio stats check failed: {e}")
        
        return self._add_result(
            "Radio Stats",
            False,
            "No data received"
        )
    
    def check_mavlink(self) -> HealthCheckResult:
        info("Checking MAVLink connection")
        
        try:
            mavlink = MAVLinkDriver(self.jetson_host, 14550)
            
            if mavlink.connect(timeout=10):
                heartbeat_ok, count = mavlink.monitor_heartbeats(duration=5)
                mavlink.close()
                
                if heartbeat_ok:
                    return self._add_result(
                        "MAVLink",
                        True,
                        f"Heartbeats received ({count} in 5s)",
                        {"heartbeat_count": count}
                    )
                else:
                    return self._add_result(
                        "MAVLink",
                        False,
                        f"Heartbeat rate too low ({count} in 5s)"
                    )
            
        except Exception as e:
            logger.error(f"MAVLink check failed: {e}")
        
        return self._add_result(
            "MAVLink",
            False,
            "Connection failed"
        )
    
    def check_video_stream(self) -> HealthCheckResult:
        info("Checking video stream")
        spec = (self.video_spec or "").strip()
        try:
            # UDP sniff mode: udp:PORT
            if spec.startswith("udp:"):
                try:
                    port = int(spec.split(":", 1)[1])
                except Exception:
                    port = 5600
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(("0.0.0.0", port))
                    sock.settimeout(5)
                    data, addr = sock.recvfrom(4096)
                    if data:
                        return self._add_result(
                            "Video Stream",
                            True,
                            f"UDP {port}: received {len(data)} bytes",
                            {"transport": "udp", "port": port, "bytes_received": len(data)}
                        )
                except socket.timeout:
                    return self._add_result(
                        "Video Stream",
                        False,
                        f"UDP {port}: no packets received"
                    )
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
            # RTSP mode: rtsp://host[:port]/...
            elif spec.startswith("rtsp://"):
                url = urlparse(spec)
                host = url.hostname or self.jetson_host
                port = url.port or 554
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                rc = s.connect_ex((host, port))
                if rc == 0:
                    try:
                        req = f"OPTIONS {spec} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
                        s.sendall(req)
                        s.settimeout(3)
                        data = s.recv(1024)
                        s.close()
                        text = data.decode(errors="ignore") if data else ""
                        if "RTSP/1.0" in text or "Public:" in text or "OPTIONS" in text:
                            return self._add_result(
                                "Video Stream",
                                True,
                                f"RTSP {host}:{port}: responsive",
                                {"transport": "rtsp", "host": host, "port": port}
                            )
                        else:
                            return self._add_result(
                                "Video Stream",
                                False,
                                f"RTSP {host}:{port}: unexpected response",
                            )
                    except Exception:
                        s.close()
                        return self._add_result(
                            "Video Stream",
                            False,
                            f"RTSP {host}:{port}: no RTSP response",
                        )
                else:
                    return self._add_result(
                        "Video Stream",
                        False,
                        f"RTSP {host}:{port}: not reachable"
                    )
            # TCP probe: tcp:PORT or numeric
            else:
                port_str = spec.replace("tcp:", "") if spec.startswith("tcp:") else spec
                try:
                    port = int(port_str) if port_str else 5600
                except Exception:
                    port = 5600
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                rc = s.connect_ex((self.jetson_host, port))
                if rc == 0:
                    s.settimeout(2)
                    try:
                        data = s.recv(1024)
                        s.close()
                        if data:
                            return self._add_result(
                                "Video Stream",
                                True,
                                f"TCP {port}: received {len(data)} bytes",
                                {"transport": "tcp", "port": port, "bytes_received": len(data)}
                            )
                    except Exception:
                        pass
                    s.close()
                    return self._add_result(
                        "Video Stream",
                        True,
                        f"TCP {port}: port open",
                        {"transport": "tcp", "port": port}
                    )
        except Exception as e:
            logger.error(f"Video stream check failed: {e}")

        return self._add_result(
            "Video Stream",
            False,
            f"No stream ({spec or 'unspecified'})"
        )
    
    def check_pth_sensors(self) -> HealthCheckResult:
        info("Checking PTH sensors")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.jetson_host,
                username="jetson",
                password="jetson",
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            pth_path = os.environ.get("ELIJAH_PTH_PATH", "/var/log/seraph/pth.json")
            stdin, stdout, stderr = client.exec_command(f"cat {pth_path} 2>/dev/null || echo '{}'")
            output = stdout.read().decode('utf-8')
            client.close()
            
            if output and output != '{}':
                try:
                    pth_data = json.loads(output)
                    if "pressure" in pth_data and "temperature" in pth_data and "humidity" in pth_data:
                        return self._add_result(
                            "PTH Sensors",
                            True,
                            f"P:{pth_data['pressure']:.1f} T:{pth_data['temperature']:.1f} H:{pth_data['humidity']:.1f}",
                            pth_data
                        )
                except:
                    pass
            
        except Exception as e:
            logger.error(f"PTH sensor check failed: {e}")
        
        return self._add_result(
            "PTH Sensors",
            False,
            "Sensor data not available"
        )
    
    def check_versions(self) -> Dict[str, HealthCheckResult]:
        info("Checking software versions")
        results = {}
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.jetson_host,
                username="jetson",
                password="jetson",
                timeout=Config.SSH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            stdin, stdout, stderr = client.exec_command("cd /opt/seraph && git rev-parse HEAD 2>/dev/null || echo 'unknown'")
            seraph_version = stdout.read().decode('utf-8').strip()
            
            stdin, stdout, stderr = client.exec_command("cd /opt/elijah && git rev-parse HEAD 2>/dev/null || echo 'unknown'")
            elijah_version = stdout.read().decode('utf-8').strip()
            
            stdin, stdout, stderr = client.exec_command("cat /opt/firmware/version.txt 2>/dev/null || echo 'unknown'")
            fc_version = stdout.read().decode('utf-8').strip()
            
            client.close()
            
            results["seraph"] = self._add_result(
                "Seraph Version",
                seraph_version != "unknown",
                seraph_version[:8] if seraph_version != "unknown" else "Not found",
                {"version": seraph_version}
            )
            
            results["elijah"] = self._add_result(
                "Elijah Version",
                elijah_version != "unknown",
                elijah_version[:8] if elijah_version != "unknown" else "Not found",
                {"version": elijah_version}
            )
            
            results["fc"] = self._add_result(
                "FC Firmware",
                fc_version != "unknown",
                fc_version[:20] if fc_version != "unknown" else "Not found",
                {"version": fc_version}
            )
            
        except Exception as e:
            logger.error(f"Version check failed: {e}")
        
        return results
    
    def run_all_checks(self) -> List[HealthCheckResult]:
        info("Running comprehensive health checks")
        try:
            Config.init_directories()
        except Exception:
            pass
        self.results = []
        
        with create_progress() as progress:
            task = progress.add_task("Running health checks...", total=7)
            
            self.check_connectivity()
            progress.advance(task)
            
            self.check_tailscale()
            progress.advance(task)
            
            self.check_radio_stats(timeout=Config.HEALTH_CHECK_TIMEOUT)
            progress.advance(task)
            
            self.check_mavlink()
            progress.advance(task)
            
            self.check_video_stream()
            progress.advance(task)
            
            self.check_pth_sensors()
            progress.advance(task)
            
            self.check_versions()
            progress.advance(task)
        
        passed = sum(1 for r in self.results if r.status)
        total = len(self.results)
        
        info(f"\nHealth check summary: {passed}/{total} passed")
        
        return self.results
    
    def save_results(self, filepath: Optional[str] = None) -> str:
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = Config.RUNS_DIR / f"health_check_{timestamp}.json"
        
        results_dict = {
            "timestamp": datetime.now().isoformat(),
            "jetson_host": self.jetson_host,
            "radio_ip": self.radio_ip,
            "results": [r.to_dict() for r in self.results],
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.status),
                "failed": sum(1 for r in self.results if not r.status)
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        logger.debug(f"Results saved to {filepath}")
        return str(filepath)
