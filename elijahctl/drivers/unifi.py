import requests
import json
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import urllib3
import ipaddress

from ..config import UniFiConfig, Config
from ..utils.logging import get_logger, info, success, error, warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


class UniFiDriver:
    def __init__(self, config: UniFiConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = bool(config.verify_tls)
        self.csrf_token = None
        self.site_name = config.site
        self.api_version = None
        self._unifi_os: Optional[bool] = None

    def _detect_api_version(self) -> Optional[str]:
        try:
            response = self.session.get(f"{self.config.controller_url}/status", timeout=5)
            if response.status_code == 200:
                data = response.json()
                version = data.get("meta", {}).get("server_version", "")

                if version.startswith("8"):
                    return "v8"
                elif version.startswith("7"):
                    return "v7"
                elif version.startswith("6"):
                    return "v6"

            response = self.session.get(
                f"{self.config.controller_url}/api/s/{self.site_name}/stat/sysinfo", timeout=5
            )
            if response.status_code == 200:
                return "v6"

        except:
            pass

        return "v7"

    def _is_unifi_os(self) -> bool:
        if self._unifi_os is not None:
            return self._unifi_os
        try:
            r = self.session.get(f"{self.config.controller_url}/status", timeout=5)
            self._unifi_os = (
                r.status_code == 200 and isinstance(r.json(), dict) and "meta" in r.json()
            )
        except Exception:
            self._unifi_os = False
        return self._unifi_os

    def _net_base(self) -> str:
        return (
            f"{self.config.controller_url}/proxy/network"
            if self._is_unifi_os()
            else self.config.controller_url
        )

    def login(self) -> bool:
        info(f"Logging into UniFi controller at {self.config.controller_url}")

        self.api_version = self._detect_api_version()
        logger.debug(f"Detected UniFi API version: {self.api_version}")

        login_data = {
            "username": self.config.username,
            "password": self.config.password,
            "remember": True,
        }

        try:
            # Use UniFi OS login path when available; fall back to legacy
            if self._is_unifi_os() or self.api_version in ("v7", "v8"):
                login_url = f"{self.config.controller_url}/api/auth/login"
            else:
                login_url = f"{self.config.controller_url}/api/login"

            response = self.session.post(login_url, json=login_data, timeout=Config.HTTP_TIMEOUT)

            if response.status_code == 200:
                if "x-csrf-token" in response.headers:
                    self.csrf_token = response.headers["x-csrf-token"]
                    self.session.headers.update({"x-csrf-token": self.csrf_token})

                success("Successfully logged into UniFi controller")
                return True
            else:
                error(f"Login failed with status {response.status_code}")
                return False

        except Exception as e:
            error(f"Failed to login to UniFi controller: {e}")
            return False

    def logout(self):
        try:
            if self.api_version == "v8":
                logout_url = f"{self.config.controller_url}/api/auth/logout"
            else:
                logout_url = f"{self.config.controller_url}/api/logout"

            self.session.post(logout_url, timeout=5)
        except:
            pass

    def get_devices(self) -> List[Dict[str, Any]]:
        try:
            url = f"{self._net_base()}/api/s/{self.site_name}/stat/device"
            response = self.session.get(url, timeout=Config.HTTP_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])

        except Exception as e:
            logger.error(f"Failed to get devices: {e}")

        return []

    def find_device_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        devices = self.get_devices()

        for device in devices:
            if device.get("name") == name or device.get("hostname") == name:
                return device

        return None

    def adopt_device(self, mac: str) -> bool:
        info(f"Adopting device {mac}")

        try:
            url = f"{self._net_base()}/api/s/{self.site_name}/cmd/devmgr"
            data = {"cmd": "adopt", "mac": mac.lower()}

            response = self.session.post(url, json=data, timeout=Config.HTTP_TIMEOUT)

            if response.status_code == 200:
                success(f"Device {mac} adoption initiated")
                return True
            else:
                error(f"Adoption failed with status {response.status_code}")
                return False

        except Exception as e:
            error(f"Failed to adopt device: {e}")
            return False

    def configure_device(self, device_id: str) -> bool:
        info(f"Configuring device {device_id}")

        try:
            url = f"{self._net_base()}/api/s/{self.site_name}/rest/device/{device_id}"

            # Compute a reasonable gateway from IP/mask if possible (avoid hard-coded)
            gateway_ip = "10.101.0.1"
            try:
                iface = ipaddress.ip_interface(f"{self.config.static_ip}/{self.config.netmask}")
                # pick first usable host as default gw (network + 1)
                network = iface.network
                hosts = list(network.hosts())
                if hosts:
                    gateway_ip = str(hosts[0])
            except Exception:
                pass

            # Accept CIDR length or dotted mask in config.netmask
            try:
                mask = str(
                    ipaddress.IPv4Network(f"0.0.0.0/{self.config.netmask}", strict=False).netmask
                )
            except Exception:
                mask = "255.255.255.0"

            net_obj = {
                "type": "static",
                "ip": self.config.static_ip,
                "netmask": mask,
                "gateway": gateway_ip,
                "dns1": "8.8.8.8",
                "dns2": "8.8.4.4",
            }
            # Include both keys to straddle controller version differences
            config_data = {
                "name": self.config.device_name,
                "config_network": net_obj,
                "config_networks": net_obj,
            }

            response = self.session.put(url, json=config_data, timeout=Config.HTTP_TIMEOUT)

            if response.status_code == 200:
                success(f"Device configuration updated")
                return True
            else:
                error(f"Configuration failed with status {response.status_code}")
                return False

        except Exception as e:
            error(f"Failed to configure device: {e}")
            return False

    def disable_24ghz(self) -> bool:
        info("Disabling 2.4 GHz on wireless networks")

        try:
            url = f"{self._net_base()}/api/s/{self.site_name}/rest/wlanconf"
            response = self.session.get(url, timeout=Config.HTTP_TIMEOUT)

            if response.status_code != 200:
                error("Failed to get wireless network configuration")
                return False

            wlans = response.json().get("data", [])

            for wlan in wlans:
                wlan_id = wlan.get("_id")
                wlan_name = wlan.get("name")
                if not wlan_id:
                    continue
                # Mutate only band keys in-place to avoid losing other fields
                updated = dict(wlan)
                # Controllers vary: some use 'wlan_bands' (list), others 'wlan_band' (string)
                if "wlan_bands" in updated:
                    updated["wlan_bands"] = ["5g"]
                if "wlan_band" in updated:
                    updated["wlan_band"] = "5g"
                update_url = f"{self._net_base()}/api/s/{self.site_name}/rest/wlanconf/{wlan_id}"
                update_response = self.session.put(
                    update_url, json=updated, timeout=Config.HTTP_TIMEOUT
                )
                if update_response.status_code == 200:
                    success(f"Disabled 2.4 GHz on network: {wlan_name}")
                else:
                    warning(f"Failed to update network: {wlan_name}")

            return True

        except Exception as e:
            error(f"Failed to disable 2.4 GHz: {e}")
            return False

    def disable_auto_optimize(self) -> bool:
        info("Disabling Auto-Optimize features")

        try:
            settings_url = f"{self._net_base()}/api/s/{self.site_name}/set/setting/auto_optimize"
            settings_data = {"enabled": False}

            response = self.session.post(
                settings_url, json=settings_data, timeout=Config.HTTP_TIMEOUT
            )

            if response.status_code == 200:
                success("Auto-Optimize disabled")
                return True
            else:
                warning(f"Failed to disable Auto-Optimize: {response.status_code}")
                return False

        except Exception as e:
            warning(f"Failed to disable Auto-Optimize: {e}")
            return False

    def provision(self) -> bool:
        try:
            if not self.login():
                return False

            devices = self.get_devices()
            target_device = None

            for device in devices:
                if device.get("type") == "uap" and not device.get("adopted"):
                    info(f"Found unadopted AP: {device.get('mac')}")
                    if not self.adopt_device(device.get("mac")):
                        warning("Failed to adopt device - manual adoption may be required")
                    else:
                        target_device = device
                        break

            if not target_device:
                target_device = self.find_device_by_name(self.config.device_name)

            if target_device:
                device_id = target_device.get("_id")
                if device_id:
                    if not self.configure_device(device_id):
                        warning("Failed to configure device settings")
            else:
                warning("No UniFi AP found to configure")
                warning("Please adopt the AP manually first, then re-run this command")

            if self.config.disable_24ghz:
                if not self.disable_24ghz():
                    warning("Failed to disable 2.4 GHz bands")

            if self.config.disable_autolink:
                if not self.disable_auto_optimize():
                    warning("Failed to disable Auto-Optimize")

            # Read-back guard: warn if 2.4GHz remains enabled
            try:
                url = f"{self._net_base()}/api/s/{self.site_name}/rest/wlanconf"
                r = self.session.get(url, timeout=Config.HTTP_TIMEOUT)
                if r.status_code == 200:
                    for wlan in r.json().get("data", []):
                        bands = wlan.get("wlan_bands") or (
                            [wlan.get("wlan_band")] if wlan.get("wlan_band") else []
                        )
                        if any(b in ("2g", "2.4g", "2g2") for b in bands):
                            warning(f"WLAN {wlan.get('name')} still includes 2.4GHz")
            except Exception:
                pass

            self.logout()

            success("UniFi configuration completed")
            return True

        except Exception as e:
            error(f"UniFi provisioning failed: {e}")
            self.logout()
            return False
