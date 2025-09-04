from dataclasses import dataclass
from typing import Dict, Tuple, Optional
from pathlib import Path
import json


@dataclass
class MHProfile:
    name: str
    # Maps semantic keys -> (uci_config, section_selector, option)
    uci_keys: Dict[str, Tuple[str, str, str]]


def load_profile_from_file(path: Path) -> Optional[MHProfile]:
    try:
        if path.exists():
            data = json.loads(path.read_text())
            return MHProfile(
                name=data["name"], uci_keys={k: tuple(v) for k, v in data["uci_keys"].items()}
            )
    except Exception:
        pass
    return None


def detect_profile(uci_show_text: str) -> Optional[MHProfile]:
    """
    Very lightweight detector that inspects `uci show` text and returns a mapping
    for known Microhard builds. Extend as new builds are encountered.

    Returns None if no known profile is detected.
    """
    text = (uci_show_text or "").lower()

    # First, allow operator-provided mapping (no code change deployments)
    from ..config import Config  # local import to avoid cycles

    custom = load_profile_from_file(Config.STATE_DIR / "mh_profile.json")
    if custom:
        return custom

    # Example Microhard layout (placeholder; adjust to actual builds when known)
    # We look for an mh_radio config presence.
    if "mh_radio." in text:
        return MHProfile(
            name="mh_radio_v1",
            uci_keys={
                # Semantic -> (config, section, option)
                "hostname": ("system", "@system[0]", "hostname"),
                "description": ("system", "@system[0]", "description"),
                "role": ("mh_radio", "@mh[0]", "mode"),  # Master/Slave
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

    # Fallback: not recognized
    return None
