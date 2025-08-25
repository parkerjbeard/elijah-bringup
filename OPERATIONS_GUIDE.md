# ElijahCTL Operations Guide

This guide provides comprehensive, granular technical documentation for the `elijahctl` project and a detailed, step‑by‑step workflow to automate the legacy bench processes for Air/Ground radio bring‑up, Jetson provisioning, UniFi AP configuration, and system health verification.

---

## Table of Contents

1. Overview and Goals
2. Architecture and Components
3. Installation and Requirements
4. Configuration and State
5. Drivers and Protocols
   - Microhard (OpenWrt/LuCI/ubus)
   - UniFi (UniFi OS, proxied Network app)
   - Jetson (Ansible, SSH, Systemd)
   - MAVLink (PX4 parameters)
6. Health Checks
7. Networking Utilities and Portability
8. CLI Commands and Examples
9. End‑to‑End Runbooks
   - Air Radio + Jetson (Bench)
   - Ground Station + UniFi AP
   - Health Verification and Acceptance
10. Microhard Profile Mapping Workflow
11. Troubleshooting
12. Reference (Env Vars, Ports, Defaults, File Layout)

---

## 1) Overview and Goals

`elijahctl` replaces manual click‑paths with a reproducible, scriptable CLI:

- Stage and apply Microhard RF/network/stat settings via SSH or HTTP (ubus)
- Provision Jetson (Ansible), verify services, and set MAVLink SYSID
- Configure UniFi APs for 5 GHz‑only on UniFi OS controllers
- Run consistent health checks for lab acceptance
- Track HITL/In‑situ checklists in a simple ledger

Outcomes: bench‑ready automation, fewer surprises, and an auditable process trail.

---

## 2) Architecture and Components

- CLI (`elijahctl/cli.py`): User entrypoint; commands mirror the operator runbook
- Drivers (`elijahctl/drivers/`):
  - `microhard.py`: OpenWrt/ubus, profile‑mapped UCI write, SSH/HTTP fallback
  - `unifi.py`: UniFi OS login + proxied Network app, per‑WLAN bands, device config
  - `jetson.py`: Ansible playbook wrapper, service verification, Tailscale check
  - `mavlink.py`: PX4 parameter set/verify over MAVLink
- Health (`elijahctl/health/checks.py`): Connectivity, Tailscale, radio‑stats, MAVLink, video, PTH, versions
- Utils (`elijahctl/utils/`): Logging, networking (cross‑platform), small helpers
- Config (`elijahctl/config.py`): Dataclasses and defaults for radios/APs/checklists
- Checklist (`elijahctl/checklist.py`): HITL/In‑situ JSON schemas + CSV ledger

Data flow snapshots:
- Microhard: Stage semantic RF/stats → map to UCI via profile → uci set/commit → reboot → DHCP flip detection
- UniFi: Login `/api/auth/login` → Network app via `/proxy/network/api/...` → device+WLAN updates → read‑back warnings
- Jetson: `ansible-playbook` (non‑interactive with `sshpass` if present) → Tailscale + services check

---

## 3) Installation and Requirements

- Python 3.11+
- macOS 13+/Linux (Ubuntu 20.04/22.04)
- Recommended tools: `ansible` and `sshpass`

Install from source:

```bash
pip install -e .
# or for development
pip install -e ".[dev]"
```

System packages (Linux):

```bash
sudo apt-get update
sudo apt-get install -y ansible sshpass
```

Confirm CLI:

```bash
elijahctl version
```

---

## 4) Configuration and State

- Base dir: `~/.elijahctl`
  - `state/` – working state (e.g., last radio MAC, microhard profile map)
  - `runs/` – health reports, JSON artifacts
  - `inventory/` – checklist CSV ledger
  - `logs/` – execution logs

Defaults (`elijahctl/config.py`):
- Microhard: IP `192.168.168.1`, user `admin`, pass `supercool`
- Jetson: host `192.168.55.1`, user `jetson`
- UniFi: site `default`, device `rainmakerGCSX`, static `10.101.252.1/16`

---

## 5) Drivers and Protocols

### 5.1 Microhard (OpenWrt/LuCI/ubus)

- Discovery: TCP probes on 22/23/80
- SSH path: `uci set/commit` batched per config; reboot
- HTTP path (fallback): ubus calls to `/cgi-bin/luci/rpc/auth` and `/ubus`
- Profile mapping: semantic RF/stats keys → actual UCI keys; multiple detection modes:
  - SSH `uci show` → `detect_profile()`
  - HTTP LuCI `uci.get_all('mh_radio')` presence → best‑effort mapping
  - External override: `~/.elijahctl/state/mh_profile.json` (preferred for bench)
- DHCP flip: ARP‑assisted discovery, limited pingless probes for portability

Staged semantics:
- RF: `role`, `freq_mhz`, `bw_mhz`, `net_id`, `aes_key`
- Network: DHCP client (when enabled)
- Stats: `enable`, `port`, `interval`, `fields` (UDP 22222, `rf,rssi,snr,associated_ip`)

### 5.2 UniFi (UniFi OS)

- Login: `POST /api/auth/login`
- Network App base: `/proxy/network`
- Site‑scoped APIs: `/api/s/<site>/...`
- Operations:
  - Adopt device: `cmd/devmgr`
  - Configure device IP: `rest/device/<id>` (static IP, mask, gateway, DNS)
  - Disable 2.4 GHz: set each WLAN’s `wlan_bands` to `["5g"]`
  - Disable auto‑optimize: best‑effort setting (version‑dependent)
  - Read‑back: warn if any WLAN still includes 2.4 GHz

### 5.3 Jetson (Ansible, SSH, Systemd)

- Ansible runner: `ansible-playbook`, non‑interactive if `sshpass` is available
- Env knobs: `JETSON_SSH_PASS`, `JETSON_BECOME_PASS`, `ELIJAH_PLAYBOOK`
- Tailscale check: SSH → `tailscale status --json`; caches `Self.DNSName`
- Services: default set or override via `ELIJAH_SERVICES`

### 5.4 MAVLink

- Uses `pymavlink` to set `MAV_SYS_ID`
- Connects to Jetson’s UDP endpoint (default 14550)

---

## 6) Health Checks

Components:
- Connectivity: reachability and TCP RTT (cross‑platform)
- Tailscale: node online, DNS name
- Radio Stats: UDP 22222 packets, validate fields
- MAVLink: heartbeat counts over interval
- Video: UDP sniff, RTSP responsiveness, or TCP probe
- PTH Sensors: JSON from `ELIJAH_PTH_PATH` (default `/var/log/seraph/pth.json`)
- Versions: git hashes from `/opt/seraph` and `/opt/elijah`, FW version file

Outputs:
- Printed pass/fail per component
- JSON summary written to `~/.elijahctl/runs/health_check_*.json`

---

## 7) Networking Utilities and Portability

- Reachability: TCP connect tests (22/80/443) instead of ICMP `ping -W` (macOS‑safe)
- Interface parsing:
  - Linux: `ip -o -f inet addr show`
  - macOS: `ifconfig` with hex netmask decoding
- ARP warming: UDP packet to port 9 to populate ARP, avoids ping flag differences

---

## 8) CLI Commands and Examples

All commands support `-v` for verbose logging and `--log-file <path>` for log capture.

- Discover radio services:
  - `elijahctl discover --ip 192.168.168.1`

- Detect Microhard profile (and prepare for mapping):
  - `elijahctl radio-profile --ip 192.168.168.1`

- Provision Air radio + Jetson:
  - `elijahctl provision --role air --drone-id 012 --sysid 12 --aes-key "$AES" --microhard-pass "$MH" --tailscale-key "$TS" --yes`

- Provision Ground radio:
  - `elijahctl provision --role ground --drone-id 001 --aes-key "$AES"`

- Safe reset (AT commands over Telnet):
  - `elijahctl reset-radio --ip 192.168.168.1 --force`

- Health checks (auto discover radio IP, set timeouts):
  - `ELIJAH_PTH_PATH=/opt/seraph/pth.json elijahctl health --jetson el-012 --radio-ip auto --timeout 10`

- UniFi AP configuration (UniFi OS, site aware):
  - `elijahctl unifi --controller https://unifi.local --user admin --pass "$UPASS" --site default --name rainmakerGCSX --ip 10.101.252.1/16 --disable-24ghz --disable-autolink`

- Set FC `MAV_SYS_ID`:
  - `elijahctl set-sysid --host el-012 --sysid 12`

- Checklist ledger update:
  - `elijahctl checklist --update hitl.json --drone-id 012 --phase hitl`

---

## 9) End‑to‑End Runbooks

### 9.1 Air Radio + Jetson (Bench)

1. Prepare host
   - Install Python deps; install `ansible` and `sshpass` if possible
   - Export optional envs: `JETSON_SSH_PASS`, `JETSON_BECOME_PASS`, `ELIJAH_PLAYBOOK`
2. Verify radio is reachable
   - `elijahctl discover --ip 192.168.168.1` (power‑cycle radio and switch if needed)
3. Confirm/Provide Microhard profile mapping
   - `elijahctl radio-profile --ip 192.168.168.1`
   - If unknown mapping, SSH and run `uci show`; create `~/.elijahctl/state/mh_profile.json` (see section 10)
4. Provision the air radio + Jetson
   - `elijahctl provision --role air --drone-id 012 --sysid 12 --aes-key "$AES" --microhard-pass "$MH" --tailscale-key "$TS" --yes`
   - Wait for reboot and DHCP (~12s), IP discovery occurs automatically
5. Health verify
   - `elijahctl health --jetson el-012 --radio-ip auto --timeout 10`
6. Optional: set SYSID (if not done in the flow)
   - `elijahctl set-sysid --host el-012 --sysid 12`

### 9.2 Ground Station + UniFi AP

1. Provision ground radio
   - `elijahctl provision --role ground --drone-id 001 --aes-key "$AES"`
2. Configure UniFi AP (UniFi OS)
   - `elijahctl unifi --controller https://unifi.local --user admin --pass "$UPASS" --site default --name rainmakerGCSX --ip 10.101.252.1/16 --disable-24ghz --disable-autolink`
   - Read‑back warns if 2.4 GHz remains enabled

### 9.3 Health and Acceptance

1. Health checks
   - `elijahctl health --jetson el-012 --radio-ip auto --timeout 10`
2. Record checklist
   - Prepare HITL JSON; run `elijahctl checklist --update hitl.json --drone-id 012 --phase hitl`
3. Archive run output
   - Artifacts stored under `~/.elijahctl/runs/` and appended to `inventory/checklist.csv`

---

## 10) Microhard Profile Mapping Workflow

Why: Without a profile map, RF/stats writes over HTTP will be no‑ops.

Steps:
1. Detect presence
   - `elijahctl radio-profile --ip 192.168.168.1` (checks for known mapping)
2. Pull UCI layout from a live radio
   - `ssh admin@192.168.168.1 'uci show'` → save output
3. Build a mapping file at `~/.elijahctl/state/mh_profile.json`

Example template:

```json
{
  "name": "mh_radio_v1",
  "uci_keys": {
    "role": ["mh_radio", "@mh[0]", "mode"],
    "freq_mhz": ["mh_radio", "@mh[0]", "freq_mhz"],
    "bw_mhz": ["mh_radio", "@mh[0]", "bw_mhz"],
    "net_id": ["mh_radio", "@mh[0]", "net_id"],
    "aes_key": ["mh_radio", "@mh[0]", "aes_key"],
    "dhcp_proto": ["network", "lan", "proto"],
    "stats_enable": ["mh_stats", "@stats[0]", "enable"],
    "stats_port": ["mh_stats", "@stats[0]", "port"],
    "stats_interval": ["mh_stats", "@stats[0]", "interval"],
    "stats_fields": ["mh_stats", "@stats[0]", "fields"]
  }
}
```

4. Re‑run provisioning; writes now map to your build’s keys
5. Validate via `uci show` on the unit and health radio‑stats

---

## 11) Troubleshooting

- No services found at `192.168.168.1`
  - Power‑cycle radio and bench switch together; verify cabling
- “Unknown Microhard UCI layout”
  - Provide `~/.elijahctl/state/mh_profile.json` per section 10
- HTTP only radios fail to apply
  - Confirm `http://<ip>/cgi-bin/luci/rpc/auth` is reachable; see logs for ubus `error`
- DHCP flip not discovered
  - Allow time (12–120s), ensure host is on same L2; ARP warming is UDP‑based
- UniFi login 401/404
  - Use controller root (e.g., `https://udm.local`), UniFi OS pathing, and `--site`
- 2.4 GHz persists after update
  - Version drift; read‑back warning indicates manual review needed
- Tailscale check fails
  - SSH into Jetson; `tailscale status --json`; ensure Online and DNSName
- Ansible provisioning hangs
  - Install `sshpass` or supply passwords interactively; check `ELIJAH_PLAYBOOK`
- Radio‑stats red in health
  - Confirm stats keys in your profile map and firewall rules; port 22222

---

## 12) Reference

### Environment Variables

- `JETSON_SSH_PASS`, `JETSON_BECOME_PASS`: Ansible SSH/sudo passwords (default `jetson`)
- `ELIJAH_PLAYBOOK`: Playbook path (default `deploy_companion.yml`)
- `ELIJAH_SERVICES`: Override Jetson service verification; CSV list of names
- `ELIJAH_PTH_PATH`: PTH sensor JSON path (default `/var/log/seraph/pth.json`)

### Defaults and Ports

- Microhard default IP: `192.168.168.1`
- Jetson SSH: `192.168.55.1`
- MAVLink UDP: 14550
- Radio Stats UDP: 22222
- Video: usually `udp:5600`, RTSP 554

### File Layout

- `~/.elijahctl/state/last_radio_mac.txt`: cached MAC from discovery
- `~/.elijahctl/state/mh_profile.json`: operator‑provided Microhard UCI map
- `~/.elijahctl/runs/*.json`: health run outputs
- `~/.elijahctl/inventory/checklist.csv`: checklist ledger
- `~/.elijahctl/logs/*`: logs

---

## Appendix: Command Cheat Sheet

- Discover: `elijahctl discover --ip 192.168.168.1`
- Profile: `elijahctl radio-profile --ip 192.168.168.1`
- Provision (Air): `elijahctl provision --role air --drone-id 012 --sysid 12 --aes-key "$AES" --microhard-pass "$MH" --tailscale-key "$TS" --yes`
- Provision (Ground): `elijahctl provision --role ground --drone-id 001 --aes-key "$AES"`
- Reset Radio: `elijahctl reset-radio --ip 192.168.168.1 --force`
- UniFi: `elijahctl unifi --controller https://unifi.local --user admin --pass "$UPASS" --site default --name rainmakerGCSX --ip 10.101.252.1/16 --disable-24ghz --disable-autolink`
- Health: `elijahctl health --jetson el-012 --radio-ip auto --timeout 10`
- Set SYSID: `elijahctl set-sysid --host el-012 --sysid 12`
- Checklist: `elijahctl checklist --update hitl.json --drone-id 012 --phase hitl`

---

This guide captures the operational details needed to take a unit from factory defaults to a verified bench run, with automation replacing legacy manual steps while preserving levers for real‑world variation (profiles, sites, service names, paths).

