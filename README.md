# elijahctl - Elijah Automated Provisioning System

Comprehensive CLI tool for automated provisioning, configuration, and validation of Elijah drone systems including air units, ground stations, and companion computers.

For detailed setup procedures, refer to the [Production Setup Guide](setup.md).

## Core Capabilities

- **Radio Configuration**: Automated Microhard radio provisioning for air and ground units
- **Companion Computer Deployment**: Ansible-based Jetson configuration and service deployment
- **Flight Controller Management**: MAVLink parameter configuration and system ID assignment
- **Network Infrastructure**: UniFi access point configuration and optimization
- **System Validation**: Comprehensive health monitoring and verification
- **Documentation Management**: Production checklist tracking with audit trail

## System Requirements

### Prerequisites

- Python 3.11 or higher
- Ansible (required for Jetson provisioning)
- Network connectivity to target devices
- Linux or macOS workstation (Windows supported only for ESC configuration)

### Installation Methods

#### Source Installation (recommended with venv)

```bash
# Clone repository
git clone https://github.com/elijah/elijahctl.git
cd elijahctl

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

# Install the package (editable for development, or drop -e for production)
pip install -e .

# For development tooling (tests, linting, etc.)
pip install -e ".[dev]"
```

Notes:
- Activate the environment in each new terminal before running commands: `source .venv/bin/activate`.
- If you prefer not to activate, you can call the CLI directly: `./.venv/bin/elijahctl ...`.

#### Optional: pipx Installation

```bash
pipx install elijahctl
```

## Quick Reference

Before running commands, activate your venv:

```bash
source /Users/parkerbeard/elijah-bringup/.venv/bin/activate
```

### 1. Service Discovery

```bash
elijahctl discover --ip 192.168.168.1
# or without activating the venv
/Users/parkerbeard/elijah-bringup/.venv/bin/elijahctl discover --ip 192.168.168.1
```

### 2. Air Unit Provisioning

```bash
elijahctl provision \
  --role air \
  --drone-id 012 \
  --sysid 12 \
  --aes-key $AES_KEY \
  --microhard-pass $MICROHARD_PASS \
  --tailscale-key $TAILSCALE_KEY
```

### 3. Flight Controller Configuration

```bash
elijahctl set-sysid --host el-012 --sysid 12
```

### 4. System Health Verification

```bash
elijahctl health --jetson el-012 --radio-ip auto --video udp:5600
```

### 5. Ground Station Setup

```bash
# Ground Radio Configuration
elijahctl provision \
  --role ground \
  --drone-id 001 \
  --aes-key $AES_KEY \
  --microhard-pass $MICROHARD_PASS

# UniFi AP Configuration
elijahctl unifi \
  --controller https://unifi.local \
  --user admin \
  --pass $UNIFI_PASS \
  --name rainmakerGCSX \
  --ip 10.101.252.1/16 \
  --disable-24ghz \
  --disable-autolink
```

### 6. Production Documentation

```bash
elijahctl checklist \
  --update checklist_data.json \
  --drone-id 012 \
  --phase hitl
```

## Command Reference

| Command | Purpose | Usage Context |
|---------|---------|---------------|
| `discover` | Detect services on Microhard radio | Initial connection verification |
| `provision` | Configure air/ground radio parameters | Radio setup phase |
| `reset-radio` | Factory reset via AT commands | Recovery operations only |
| `flash-fc` | Stage firmware for flight controller | Pre-flight preparation |
| `health` | Execute comprehensive system validation | Post-configuration verification |
| `unifi` | Configure UniFi access point | Ground station setup |
| `checklist` | Document configuration state | Production tracking |
| `set-sysid` | Configure MAV_SYS_ID parameter | Flight controller setup |

## Required Environment Configuration

```bash
export AES_KEY="your-128-bit-aes-key"
export MICROHARD_PASS="supercool"
export TAILSCALE_KEY="tskey-auth-..."
```

## Data Storage Structure

Application data stored in `~/.elijahctl/`:

```
~/.elijahctl/
├── state/
│   └── runs/             # Timestamped execution records
├── inventory/
│   └── checklist.csv     # Production checklist ledger
├── logs/                 # Application logs
└── secrets.json          # Encrypted credentials (chmod 600)
```

## Development

### Environment Setup

```bash
# Install development dependencies
make dev

# Execute test suite
make test

# Code formatting
make format

# Static analysis
make lint

# Type checking
make type-check

# Complete validation
make all
```

### Architecture

```
elijahctl/
├── drivers/          # Hardware interface modules
│   ├── microhard.py  # Radio control
│   ├── jetson.py     # Companion computer
│   ├── mavlink.py    # Flight controller
│   └── unifi.py      # Network infrastructure
├── health/           # Validation modules
├── utils/            # Common utilities
├── tests/            # Test suite
├── config.py         # Configuration models
├── checklist.py      # Documentation management
└── cli.py            # Command interface
```

## Critical Safety Requirements

- **Radio Reset**: Never use pinhole reset on Microhard radios. Use `reset-radio` command exclusively.
- **Configuration Staging**: All changes are staged before applying (enforced by tooling).
- **Power Management**: Always power cycle radio and switch simultaneously for proper DHCP operation.
- **Hardware Protection**: Inner MMCX→SMA lead must remain permanently attached to radio.

## Manual Operations

Certain operations require manual intervention by design:

1. **Antenna Installation**: Proper torque specification, RHCP/LHCP alternation
2. **ESC Configuration**: KDEDirect on Windows with v2_standard.cfg parameter file
3. **UniFi Adoption**: Initial trust establishment with controller
4. **RemoteID Setup**: Module configuration and regulatory database registration

## Troubleshooting
### Command not found / wrong interpreter
1. Ensure the venv is activated: `source .venv/bin/activate`
2. Or call the tool via absolute path: `./.venv/bin/elijahctl ...`
3. Verify installation completed without errors: `pip install -e .`

### Device offline
- If the Microhard radio is powered off or disconnected, `discover` will report all services as False. This is expected and confirms the CLI is working.


### Radio Communication Issues
1. Power cycle radio and switch simultaneously
2. Verify physical connections
3. Execute `discover` command to confirm service availability

### DHCP Address Migration
1. Confirm radio MAC address is cached before reboot
2. Check router DHCP lease table
3. Allow up to 2 minutes for IP assignment

### MAVLink Connection Failures
1. Verify Jetson network connectivity
2. Check service status: `systemctl status mavlink-router`
3. Confirm flight controller power and connections

### UniFi Configuration Drift
1. Apply required settings through UniFi controller UI
2. Re-run `elijahctl unifi` for validation
3. Document any persistent discrepancies

## License

MIT License - See LICENSE file for complete terms

## Support

Report issues and feature requests via GitHub Issues.