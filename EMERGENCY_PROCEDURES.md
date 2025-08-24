# Emergency Procedures Guide

## Critical Contact Information

**Primary Support**: [Your Support Channel]  
**Escalation Path**: L1 → L2 → Engineering Team  
**Emergency Hotline**: [Emergency Contact Number]  
**On-Call Schedule**: [Link to Schedule]

---

## 1. Radio Communication Failure

### Symptoms
- No response from radio at known IP address
- Services unavailable (SSH/HTTP/Telnet)
- Radio stats not being received
- LEDs showing unexpected patterns

### Immediate Actions

#### Level 1: Basic Recovery (5 minutes)
1. Verify physical connections (power, Ethernet)
2. Power cycle radio and switch **simultaneously**
3. Wait 2 minutes for DHCP acquisition
4. Run discovery:
   ```bash
   elijahctl discover --ip 192.168.168.1 -v
   ```

#### Level 2: MAC-Based Recovery (10 minutes)
1. If radio not at default IP, use MAC hunt:
   ```bash
   elijahctl health --radio-ip auto -v
   ```
2. Check DHCP lease table on router
3. Scan network segment:
   ```bash
   sudo nmap -sn 192.168.168.0/24
   ```

#### Level 3: AT Command Reset (15 minutes)
**WARNING**: Only if Levels 1-2 fail
1. Connect via serial console if available
2. Execute safe reset:
   ```bash
   elijahctl reset-radio --ip 192.168.168.1 --force
   ```
3. Re-provision from scratch
4. Document incident with radio serial number

### Escalation Criteria
- Radio unresponsive after Level 3
- Physical damage suspected
- Multiple units experiencing same issue

---

## 2. Jetson System Failure

### Symptoms
- Jetson unreachable at 192.168.55.1
- Services (mavlink-router, seraph, elijah) not running
- Tailscale offline
- No MAVLink heartbeats

### Immediate Actions

#### Level 1: Service Recovery (5 minutes)
1. SSH to Jetson:
   ```bash
   ssh jetson@192.168.55.1
   ```
2. Check service status:
   ```bash
   systemctl status mavlink-router seraph elijah radio-stats
   ```
3. Restart failed services:
   ```bash
   sudo systemctl restart [service-name]
   ```

#### Level 2: System Recovery (10 minutes)
1. Check system resources:
   ```bash
   df -h
   free -m
   top -bn1 | head -20
   ```
2. Clear logs if disk full:
   ```bash
   sudo journalctl --vacuum-time=1d
   ```
3. Reboot Jetson:
   ```bash
   sudo reboot
   ```

#### Level 3: Re-provisioning (20 minutes)
1. Factory reset Jetson (if accessible)
2. Re-run Ansible deployment:
   ```bash
   ansible-playbook -i 'all,' deploy_companion.yml -T 60 \
     -e "ansible_host=192.168.55.1 ansible_user=jetson \
         device_name=el-012 sysid=12 \
         tailscale_auth_key=$TAILSCALE_KEY \
         microhard_password=$MICROHARD_PASS"
   ```

### Escalation Criteria
- Hardware failure suspected
- Repeated failures after re-provisioning
- Multiple Jetsons affected simultaneously

---

## 3. Flight Controller Connection Loss

### Symptoms
- No MAVLink heartbeats
- QGC shows "Communication Lost"
- Parameter reads/writes failing
- FC unresponsive to commands

### Immediate Actions

#### Level 1: Connection Recovery (3 minutes)
1. Verify mavlink-router service:
   ```bash
   ssh jetson@192.168.55.1
   sudo systemctl status mavlink-router
   sudo systemctl restart mavlink-router
   ```
2. Check serial port:
   ```bash
   ls -la /dev/ttyTHS* /dev/ttyACM*
   ```

#### Level 2: FC Power Cycle (5 minutes)
1. Power off FC safely
2. Wait 10 seconds
3. Power on FC
4. Monitor for heartbeats:
   ```bash
   elijahctl health --jetson el-012 -v
   ```

#### Level 3: Parameter Reset (10 minutes)
1. Connect via QGC if possible
2. Reset SYSID:
   ```bash
   elijahctl set-sysid --host el-012 --sysid 12 -v
   ```
3. Verify critical parameters
4. Document any parameter changes

### Escalation Criteria
- FC firmware corruption suspected
- Hardware failure indicators
- Safety-critical parameters changed

---

## 4. Network Infrastructure Failure

### Symptoms
- No connectivity between components
- DHCP not assigning addresses
- UniFi AP offline
- Intermittent connectivity

### Immediate Actions

#### Level 1: Basic Network Recovery (5 minutes)
1. Check physical connections
2. Power cycle network equipment in order:
   - Router/DHCP server
   - Switches
   - Access points
3. Verify DHCP service running

#### Level 2: Configuration Recovery (10 minutes)
1. Check UniFi controller status
2. Re-apply UniFi configuration:
   ```bash
   elijahctl unifi \
     --controller https://unifi.local \
     --user admin --pass $UNIFI_PASS \
     --name rainmakerGCSX \
     --ip 10.101.252.1/16 \
     --disable-24ghz --disable-autolink -v
   ```
3. Verify 5GHz-only operation

#### Level 3: Full Network Reset (20 minutes)
1. Document current configuration
2. Factory reset network equipment
3. Restore configuration from backup
4. Re-provision all radios

### Escalation Criteria
- Physical infrastructure damage
- ISP/upstream connectivity issues
- Security breach suspected

---

## 5. Critical System Rollback

### When to Rollback
- Multiple component failures
- Safety-critical malfunction
- Configuration corruption
- Failed deployment validation

### Rollback Procedure

#### Step 1: Stop All Operations
```bash
# Stop all active services
ssh jetson@192.168.55.1
sudo systemctl stop mavlink-router seraph elijah radio-stats
```

#### Step 2: Document Current State
```bash
# Capture system state
elijahctl health --jetson el-012 --radio-ip auto -v > /tmp/rollback_state.txt

# Save configuration
ssh admin@[radio-ip] "uci export" > /tmp/radio_config_backup.txt
```

#### Step 3: Restore Previous Configuration
1. Identify last known good configuration from:
   - `~/.elijahctl/state/runs/` (previous successful runs)
   - Configuration backups
   - Git repository tags

2. Apply previous configuration:
   ```bash
   # Restore radio configuration
   elijahctl provision --config /path/to/last_good_config.json
   
   # Restore Jetson services
   ansible-playbook -i 'all,' deploy_companion.yml \
     --extra-vars @/path/to/last_good_vars.yml
   ```

#### Step 4: Validate Rollback
```bash
# Run comprehensive health check
elijahctl health --jetson el-012 --radio-ip auto --video udp:5600 -v

# Verify critical services
for service in mavlink-router seraph elijah; do
    ssh jetson@192.168.55.1 "systemctl is-active $service"
done
```

---

## 6. Data Preservation During Emergency

### Critical Data to Preserve
1. **Configuration Files**
   - `/etc/config/*` on radio
   - `~/.elijahctl/` on workstation
   - Ansible playbook variables

2. **Logs**
   - System logs: `journalctl -b > system_logs.txt`
   - Radio logs: via SSH to radio
   - Application logs: `~/.elijahctl/logs/`

3. **State Information**
   - Health check outputs
   - Network configuration
   - Service status snapshots

### Emergency Backup Commands
```bash
# Create emergency backup
mkdir -p /tmp/emergency_backup_$(date +%Y%m%d_%H%M%S)
cd /tmp/emergency_backup_*

# Backup elijahctl state
cp -r ~/.elijahctl ./elijahctl_state

# Backup radio config
ssh admin@[radio-ip] "uci export" > radio_config.txt

# Backup Jetson state
ssh jetson@192.168.55.1 "sudo tar czf - /etc/systemd/system/" > jetson_services.tar.gz

# Create incident report
cat > incident_report.md << EOF
Date: $(date)
Affected Unit: [drone-id]
Symptoms: [description]
Actions Taken: [list]
Resolution: [outcome]
EOF
```

---

## 7. Post-Emergency Procedures

### Incident Documentation
1. Create incident ticket with:
   - Timeline of events
   - Actions taken
   - Resolution steps
   - Root cause (if known)

2. Update runbooks with:
   - New failure modes discovered
   - Successful recovery procedures
   - Lessons learned

### System Validation
After emergency resolution:
1. Run full health check suite
2. Verify all services operational
3. Test edge cases that triggered emergency
4. Document any configuration changes

### Preventive Measures
1. Review logs for warning signs
2. Update monitoring thresholds
3. Schedule preventive maintenance
4. Update emergency contact list

---

## Quick Reference Card

| Emergency Type | First Action | Tool Command | Escalation Time |
|---------------|--------------|--------------|-----------------|
| Radio Failure | Power cycle | `elijahctl discover --ip 192.168.168.1` | 5 min |
| Jetson Failure | Check services | `systemctl status [services]` | 5 min |
| FC Loss | Restart MAVLink | `systemctl restart mavlink-router` | 3 min |
| Network Failure | Power cycle | Check DHCP leases | 5 min |
| Multiple Failures | Stop operations | Document state | Immediate |

## Emergency Kit Requirements

Maintain an emergency kit with:
- Serial console cables (USB-to-TTL)
- Spare Ethernet cables (tested)
- Power supplies (48V for radio)
- Factory default configuration files
- Offline documentation copy
- Contact list (printed)