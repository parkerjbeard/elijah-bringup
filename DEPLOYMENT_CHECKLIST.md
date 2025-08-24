# Production Deployment Validation Checklist

## Pre-Deployment Phase

### Environment Preparation
- [ ] **Infrastructure Ready**
  - [ ] Network equipment powered and configured
  - [ ] DHCP server operational with correct scope
  - [ ] Routing tables configured
  - [ ] Firewall rules implemented
  - [ ] Physical connections verified

- [ ] **Credentials Ready**
  - [ ] AES_KEY available in environment
  - [ ] MICROHARD_PASS available in environment
  - [ ] TAILSCALE_KEY available from admin console
  - [ ] UNIFI credentials available if needed

- [ ] **Tools and Dependencies**
  - [ ] Python 3.11+ installed and verified
  - [ ] elijahctl installed (`pip install -e .`)
  - [ ] Ansible installed and configured
  - [ ] Network diagnostic tools available (nmap, arp, etc.)
  - [ ] Emergency recovery tools prepared

- [ ] **Documentation Review**
  - [ ] Setup guide reviewed by team
  - [ ] Emergency procedures accessible
  - [ ] Contact information updated
  - [ ] Previous deployment notes reviewed

---

## Deployment Phase

### Stage 1: Radio Configuration

#### Air Radio Setup
- [ ] **Initial Connection**
  ```bash
  elijahctl discover --ip 192.168.168.1 -v
  ```
  - [ ] SSH service detected
  - [ ] HTTP service detected
  - [ ] Telnet service available

- [ ] **Provisioning Execution**
  ```bash
  elijahctl provision \
    --role air \
    --drone-id [ID] \
    --sysid [SYSID] \
    --aes-key "$AES_KEY" \
    --microhard-pass "$MICROHARD_PASS" \
    --tailscale-key "$TAILSCALE_KEY" -v
  ```
  - [ ] Configuration staged successfully
  - [ ] Single commit verified
  - [ ] Radio rebooted cleanly
  - [ ] New IP acquired via DHCP

- [ ] **Configuration Verification**
  - [ ] Hostname: `elijah-[ID]-air`
  - [ ] Frequency: 2427 MHz
  - [ ] Bandwidth: 5 MHz
  - [ ] Network ID: `rainmaker`
  - [ ] Mode: Slave
  - [ ] Power: 30 dBm
  - [ ] Encryption: AES-128 enabled
  - [ ] LAN: DHCP client
  - [ ] Radio stats: UDP 22222 enabled

#### Ground Radio Setup
- [ ] **Ground Station Configuration**
  ```bash
  elijahctl provision \
    --role ground \
    --drone-id 001 \
    --aes-key "$AES_KEY" \
    --microhard-pass "$MICROHARD_PASS" -v
  ```
  - [ ] Mode: Master confirmed
  - [ ] RF parameters match air radio
  - [ ] DHCP client configured

### Stage 2: Jetson Configuration

- [ ] **Ansible Deployment**
  - [ ] Services deployed via elijahctl or manual Ansible
  - [ ] Deployment completed without errors
  - [ ] All playbook tasks green

- [ ] **Service Verification**
  ```bash
  ssh jetson@192.168.55.1
  systemctl is-active mavlink-router seraph elijah
  ```
  - [ ] mavlink-router: active
  - [ ] seraph: active
  - [ ] elijah: active
  - [ ] radio-stats: active (after radio connected)

- [ ] **Tailscale Verification**
  ```bash
  tailscale status --json | jq '.Self.DNSName, .Self.Online'
  ```
  - [ ] Device online
  - [ ] Correct DNS name (`el-[ID]`)
  - [ ] Reachable via Tailscale network

### Stage 3: Flight Controller

- [ ] **System ID Configuration**
  ```bash
  elijahctl set-sysid --host el-[ID] --sysid [SYSID] -v
  ```
  - [ ] Parameter set successfully
  - [ ] FC rebooted
  - [ ] New SYSID verified
  - [ ] Heartbeats detected at ~1Hz

### Stage 4: Network Infrastructure

- [ ] **UniFi Configuration** (if applicable)
  ```bash
  elijahctl unifi \
    --controller https://unifi.local \
    --user admin --pass "$UNIFI_PASS" \
    --name rainmakerGCSX \
    --ip 10.101.252.1/16 \
    --disable-24ghz --disable-autolink -v
  ```
  - [ ] 2.4 GHz disabled
  - [ ] Auto-optimization disabled
  - [ ] Static IP configured
  - [ ] Device name set correctly

---

## Post-Deployment Validation

### System Health Check

- [ ] **Comprehensive Health Validation**
  ```bash
  elijahctl health --jetson el-[ID] --radio-ip auto --video udp:5600 -v
  ```
  
  **All checks must pass:**
  - [ ] Jetson Connectivity: ✓ (with RTT < 100ms)
  - [ ] Radio Connectivity: ✓ (with RTT < 50ms)
  - [ ] Tailscale Status: ✓ (Online)
  - [ ] MAVLink Heartbeat: ✓ (~1 Hz)
  - [ ] Radio Statistics: ✓ (RSSI/SNR values present)
  - [ ] Video Stream: ✓ (bytes > 0)
  - [ ] PTH Sensors: ✓ (values present)
  - [ ] Version Info: ✓ (git hashes present)

### Communication Verification

- [ ] **Radio Link Quality**
  - [ ] RSSI: > -70 dBm
  - [ ] SNR: > 20 dB
  - [ ] Three green RSSI LEDs solid
  - [ ] TX/RX LEDs blinking red
  - [ ] No packet loss over 5 minutes

- [ ] **End-to-End Connectivity**
  - [ ] GCS can connect to drone
  - [ ] MAVLink messages flowing
  - [ ] Video stream visible
  - [ ] Telemetry updating in real-time
  - [ ] Commands acknowledged

### Resilience Testing

- [ ] **Idempotence Verification**
  - [ ] Re-run provisioning with same parameters
  - [ ] No errors or warnings
  - [ ] Configuration unchanged
  - [ ] System remains operational

- [ ] **Power Cycle Recovery**
  - [ ] Power cycle radio and switch
  - [ ] System recovers within 2 minutes
  - [ ] All services auto-start
  - [ ] Health check passes

- [ ] **Failover Testing**
  - [ ] Disconnect and reconnect network cables
  - [ ] Services recover automatically
  - [ ] No manual intervention required

### Documentation and Handoff

- [ ] **Production Documentation**
  ```bash
  elijahctl checklist \
    --update production_data.json \
    --drone-id [ID] \
    --phase production -v
  ```
  - [ ] Checklist entry created
  - [ ] JSON report generated
  - [ ] CSV ledger updated

- [ ] **Deployment Artifacts**
  - [ ] Configuration backup saved
  - [ ] Health check report archived
  - [ ] Network diagram updated
  - [ ] Credentials documented
  - [ ] Incident log initialized

---

## Rollback Criteria

**Initiate rollback if ANY of the following occur:**

### Critical Failures
- [ ] Radio cannot maintain stable connection
- [ ] Jetson services crash repeatedly
- [ ] Flight controller not responding
- [ ] Network infrastructure unstable

### Performance Failures
- [ ] RSSI consistently < -80 dBm
- [ ] Packet loss > 5%
- [ ] MAVLink heartbeat irregular
- [ ] Video stream stuttering/frozen
- [ ] Response time > 500ms

### Configuration Failures
- [ ] Wrong frequency or bandwidth
- [ ] Encryption not working
- [ ] DHCP failures
- [ ] Service configuration errors
- [ ] Parameter corruption

---

## Sign-Off

### Technical Validation
- [ ] **Systems Engineer**: ___________________ Date: ___________
  - All technical checks completed
  - Performance meets specifications
  - No outstanding issues

- [ ] **Network Administrator**: ___________________ Date: ___________
  - Network configuration verified
  - Monitoring enabled

### Operational Acceptance
- [ ] **Operations Manager**: ___________________ Date: ___________
  - Documentation complete
  - Training provided
  - Support procedures in place

- [ ] **Quality Assurance**: ___________________ Date: ___________
  - All tests passed
  - Compliance verified
  - Risk assessment complete

---

## Post-Deployment Actions

### Immediate (Within 1 hour)
- [ ] Monitor system for first hour
- [ ] Verify all metrics stable
- [ ] Check for any alerts or warnings
- [ ] Document any observations

### Day 1
- [ ] Review 24-hour metrics
- [ ] Collect operator feedback
- [ ] Address any minor issues
- [ ] Update documentation as needed

### Week 1
- [ ] Analyze week's performance data
- [ ] Conduct team retrospective
- [ ] Document lessons learned
- [ ] Plan any optimizations

### Ongoing
- [ ] Weekly health checks
- [ ] Annual disaster recovery test

---

## Emergency Contacts

**On-Call Engineer**: ___________________  
**Network Operations**: ___________________  
**Vendor Support**: ___________________  

**Escalation Path**: L1 (15 min) → L2 (30 min) → L3 (1 hour) → Management

---

## Notes Section

### Deployment Notes:
```
Date: 
Deployer: 
Environment: 
Special Conditions: 
```

### Issues Encountered:
```
Issue: 
Resolution: 
Time to Resolve: 
```

### Optimization Opportunities:
```
Observation: 
Recommendation: 
Priority: 
```

---

**Document Version**: 1.0  
**Last Updated**: [Date]  
**Next Review**: [Date + 30 days]