# Microhard Setup (Zero → One) with `elijahctl`

This is the **single, final** setup file for taking a Microhard radio from out-of-box to fully configured through the CLI. It folds in our older manual process so nothing is missed.

Read first:
• **Do not** use the pinhole reset; it can brick the radio. If you must reset, use the AT two-step only (`AT+MSRTF=0` then `AT+MSRTF=1`). *Networking Setup*, p. 1.&#x20;
• **Attach all four antennas before power.** The inner **MMCX→SMA lead stays on the radio permanently**; the outer **SMA↔SMA** goes to the paddles. Alternate **RHCP/LHCP**. “Click” the MMCX home; 8 in-lb on SMA is fine. *Networking Setup*, p. 2.&#x20;

## 0) Bench wiring and base facts

1. Power the PDB (48 V). Use the 4-pin Microhard power lead to the radio; Ethernet from radio to your bench switch/router. *Networking Setup*, p. 1–2.&#x20;
2. Default device address is `192.168.168.1`; default login is `admin/admin`. *Networking Setup*, p. 2–3.&#x20;
3. If a radio won’t show up, **power-cycle the radio and the switch at the same time** to tame DHCP lease weirdness. *Networking Setup*, p. 1.&#x20;

## 1) One-time host prep

```bash
# Python 3.11+ and CLI
python3 --version
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .

# Secrets (example values shown)
export AES_KEY="your-128-bit-aes-key"
export MICROHARD_PASS="admin"       # factory default; the tool can switch it to our target
export TAILSCALE_KEY="tskey-auth-..."
```

## 2) Sanity check the radio is reachable

```bash
# Detect open services at the factory IP
elijahctl discover --ip 192.168.168.1 -v
```

If nothing is found, unplug/replug power to **both** radio and switch together, then run discover again. *Networking Setup*, p. 1.&#x20;

## 3) Provision the **Air** radio via CLI

Target state mirrors our old manual steps (freq 2427 MHz, BW 5 MHz, Net ID `rainmaker`, role **Slave**, TX 30 dBm, **AES-128** with key, LAN **DHCP client**, **Radio Stats** enabled on UDP **22222** with **RF/RSSI/SNR/Associated IP** fields). *Networking Setup*, p. 3 & p. 8.&#x20;

```bash
# The tool will prompt for drone ID and MAV_SYS_ID interactively
elijahctl provision \
  --role air \
  --aes-key "$AES_KEY" \
  --microhard-pass "$MICROHARD_PASS" \
  --tailscale-key "$TAILSCALE_KEY" -v

# When prompted:
# Enter drone ID (e.g., 012): [user enters value]
# Enter MAV_SYS_ID for air radio: [user enters value]
```

**Note:** The drone ID and MAV_SYS_ID are now prompted interactively for easier provisioning of multiple drones. You can still provide them via command line if preferred:
```bash
# Optional: specify inline to skip prompts
elijahctl provision \
  --role air \
  --drone-id 012 \
  --sysid 12 \
  --aes-key "$AES_KEY" \
  --microhard-pass "$MICROHARD_PASS" \
  --tailscale-key "$TAILSCALE_KEY" -v
```

What the CLI does (so you don’t have to click pages):
• Sets hostname/description (`elijah-012-air`). *Networking Setup*, p. 3.&#x20;
• Writes **Wireless → Settings**: 2427/5, `rainmaker`, **Slave**, **30 dBm**, **AES-128 key**. *Networking Setup*, p. 3 & p. 8.&#x20;
• Switches **Network → LAN** to **DHCP client**. *Networking Setup*, p. 3 & p. 8.&#x20;
• Enables **Radio Stats Stream** on **22222**, **interval 1000 ms**, and **RF/RSSI/SNR/Associated IP** fields. *Networking Setup*, p. 3 & p. 8.&#x20;
• Commits **once** (Save & Apply behavior), then reboots. *Networking Setup* warns to apply only at end; the CLI mirrors that. p. 3 & p. 8.&#x20;

After reboot the radio will grab a new **DHCP** address. The CLI caches the MAC and can locate it:

```bash
# Learn the new DHCP IP by MAC and store it
# Replace 'el-XXX' with the drone ID you used during provisioning
elijahctl health --jetson el-XXX --radio-ip auto -v
```

Visual proof when linked to a good ground set: **three green RSSI LEDs solid** and **red TX/RX blinking**. *Networking Setup*, p. 4.&#x20;

## 4) Provision the **Ground** radio via CLI

Ground mirrors Air except role **Master** and hostname `rainmaker-ground-X`.

```bash
# The tool will prompt for drone ID interactively
elijahctl provision \
  --role ground \
  --aes-key "$AES_KEY" \
  --microhard-pass "$MICROHARD_PASS" -v

# When prompted:
# Enter drone ID (e.g., 012): [user enters ground station ID like 001]
```

**Note:** The drone ID is now prompted interactively. You can still provide it via command line if preferred:
```bash
# Optional: specify inline to skip prompt
elijahctl provision \
  --role ground \
  --drone-id 001 \
  --aes-key "$AES_KEY" \
  --microhard-pass "$MICROHARD_PASS" -v
```

The CLI writes the same RF settings, **Master** mode, **DHCP client**, and leaves stats behavior consistent. This replaces the manual Ground steps in *Networking Setup*, p. 6–7.&#x20;

## 5) Safe reset / recovery, if needed

Only if the device is wedged. **Do not** use the pinhole. Use the **AT two-step** over Telnet:

```bash
# Factory-safe reset (two-step)
elijahctl reset-radio --ip 192.168.168.1 --force
# Under the hood it sends: AT+MSRTF=0  then  AT+MSRTF=1
```

That matches our old guidance. *Networking Setup*, p. 1.&#x20;

## 6) What to verify, fast

```bash
# If Jetson is present, run the full health sweep (proves radio stats fields too)
# Replace 'el-XXX' with the actual drone ID you entered during provisioning
elijahctl health --jetson el-XXX --radio-ip auto --video udp:5600 -v
```

Checks to see green:
• **Radio Stats** packets on **22222** that include `rssi` and `snr` and the **Associated IP** field we rely on. *Networking Setup*, p. 3 & p. 8.&#x20;
• **MAVLink** heartbeats if the rest of the bench is up (not required just to prove the radio).

## 7) Exact mapping vs the old click-through

For audit parity with the old guide:
• System → Settings: `hostname=elijah-<ID>-air` or `rainmaker-ground-<N>`; `description=…` *Networking Setup*, p. 3 & p. 6–7.&#x20;
• Wireless → Settings: `freq=2427`, `bw=5`, `net_id=rainmaker`, `mode=Slave/Master`, `tx_power=30`, `encryption=AES-128`, `key=<fleet key>`. *Networking Setup*, p. 3, p. 7–8.&#x20;
• Network → Interfaces: LAN `proto=dhcp`. *Networking Setup*, p. 3 & p. 7–8.&#x20;
• Applications → Radio Stats Stream: `enable`, `port=22222`, `interval=1000`, fields `RF,RSSI,SNR,Associated IP`. *Networking Setup*, p. 3 & p. 8.&#x20;

The CLI writes all of the above in one atomic apply, mirroring the “Save then **Save & Apply at the end**” safety rule. *Networking Setup*, p. 3 & p. 8.&#x20;

## 8) Troubleshooting quick hits

• No services at `192.168.168.1`: pair power-cycle radio and switch; try `elijahctl discover` again. *Networking Setup*, p. 1.&#x20;
• Can’t reach LuCI after apply: plug radio into router and re-apply once from the UI; DHCP may have flipped mid-flow. *Networking Setup*, p. 4.&#x20;
• Stats flowing but missing fields: the CLI enables **RF/RSSI/SNR/Associated IP**; re-provision to restore; then re-check with `elijahctl health`. *Networking Setup*, p. 3 & p. 8.&#x20;

## 9) Done criteria

Air and Ground both show the right RF set, encryption on with the fleet key, LAN on DHCP, and stats flowing on 22222. Air + good Ground will show **three green RSSI solid** and **red TX/RX blinking**. *Networking Setup*, p. 4.&#x20;

---

### Adjacent but out-of-scope here (for the larger bench run)

ESC flashing/params and motor spin mapping are still handled in **KDEDirect** on Windows; follow the short card with pictures and the CW/CCW diagram, then test spins in QGC. *ESC Configuration*, all pages.&#x20;

This file supersedes the old click-paths; run the **Air** and **Ground** commands above and you’re done.
