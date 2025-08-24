Got it. Here’s the tightened, **hand‑off spec** that folds in your new HITL/in‑situ checklist and the **ESC/KDEDirect** steps. It keeps the one‑button vision (“`elijahctl`”), but calls out the few things that must stay hand‑done (antenna torque, ESC flashing, RemoteID/FAA entry, first‑time UniFi adoption).

I cite the two source docs inline wherever they bind the process. &#x20;

---

## 0) Scope, names, inputs

**Goal:** push‑button bring‑up of an Elijah air set + ground station with hard gates for the HITL shelf and in‑situ checks. Radios are treated as OpenWrt/LuCI boxes; Jetson is driven by Ansible; FC by MAVLink.

**Inputs per unit**

* `drone_id` (e.g., `012`) → names `el-012` (Jetson), `elijah-012-air` (air radio).&#x20;
* `sysid` (e.g., `12`) → `MAV_SYS_ID`.&#x20;
* Secrets: Microhard admin pass, AES‑128 key (`rainmaker` net), Tailscale key.&#x20;
* RemoteID module serial + FAA DB entry (manual but logged; shows on your sheet).
* ESC param set version (from `v2_standard.cfg`) + ESC firmware build.&#x20;

**Naming + links**

* Ground radio: `rainmaker-ground-X`, static `10.101.252.1/16`, 2.4 GHz **off**, Auto‑Link **off**.&#x20;

---

## 1) End‑to‑end flow (batch‑safe)

1. **HITL shelf prep**

   1. Air Microhard set up (stage → single apply) → DHCP flip handled.
   2. Jetson bring‑up with Ansible → Tailscale name shows → FC firmware staged.
   3. ESC flash + params per motor in KDEDirect → spin and map.
   4. QGC: set `MAV_SYS_ID` → reboot → heartbeats.
   5. Seraph: radio stats, video, PTH, versions green.
2. **In‑situ checkout**
   Mount in vehicle; run Seraph checks again; safety/arm tests; RemoteID live.
3. **Ground**
   Ground Microhard; UniFi AP adopt+lock; link proof (3 green RSSI, flashing red TX/RX).&#x20;

Everything below tells an engineer how to build `elijahctl` + what to do by hand.

---

## 2) Air Microhard — target state + safe path

**Do not** pin‑reset. If you must reset: `AT+MSRTF=0` then `AT+MSRTF=1`.&#x20;

**Stage (no apply yet):**

* **System → Settings**
  `hostname=elijah-<ID>-air`, `desc="Elijah <ID> Air Radio"`.&#x20;
* **Wireless → Settings**
  `freq=2427 MHz`, `bw=5 MHz`, `net_id=rainmaker`, `mode=Slave`, `tx=30`, `encryption=AES‑128`, `key=<fleet key>`.&#x20;
* **Network → Interfaces**
  LAN → **DHCP client** (do not switch yet).&#x20;
* **Applications → Radio Stats Stream**
  `enable=true`, `server_port=22222`, `interval=1000 ms`, enable fields **RF/RSSI/SNR/Associated IP**; Server IP left blank (Jetson service fills).&#x20;

**Apply once** (Save & Apply) only when all staged, then reboot. Handle DHCP flip by lease scan. Debug fallback (from doc): if hostname not reachable, plug to router and hit LuCI again.&#x20;

**Probe + ubus/uci code (snips)**

```python
# Microhard discovery
def port_open(ip, port): ...
def discover(ip="192.168.168.1"): return {"ssh":port_open(ip,22),"telnet":port_open(ip,23),"http":port_open(ip,80)}
```

```python
# ubus login + uci set + commit + reboot
POST /cgi-bin/luci/rpc/auth {"id":1,"method":"login","params":["admin","admin"]}
→ ubus_rpc_session
POST /ubus {"jsonrpc":"2.0","id":2,"method":"call","params":[token,"uci","set",
 {"config":"system","section":"@system[0]","values":{"hostname":"elijah-012-air"}}]}
POST /ubus ... commit system|wireless|network
POST /ubus ... call [token,"system","reboot",{}]
```

(Use this in code; avoids brittle HTML; mirrors the “Save now, Apply at end” rule.)&#x20;

**Reset (only safe way):**

```
Telnet → AT+MSRTF=0  → AT+MSRTF=1
```



**Link proof:** when paired to good ground radio: **three green RSSI** solid, **TX/RX** red blinking.&#x20;

---

## 3) Jetson — bring‑up + firmware stage

Wire Jetson to router (not through Microhard) for first pass. Ping/SSH `192.168.55.1` (`jetson` login). Run the **exact** Ansible call from the doc with vars:

```
ansible-playbook -i 'all,' deploy_companion.yml --ask-pass --ask-become-pass -T 60 \
  -e "ansible_host=192.168.55.1 ansible_user=jetson device_name=el-<ID> sysid=<SYSID> \
      tailscale_auth_key=<TSKEY> microhard_password=<RADIO_PASS>"
```

Radio‑stats startup check is expected red until radio present. Then confirm the Tailscale name shows (`el-<ID>`). Power‑cycle. Load FC firmware in ARK UI (`el-<ID>/`). Later, move Jetson Ethernet from router to the Microhard.&#x20;

---

## 4) Flight controller — `MAV_SYS_ID` + heartbeats

QGC path (doc): add UDP 14550 link to the Jetson host, set `MAV_SYS_ID` to your `sysid`, reboot, see heartbeats.&#x20;

Headless snip:

```python
from pymavlink import mavutil, mavwp
m = mavutil.mavlink_connection('udpout:el-012:14550')
m.wait_heartbeat(timeout=10)
m.mav.param_set_send(m.target_system, m.target_component, b"MAV_SYS_ID",
                     float(12), mavutil.mavlink.MAV_PARAM_TYPE_INT32)
m.mav.command_long_send(m.target_system, m.target_component,
                        mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,0,1,0,0,0,0,0,0)
```

---

## 5) ESCs — firmware, params, and spin map (Windows + KDEDirect)

**Setup** (from ESC doc): Windows laptop, USB‑A→Micro‑B, Elijah ESC adapter into the **3‑color** lead on Elijah’s side (see photos). No battery needed for setup. Open **KDEDirect Device Manager**.&#x20;

**Steps (per ESC/motor):**

1. **Flash ESC firmware** from your share; then load **`v2_standard.cfg`**.&#x20;
2. In KDEDirect, write the param set to the ESC tied to the **yellow** signal wire that maps to that motor.&#x20;
3. **Motor direction** depends on ESC‑to‑FC wiring; your drawing sets the map with the **camera as front**:

   * Motor **1** (front‑right): **CW**
   * Motor **3** (front‑left): **CCW**
   * Motor **2** (rear‑left): **CW**
   * Motor **4** (rear‑right): **CCW**
     Confirm in QGC in a safe stand; flip direction in KDEDirect if wrong.&#x20;

**Notes:** The KDEDirect UI screenshot in the doc shows a 1000–2000 throttle range and motor model fields; stick to your saved `v2_standard.cfg` as single source of truth; record its version in the sheet.&#x20;

---

## 6) Ground Microhard + UniFi AP

**Ground radio target** (same save/apply pattern as air, but Master):

* Hostname `rainmaker-ground-<N>`, desc “Rainmaker Ground Radio <N>”.
* Wireless: `2427 MHz`, `5 MHz`, `rainmaker`, `Master`, `tx=30`, `AES‑128 <key>`.
* LAN → DHCP client.&#x20;

**UniFi AP** (manual first‑time adopt; scripted after): **Disable 2.4 GHz**, **disable Auto‑Link**, **static 10.101.252.1/16**, name `rainmakerGCSX`.&#x20;

---

## 7) Health checks (turn the UI steps into proofs)

`elijahctl health` should prove:

* **Paths live**: ping Jetson and radio; Tailscale node `el-<ID>` online.&#x20;
* **MAVLink**: heartbeats on 14550.&#x20;
* **Radio stats**: UDP `22222` packets with RF/RSSI/SNR/Associated IP (allow warm‑up).&#x20;
* **Video**: bytes on the stream socket in N s.&#x20;
* **PTH**: both Jonah sensors present.&#x20;
* **Versions**: Seraph + Elijah + FC firmware and params match targets (same top‑bar list you eyeball in Seraph).&#x20;

Snip to sniff radio stats:

```python
import socket
def recv_stats(port=22222, t=5):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0",port)); s.settimeout(t)
    pkt=s.recv(4096).decode(errors="ignore").lower()
    assert all(k in pkt for k in ("rssi","snr","rf")), "missing fields"
```

---

## 8) The **checklist** (mirrors your sheet; machine‑tracked)

Two phases match your grid (“Elijah HITL shelf prep” → “In‑situ checkout”), then sign‑off.

**HITL shelf prep – fields**

* **serial number (QR)** → “Earmarked working air radio” (yes/no).
* **air radio firmware** (keep factory) + **air radio config** (yes/no).&#x20;
* **RemoteID module configured** (yes/no), **RemoteID serial (20 digits)**, **RemoteID added to FAA DB** (yes/no).
* **Jetson software** (git hash), **Jetson PX4 firmware** (file ref), **Jetson param set flashed** (version), **Jetson set sysid** (value).&#x20;
* **Seraph**: SNR, PDB/PTH, cam, RemoteID seen (yes/no).&#x20;
* **ESC firmware** (version/file), **ESC params** (version), **spin direction / motor mapping** (yes/no).&#x20;
* **ADS power test** (yes/no), **Armed in Seraph with no props** (yes/no), **Arm safety param confirmed** (yes/no).&#x20;
* **ELRS configured** (if used) (yes/no).
* **Completed HITL checkout**: name/date.

**In‑situ checkout – fields**

* **Installed in vehicle** (yes/no).
* **Seraph**: Params, SNR, PDB, cam, RemoteID (yes/no).&#x20;
* Add any site‑specific RF or GNSS checks you require.

**Return to MFG**

* Batch/date written; Jetson and radio labeled and stored; inner RF lead stays on radio; outer lead with paddles removed.&#x20;

**CLI sketch** (write `checklist.json` alongside logs):

```python
@dataclass
class HitlChecklist:
    serial_qr:str; air_radio_fw:str; air_radio_config:bool
    remoteid_config:bool; remoteid_serial:str; remoteid_faa:bool
    jetson_git:str; px4_fw:str; param_set_version:str; sysid:int
    seraph_hitl:bool; esc_fw:str; esc_params:str; motor_map_ok:bool
    ads_power_ok:bool; arm_noprops_ok:bool; arm_safety_ok:bool; elrs_ok:Optional[bool]
    hitl_signed_by:str; hitl_date:str
```

---

## 9) `elijahctl` layout (what to build)

* `elijahctl provision --role air|ground --drone-id --sysid --aes-key --microhard-pass --tailscale-key`
* `elijahctl reset-radio --ip 192.168.168.1`  → **AT+MSRTF=0/1** only.&#x20;
* `elijahctl flash-fc --jetson el-012 --fw <path>` (or “hand off to ARK upload” if no API).&#x20;
* `elijahctl health --jetson el-012 --radio-ip auto`
* `elijahctl unifi --controller <url> --user --pass --name rainmakerGCSX --ip 10.101.252.1/16 --disable-24ghz --disable-autolink`&#x20;
* `elijahctl checklist --update <json>` (writes ledger + CSV row)

**Repo**

```
drivers/microhard.py    # ubus/uci + telnet reset
drivers/jetson.py       # ansible wrapper
drivers/mavlink_fc.py   # sysid set + reboot
drivers/unifi.py        # controller tweaks after adoption
health/checks.py        # radio stats, mavlink, tailscale, video, pth
state/                  # signed JSON proofs + checklist rows
```

---

## 10) Safety gates baked in

* **No pin reset**; warn + stop if attempted. Use AT reset only.&#x20;
* **Stage then apply once**; never commit mid‑run; reduce soft‑brick risk.&#x20;
* **Pair power‑cycle** radio + switch to tame DHCP leases (doc tip).&#x20;
* **ESC spin tests** in safe stand, no props; arm check in Seraph marked as **no‑props**. &#x20;

---

## 11) What must stay hand‑done (and how to record it)

* Antenna torque + RHCP/LHCP alternation; keep inner MMCX→SMA lead on the radio forever. Record torque, worker, time.&#x20;
* KDEDirect firmware + param write per ESC; record `esc_fw`, `esc_params` and per‑motor direction.&#x20;
* UniFi **adoption** (one‑time trust); everything after is scripted.&#x20;
* RemoteID config + FAA DB entry; record serial + timestamp (your sheet already tracks these fields).

---

## 12) Appendix — API bodies and snips

**LuCI/ubus JSON‑RPC** (use these shapes exactly):

* Login: `POST /cgi-bin/luci/rpc/auth {"id":1,"method":"login","params":[user,pass]} → ubus_rpc_session`
* UCI set: `POST /ubus {"jsonrpc":"2.0","id":2,"method":"call","params":[token,"uci","set",{"config":"system","section":"@system[0]","values":{"hostname":"..."}}]}`
* Commit: `{"params":[token,"uci","commit",{"config":"system"}]}`
* Reboot: `{"params":[token,"system","reboot",{}]}`
  These map cleanly to the doc’s UI steps and respect the “apply once” rule.&#x20;

**AT reset** over Telnet:

```
login admin/admin
AT+MSRTF=0
AT+MSRTF=1
```



**Ansible** (Jetson bring‑up) — the exact incantation from the doc; pass `device_name`, `sysid`, `tailscale_auth_key`, `microhard_password`. Expect radio‑stats check red until radio present.&#x20;

**KDEDirect** (Windows GUI) — load firmware, then apply `v2_standard.cfg`; map motor directions as shown; test in QGC; flip if needed.&#x20;

---

## 13) Acceptance (what “done” means)

* **HITL shelf** row fully green:
  air radio staged/applied; Jetson on Tailscale; FC sysid set; Seraph shows heartbeats, radio stats (after short wait), video, PTH; ESCs flashed + param’d; spin/mapping match the drawing; arm/no‑props and safety param confirmed; RemoteID info captured. &#x20;
* **In‑situ** row green: installed, Seraph **Params/SNR/PDB/cam/RemoteID** all good.&#x20;
* **Ground**: UniFi AP adopted + locked; ground radio set; link shows 3 green RSSI, red TX/RX flashing.&#x20;
* Labels on Jetson (`el-<ID>`) and Microhard (`<ID>`); inner RF lead left on; batch/date logged.&#x20;

---

### Blunt notes

* Do not “Save & Apply” mid‑config. Stage all, apply once. That single habit kills half the weirds.&#x20;
* Never poke the Microhard pinhole; it bricks. Use `AT+MSRTF`.&#x20;
* KDEDirect is the only sane path for these ESCs; log the exact cfg build you wrote.&#x20;

This is the **only** doc your engineer needs. Build `elijahctl` to this spec; treat the two PDFs as ground truth for values and one‑off gotchas. &#x20;
