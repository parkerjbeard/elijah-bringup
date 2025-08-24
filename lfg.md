# Elijah Bring‑Up: How the New `elijahctl` Repo Replaces the Old Manual Guides

**Audience:** the person currently overseeing Elijah networking and bring‑up.
**Goal:** show, step‑by‑step, how each part of the new automation replaces (or shortens) your existing Networking/ESC procedures, plus what remains manual.

---

## 1) Repository at a Glance

```
elijahctl/
├── config.py                # Shared typed configs, secrets storage, checklists
├── drivers/
│   ├── mh_profile.py        # Microhard profile detector + UCI key map (foundation)
│   └── unifi.py             # UniFi (Ubiquiti) controller automation
├── health/
│   └── checks.py            # One‑shot end‑to‑end health checks (Jetson/radio/FC/video)
└── utils/
    └── network.py           # Cross‑platform networking helpers (ARP, ping, MAC/IP)
```

> Other referenced modules such as `..drivers.mavlink` and `..utils.logging` are used by the above files; they provide MAVLink heartbeat monitoring and consistent CLI logging respectively.

---

## 2) What the Old Manuals Ask You To Do (Condensed)

**Networking guide (Microhard + Jetson + UniFi):**

* Configure Microhard *air* radio (hostname/description; 2427 MHz, 5 MHz BW, Net ID `rainmaker`, **Slave**, 30 dBm, AES‑128 key; set LAN to **DHCP client**; enable **Radio Stats Stream** on port **22222** with **1000 ms** interval; only “RF/RSSI/SNR/Associated IP” needed; click **Save & Apply** when done).&#x20;
* Configure Microhard *ground* radio similarly but as **Master**. (Same RF settings; Master mode; Save‑order caution.)&#x20;
* Provision the **Jetson** (connect to router; run the Seraph Ansible playbook with SYSID/serial/tailscale key; confirm Jetson appears in Tailscale; upload FC firmware via ARK; move Ethernet from router to Microhard; power/labels).&#x20;
* Provision **UniFi (Ubiquiti) router/AP**: adopt into controller, **disable 2.4 GHz**, **disable Auto‑Link**, set **static 10.101.252.1/16**, set device name to `rainmakerGCSX`.&#x20;
* **Final checks:** QGC UDP 14550 link, set `MAV_SYS_ID`, verify heartbeats, radio stats, video, and PTH in Seraph.&#x20;

**ESC configuration guide:** flash ESC, plug the adapter to each ESC lead, set KDE Direct parameters and **motor direction**, test with QGC, adjust directions if needed.&#x20;

---

## 3) How the New Code Replaces Those Steps

### A. Microhard radios (Air/Ground)

**What was manual:** web‑UI pages and page‑by‑page settings, with a strong “Save & Apply only at the end” constraint; enabling the Stats Stream (port 22222 @ 1000 ms) with specific fields.&#x20;

**What’s automated today (and where):**

* **Declarative target state for radios** — `config.RadioConfig` auto‑derives the correct values from a single role + drone ID:

  * Sets **Slave**/**Master** automatically (role), auto‑names hostnames/descriptions (`elijah-{id}-air`, `rainmaker-ground-{id}`), sets defaults **2427 MHz**, **5 MHz**, **Net ID rainmaker**, **30 dBm**, **AES‑128**, DHCP client, and Stats settings (port `22222`, interval `1000ms`).
    *Code:* `elijahctl/config.py::RadioConfig.__post_init__` and fields.
* **Profile‑aware key mapping for Microhard builds** — `drivers/mh_profile.py` **detects the UCI layout** from `uci show` output and **maps semantic keys → UCI `(config, section, option)`** (e.g., `role`, `freq_mhz`, `bw_mhz`, `net_id`, `tx_power`, `encrypt_enable`, `dhcp_proto`, and the full `mh_stats` block for streaming).
  *Code:* `detect_profile()` returns an `MHProfile` with the mapping `uci_keys[...]`.
* **Finding each radio on the network quickly and robustly** — `utils/network.py` provides:

  * `find_mac_in_leases(mac, subnet)` to get an IP from ARP or a simulated lease file (for lab runs).
  * `discover_services()` to see if **http/ssh/telnet** are open.
  * `get_mac_address(ip)`, `scan_network_for_device()`, and a **ping** that works across macOS/Linux without `sudo` (`ping_host()` uses TCP connect timing).
    *Code:* `utils/network.py`.

**What this replaces:** you no longer need to hunt for the radio’s IP, guess which tools are installed, or keep track of UCI field names per firmware. The **profile detector** and **RadioConfig** give you a single, consistent contract for air/ground radios, and the networking helpers find and talk to the device.

**What remains to finish (transparent):**

* A small **`MicrohardDriver`** that **applies** the `RadioConfig` via SSH/Telnet/HTTP UCI calls. The foundation (profile detection + exact UCI key paths) is done; the idempotent “write/apply/restart” methods are the next \~300 lines of code:

  * read current `uci show`, detect profile,
  * write keys for RF, role, encryption, DHCP client,
  * write stats block (enable, `port=22222`, `interval=1000`, fields),
  * perform **single** `uci commit` and `reload` to respect the manual’s “Save & Apply at the end” rule.&#x20;

> **Net effect today:** you have the schema, discovery, and verification pieces. Implementing `MicrohardDriver.apply(config: RadioConfig)` will eliminate the remaining Microhard clicks entirely.

---

### B. UniFi (Ubiquiti) ground router/AP

**What was manual:** adopt device; set name **`rainmakerGCSX`**; set static **10.101.252.1/16**; **disable 2.4 GHz**; **disable Auto‑Link**.&#x20;

**What’s automated:**

* **Controller login across versions** (`v6`/`v7`/`v8`, UniFi OS vs legacy), CSRF token handling, and proxy path detection.
  *Code:* `drivers/unifi.py::login(), _is_unifi_os(), _net_base(), _detect_api_version()`
* **Adoption + provisioning**:

  * `get_devices()` enumerates devices.
  * `adopt_device(mac)` initiates adoption.
  * `configure_device(device_id)` sets **name**, **static IP/netmask/gateway** (gateway computed from the network, no hard‑coding), and **DNS**.
  * `disable_24ghz()` updates each WLAN’s band fields (`wlan_bands`/`wlan_band`) to 5 GHz‑only.
  * `disable_auto_optimize()` turns off UniFi auto‑optimize/auto‑link.
  * `provision()` orchestrates the above and performs a **read‑back guard** to warn if any WLAN still includes 2.4 GHz.
    *Code:* `drivers/unifi.py`.

**What this replaces:** the entire UniFi UI workflow is a single call (`UniFiDriver.provision()`), covering each bullet from the manual (adopt, name, static IP, 2.4 GHz off, auto‑link off).&#x20;

---

### C. Jetson bring‑up + end‑to‑end checks

**What was manual:** run the Seraph Ansible play, watch Tailscale, upload FC firmware in ARK, then validate with QGC + Seraph (heartbeats, radio stats, video, PTH).&#x20;

**What’s automated:**

* **One‑shot health suite** — `health/checks.py` bundles the “final checks” into a 10–20 s pass:

  * **Connectivity:** TCP‑based reachability + RTT to Jetson (and radio if provided). `_check_connectivity()` uses `utils.network.ping_host()` so it works the same on macOS/Linux.
  * **Tailscale online:** SSH into Jetson, run `tailscale status --json`, and confirm “Online” + DNSName. `_check_tailscale()`.
  * **Radio Stats Stream (UDP 22222):** open a UDP socket, read a few packets, verify `rssi`/`snr` fields. `_check_radio_stats()`. *This confirms what you previously eyeballed in Seraph.*
  * **MAVLink/heartbeat:** open UDP **14550**, count heartbeats over 5 s, and fail if rate is too low. `_check_mavlink()` (via `MAVLinkDriver`).
  * **Video stream:** supports `udp:PORT`, `rtsp://…`, or `tcp:PORT` probes; reports “responsive” / “bytes received,” not just “port open.” `_check_video_stream()`.
  * **PTH sensors:** SSH into Jetson, read `/var/log/seraph/pth.json` (path override via `ELIJAH_PTH_PATH`) and display P/T/H values. `_check_pth_sensors()`.
  * **Versions:** read `/opt/seraph` + `/opt/elijah` Git hashes and `/opt/firmware/version.txt`. `_check_versions()`.

* **Run + report:** `run_all_checks()` executes the above with a progress UI and prints a pass/fail summary; `save_results()` writes a timestamped JSON to `~/.elijahctl/state/runs/…` for traceability.

* **Typed Jetson config:** `config.JetsonConfig` ensures consistent device naming (`el-{id}`), SYSID, and secrets integration for downstream tasks (e.g., Ansible variables).

**What this replaces:** the operator no longer needs to manually step through QGC, Seraph, and logs to spot‑check; a single health command covers connectivity, Tailscale, MAVLink, Radio Stats, video, PTH, and versions that the manual asks you to verify.&#x20;

> **Note:** the **Ansible deploy** and **ARK firmware upload** still run outside this repo (they live in Seraph/ARK). The health suite validates the outcome the manual prescribes.

---

### D. ESC configuration

**What was manual:** flash ESC firmware; connect adapter to each motor lead; set KDE Direct parameters; set/verify **motor direction**; test with QGC and adjust.&#x20;

**What’s covered in code today:**

* **Checklist capture** rather than programming: `config.HitlChecklist` includes `esc_fw_ref`, `esc_params_ref`, and `motor_map_ok` so we can **record** ESC firmware/params and sign‑offs alongside the rest of HITL bring‑up data.

**What remains manual (for now):** flashing and KDE Direct parameterization itself. There is no ESC programming driver in this repo yet.

---

## 4) Quick “Old Step → New Automation” Map

| Old manual step                                                                                                                                                                                                      | New automation / code                                                                                                           | Status                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Find radio IP / confirm services                                                                                                                                                                                     | `utils/network.find_mac_in_leases()`, `discover_services()`, `get_mac_address()`                                                | **Automated**                                |
| Configure Microhard **Air**: hostname/desc; **2427 MHz**, **5 MHz**, `rainmaker`, **Slave**, **30 dBm**, **AES‑128**; LAN **DHCP client**; **Stats: 22222 @ 1000 ms, RF/RSSI/SNR/IP**; one **Save & Apply** at end.  | `config.RadioConfig` (target state) + `drivers.mh_profile` (UCI key map)                                                        | **WIP:** implement `MicrohardDriver.apply()` |
| Configure Microhard **Ground**: same RF, **Master**.                                                                                                                                                                 | Same as above                                                                                                                   | **WIP**                                      |
| UniFi adopt device; set static **10.101.252.1/16**; set name `rainmakerGCSX`; **disable 2.4 GHz**; **disable Auto‑Link**.                                                                                            | `drivers.unifi.UniFiDriver.provision()` (login/version detect, adopt, configure, disable 2.4G + auto‑optimize, read‑back guard) | **Automated**                                |
| Jetson shows online in **Tailscale**                                                                                                                                                                                 | `health.checks.check_tailscale()`                                                                                               | **Automated**                                |
| QGC UDP **14550** heartbeats + `MAV_SYS_ID` verification                                                                                                                                                             | `health.checks.check_mavlink()`; (SYSID still set via QGC or Ansible)                                                           | **Automated** (verification)                 |
| Radio Stats flowing                                                                                                                                                                                                  | `health.checks.check_radio_stats()`                                                                                             | **Automated**                                |
| Video stream confirmed                                                                                                                                                                                               | `health.checks.check_video_stream()`                                                                                            | **Automated**                                |
| PTH sensors visible                                                                                                                                                                                                  | `health.checks.check_pth_sensors()`                                                                                             | **Automated**                                |
| Record versions (Elijah/Seraph/FC)                                                                                                                                                                                   | `health.checks.check_versions()`                                                                                                | **Automated**                                |
| ESC firmware/params + motor directions                                                                                                                                                                               | `config.HitlChecklist` fields (`esc_fw_ref`, `esc_params_ref`, `motor_map_ok`)                                                  | **Tracked**, not yet programmed              |

---

## 5) Operator Workflow (what you do now)

1. **UniFi ground AP**
   Run `UniFiDriver.provision()` with credentials + site. This adopts the AP, sets the static IP/name, and disables 2.4 GHz/Auto‑Link in one step (replacing the UniFi UI section of the manual).&#x20;

2. **Microhard radios**

   * Create a `RadioConfig` (role=`AIR` or `GROUND`, drone\_id, AES key, etc.).
   * **(When `MicrohardDriver.apply()` is added)**: apply once; it will commit all UCI changes in a single “save/apply” cycle (matching the manual’s caution).&#x20;

3. **Jetson**

   * Run the **Seraph Ansible** play as usual (outside this repo).&#x20;
   * Run `HealthCheck.run_all_checks()` (providing Jetson host and, optionally, radio IP). Use the summary and `save_results()` artifact as your acceptance record.
   * If any item fails, each check’s message tells you exactly what’s missing (e.g., UDP 22222 no packets, RTSP not reachable, PTH file missing).

4. **ESC**

   * Continue using the KDEDirect procedure for now, then record the outcomes in the HITL checklist object.&#x20;

---

## 6) Notable Implementation Details (risk‑reducing)

* **Cross‑platform reachability** without `ping` variance: `ping_host()` uses TCP connects to common ports and averages RTT; works on macOS/Linux without elevated privileges. *This avoids false negatives from OS‑specific `ping` flags.* (`utils/network.py`)

* **Robust UniFi coverage:**

  * Detects **UniFi OS** vs legacy and **v6/v7/v8** API shapes; uses `/proxy/network` when needed; writes both `config_network` and `config_networks` keys to straddle version differences. (`drivers/unifi.py`)
  * Computes the **gateway** from the given static IP/netmask; not hard‑coded.

* **Safety parity with the manual:**

  * Planned Microhard driver will batch UCI commits (one write/commit/apply) to preserve the “**Save & Apply only at the end**” instruction.&#x20;

* **Auditability:** every health run writes a JSON report (timestamp, inputs, per‑check results, summary) to `~/.elijahctl/state/runs/…`. (`health/checks.py`)

* **Secrets:** stored at `~/.elijahctl/secrets.json` with **0600** permissions. (`config.Config.save_secrets()`)

---

## 7) Gaps / “Left to Implement” (with crisp next steps)

1. **MicrohardDriver (apply settings)** — implement an idempotent driver that:

   * Discovers device (via `find_mac_in_leases` or known IP).
   * Reads `uci show`, calls `detect_profile()` to get the mapping, and **writes**: role (Master/Slave), RF settings (2427/5/rainmaker/30), **AES‑128 on with key**, LAN proto `dhcp`, and **stats** enable/port 22222/interval 1000/fields RF,RSSI,SNR,AssocIP.
   * Performs **single** commit/apply and an orderly service reload.
   * Returns a structured diff for logs (before→after).
     *Why:* fully replaces the Microhard web‑UI steps.&#x20;

2. **CLI glue** for routine tasks (optional but nice):

   * `elijahctl unifi provision`
   * `elijahctl microhard apply --role air --drone-id 012 --aes-key ******`
   * `elijahctl health run --jetson el-012`
     *Why:* standardize operator entry points; they already exist as Python calls.

3. **ESC programming automation (stretch):** a small utility to template KDEDirect settings (if a controllable interface exists), or at least a checklist‑first UI that requires recording the config + motor directions per the guide.&#x20;

4. **Minor hardening in UniFi driver:**

   * Expand netmask handling beyond `/16` or `/24` so arbitrary CIDRs map to dotted masks.
   * Add retries for transient 401/CSRF resets during long sessions.

---

## 8) Acceptance: what “done” looks like for bring‑up

* **UniFi** AP shows in the controller *and* a read‑back confirms **no 2.4 GHz** WLANs are enabled; device name and **10.101.252.1/16** are set.&#x20;
* **Jetson** health report shows:

  * **Connectivity** OK, **Tailscale** Online (DNSName printed),
  * **Radio Stats** packets seen with `rssi`/`snr`,
  * **MAVLink** heartbeats at nominal rate over UDP **14550**,
  * **Video** endpoint responsive (`udp:5600` or `rtsp://`),
  * **PTH** values present,
  * **Versions** (Seraph/Elijah/FC) captured.
    *This is exactly what the manual asked you to verify at the end.*&#x20;
* **HITL checklist** saved with ESC items filled after KDEDirect steps.&#x20;

---

## 9) Summary

* **Already automated:** UniFi provisioning, discovery utilities, and all end‑to‑end *verification* (connectivity, Tailscale, MAVLink, Radio Stats, video, PTH, versions).
* **One short hop from full automation:** Microhard configuration—the profile map and config contract are done; adding `MicrohardDriver.apply()` will remove the remaining clicks from the Networking guide.&#x20;
* **Still manual:** ESC flashing/parameterization (captured via checklist).

This structure reduces operator time and variability, gives you machine‑readable artifacts for each unit, and sets us up to remove the last bits of repetitive configuration work.
