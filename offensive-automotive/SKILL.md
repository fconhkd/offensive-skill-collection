---
name: offensive-automotive
description: "Automotive / vehicle pentest methodology for authorized engagements. Covers CAN/CAN-FD/LIN/FlexRay/Automotive Ethernet, UDS (ISO 14229) and OBD-II diagnostics, ECU firmware extraction and reflashing, keyfob attacks (rolling code, PKE relay, RollJam), TPMS, IVI/telematics (Bluetooth/Wi-Fi/cellular/V2X), EV charging (CCS, CHAdeMO, OCPP, ISO 15118), ADAS sensor attacks, in-lab tooling (can-utils, SavvyCAN, ICSim, Caring Caribou, comma.ai panda, CANtact, Kvaser, Vector), and ISO/SAE 21434 + UN R155 alignment. Use when scoping or executing pentests against vehicles, ECUs, telematics units (TCUs), infotainment, EV charging stations, or aftermarket automotive components."
---

# Offensive Automotive

## Engagement Rules — Read First

Vehicle testing has unique safety/legal constraints. Confirm in writing before any active test:

- **Never on public roads.** Test on a dyno, lift, jack stands, or closed track. Driver-assist/braking/steering manipulation can kill.
- **Lab vehicle or sacrificial ECU bench.** Never the customer's daily driver unless ROE explicitly covers it.
- **Bricking risk.** UDS reflash, security access brute, and bootloader pokes can permanently disable an ECU. Get a "spare ECU OK to brick" line in scope.
- **Safety-critical buses.** Powertrain CAN, chassis CAN, ADAS, airbag — fault injection here is potentially lethal. Escalate before active probing.
- **Local law.** US: DMCA §1201 has a vehicle-research exemption (renewed) but only for **owned** vehicles, off public roads, no telematics/subscription bypass redistribution. EU: varies by member state, EU R155 makes OEMs responsible for security but does not authorize third-party testing. BR: LGPD applies to any personal data on telematics; CFB owner consent required.
- **Standards landscape:** ISO/SAE 21434 (cyber engineering), UN R155 (type approval), UN R156 (SUMS), SAE J3061, Auto-ISAC TSPs.

## Attack Surface Map

```
                       ┌─ Cellular (4G/5G) ─┐
                       ├─ Wi-Fi / Hotspot ──┤
   REMOTE ─────────────┼─ Bluetooth / BLE ──┼──── TCU / Head Unit (IVI)
                       ├─ V2X (DSRC/C-V2X) ─┤            │
                       └─ Companion App ────┘            │
                                                         │ (Ethernet/CAN gateway)
   PROXIMITY ──── Keyfob (RKE/PKE), TPMS, NFC ───┐       │
                                                 │       │
   PHYSICAL ──── OBD-II, USB, SD, JTAG/UART ─────┴── Central Gateway ──┬── Powertrain CAN
                                                                       ├── Chassis CAN
                                                                       ├── Body CAN / LIN
                                                                       ├── ADAS CAN-FD / Eth
                                                                       └── Diag CAN (OBD)
   CHARGING ──── CCS / CHAdeMO / Type 2 / NACS / OCPP / ISO 15118 ── BMS/OBC
```

Map each surface in scope. Most modern OEMs run **CAN + CAN-FD + Automotive Ethernet (100/1000BASE-T1)** behind a central gateway; the OBD port usually only sees a sanitized diag bus.

## Phase 1 — Recon & Bus Mapping

### Identify buses and ECUs
- **Service manual / wiring diagram** (AllData, Mitchell1, OEM TIS) — best source for bus topology and ECU list.
- **VIN decode** → trim → ECU population (PCM, BCM, TCU, ABS, EPS, ESP, ACU, etc.).
- **OBD-II pinout (SAE J1962):** pin 6 = CAN-H, pin 14 = CAN-L, pin 16 = +12V, pin 4/5 = GND, pin 1/8/9/11/12/13 = OEM-specific (frequently a second CAN, MS-CAN, or K-line).
- **MS-CAN / SW-CAN / LIN** often live on auxiliary OBD pins.

### Passive sniffing first
```bash
# Linux SocketCAN bring-up (USB2CAN, CANtact, comma panda, PCAN-USB)
sudo ip link set can0 up type can bitrate 500000          # classic CAN
sudo ip link set can0 up type can bitrate 500000 dbitrate 2000000 fd on sample-point .8 dsample-point .75   # CAN-FD

candump -tz can0                                          # raw frames + delta time
candump -L can0 > drive.log                               # log replayable format
canbusload can0@500000 -r -t -b -c                        # bus utilization
cansniffer can0                                           # diff view (great for finding the bit you flipped)
```

### Diff-driven reverse engineering
1. `candump -L` while pressing/operating the target function (e.g., unlock, window, blinker) bracketed by idle.
2. Replay subset to confirm: `canplayer -I drive.log can0=can0`.
3. Narrow with `cansniffer` filtering, or import to **SavvyCAN** (best UI for hash diff, reverse-engineering, replay, ISO-TP).
4. Decode signals by toggling and watching bytes. Build a DBC. Tools: SavvyCAN → DBC export, **Kayak**, **Cabana** (comma.ai), **CANalyzer** (Vector, commercial).

## Phase 2 — Bus-Level Attacks (Classic CAN)

CAN has **no authentication, no encryption** by design. Defenses are gateway filtering, MAC layers (SecOC/AUTOSAR), and IDS.

### Frame injection
```bash
cansend can0 123#DEADBEEF                                 # single frame
cangen can0 -I 123 -L 8 -D r -g 10                        # generated traffic
canplayer -I unlock.log can0=can0                         # replay captured cmd
```

### DoS / bus-off
- **Error frame flood**: continuously transmit dominant bits to force target ECU into bus-off (TEC/REC > 255).
- **Higher-priority spam**: flood ID `0x000` to starve lower-priority traffic.
- Both are **safety-critical** — only on isolated bench.

### MAC bypass / SecOC weaknesses (AUTOSAR Secure Onboard Communication)
- Look for: replay window too large, freshness counter not in MAC, truncated MAC (<32 bits), shared key per bus instead of per ECU pair.
- Tools: extract key from ECU flash (Phase 5), then forge with valid MAC.

### Gateway bypass
- Pivot through an ECU on diag bus that has **routing privileges** to internal buses (TCU and head unit are common pivots).
- Look for **debug messages** the gateway forwards (J1939 PGN passthrough, manufacturer tester routines).

## Phase 3 — UDS (ISO 14229) Diagnostics

UDS rides over ISO-TP (ISO 15765-2) on CAN/CAN-FD or DoIP (ISO 13400) on Ethernet. **The richest attack surface on most ECUs.**

### Common Service IDs

| SID | Service | Notes |
|-----|---------|-------|
| 0x10 | DiagnosticSessionControl | 0x01 default, 0x02 programming, 0x03 extended, 0x40+ OEM (often unlocks features) |
| 0x11 | ECUReset | 0x01 hard, 0x02 keyOff, 0x03 soft |
| 0x14 | ClearDTC | |
| 0x19 | ReadDTCInformation | |
| 0x22 | ReadDataByIdentifier | DID enumeration goldmine |
| 0x23 | ReadMemoryByAddress | Often gated by securityAccess |
| 0x27 | SecurityAccess | Seed/key — frequent crypto fail |
| 0x28 | CommunicationControl | Disable normal comms (DoS) |
| 0x29 | Authentication | UDS 2020+ certificate-based |
| 0x2E | WriteDataByIdentifier | Coding / VIN write / odometer (illegal IRL) |
| 0x2F | InputOutputControlByID | Actuator drive — turn on solenoids, fuel pump etc. |
| 0x31 | RoutineControl | OEM routines (key learn, immobilizer, calibration) |
| 0x34/35/36/37 | Request/TransferData/Exit | Reflash flow |
| 0x3D | WriteMemoryByAddress | RAM / flash write |
| 0x3E | TesterPresent | Keepalive |
| 0x85 | ControlDTCSetting | |
| 0x87 | LinkControl | Switch baud |

### Service enumeration
```python
# python-can + udsoncan
import udsoncan, udsoncan.client, isotp
from udsoncan.connections import PythonIsoTpConnection
from can.interface import Bus

bus = Bus(channel='can0', interface='socketcan')
addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=0x7E0, rxid=0x7E8)
stack = isotp.CanStack(bus, address=addr)
conn = PythonIsoTpConnection(stack)

with udsoncan.client.Client(conn, request_timeout=2) as c:
    c.change_session(0x03)                  # extended diag
    for sid in range(0x10, 0xFF):
        try:
            r = c.send_request(udsoncan.Request(service=udsoncan.services.UDSService(sid)))
            print(hex(sid), r)
        except Exception as e:
            pass
```

Or `caringcaribou uds discovery` / `uds services` for fast bulk scan.

### Caring Caribou (CC) — go-to UDS tool
```bash
cc.py uds discovery                      # find ECU diag IDs
cc.py uds services 0x7E0 0x7E8           # enum supported SIDs
cc.py uds dtc 0x7E0 0x7E8                # read DTCs
cc.py uds dump_dids 0x7E0 0x7E8 0 0xFFFF # DID enumeration
cc.py uds security_seed 0x7E0 0x7E8 -lvl 1   # collect seeds
cc.py uds testerpresent 0x7E0
cc.py uds memory_dump 0x7E0 0x7E8 -addr 0 -len 0x100000
cc.py xcp ...                            # bonus: XCP attacks (calibration protocol)
```

### SecurityAccess (SID 0x27) attacks
The seed/key handshake. Common fails:

- **Constant key** (`key = seed XOR const`, or `key = const`): test by requesting same level repeatedly, look at seed/key relation.
- **Linear / weak transform** (LFSR, byte rotation, CRC): brute the transform with a few seed/key pairs.
- **Algorithm in firmware** (it always is). Pull firmware (Phase 5), find the seed→key function (hint: called from UDS handler at SID 0x27), reimplement.
- **Time-attack on lockout**: many ECUs lock for 10s after 3 fails — but power-cycle resets the counter on lots of older ECUs.
- **Default tester key files** leak from OEM dealer tools (J2534 DLLs, OEM diag apps). Worth searching.

### DID / Memory dumping
- Sweep `0x22` over the full DID range (`0x0000`–`0xFFFF`), tag positives.
- Attack `0x23` ReadMemoryByAddress with educated guesses (flash base, RAM base from CPU datasheet).
- After SecurityAccess, `0x23` often dumps the whole flash unauthenticated *for the duration of the session*.

### Reflash flow (0x34 → 0x36 → 0x37)
1. Switch to programming session 0x10 0x02.
2. SecurityAccess at programming level (often a different level than diag).
3. `0x34 RequestDownload` with addr+size.
4. `0x36 TransferData` chunks.
5. `0x37 RequestTransferExit`.
6. `0x31 RoutineControl` with checksum/erase routines.

Hijacking this: forge a TransferData with malicious code if the integrity check is CRC-only or not signed. Modern ECUs use **HSM-signed** flashware (UDS over MAC, signed with OEM keypair). Look for legacy ECUs in scope.

## Phase 4 — Other Bus Systems

### LIN (Local Interconnect Network)
Single-wire, master/slave, 19.2 kbps. Body/comfort domain (windows, mirrors, seats, sunroof). No security at all.
- HW: LIN transceiver (TJA1021), MCP2004, or CANtact-LIN. Microchip MCP2025 dev boards work.
- Spoof master breaks; impersonate slave to fake sensor values.
- Tools: **PyLin**, **LIN-Bus-Sniffer**, custom Arduino+TJA1021.

### FlexRay
Time-triggered, 10 Mbps, dual-channel. Used in chassis (steering, braking) on luxury Euro brands (BMW, Audi).
- HW: Vector VN7572 / VN8912 (commercial only), Eberspächer FlexRay tooling.
- Synchronization is the gate — passive sniffing easy, injection requires being in a static slot.
- Caring Caribou has limited FlexRay support; mostly Vector CANalyzer in practice.

### Automotive Ethernet (100/1000BASE-T1, single-pair)
SOME/IP, AVB/TSN, DoIP. Found between ADAS, IVI, and central gateway.
- HW media converter: **Intrepid RAD-Moon** / **Technica MediaConverter** / **ESI-Mini** (need 100BASE-T1 ↔ 100BASE-TX).
- Once on the wire: Wireshark with SOME/IP dissector, Nmap, normal IP recon.
- **DoIP (ISO 13400, port 13400/UDP and 13400/TCP)**: UDS over Ethernet — same SecurityAccess attacks at line speed.
- Common find: SOME/IP services with no authentication doing internal RPC.

### CAN-FD specific
- Up to 5 Mbps in data phase, payload up to 64 B.
- Most attacks identical to classic CAN; tooling needs CAN-FD-capable HW (PCAN-USB FD, Kvaser Memorator, comma.ai panda red, CANtact Pro).

## Phase 5 — ECU Hardware Attacks (Bench)

Pull the ECU. The host MCU is usually:
- **Infineon AURIX (TC2xx/TC3xx)** — TriCore, dominant powertrain
- **NXP MPC5xxx (Power Architecture) / S32K (ARM Cortex-M)** — chassis, body
- **Renesas RH850 / V850** — Toyota/Honda/Mazda powertrain
- **STM32 / TI Hercules / NXP S32G** — newer ADAS/zonal

### Workflow
1. **Open the ECU** (often potted — careful with picks/heat).
2. **Identify chips**: MCU, external flash (SPI NOR like W25Q*, MX25L*, S25FL*), EEPROM, transceivers.
3. **Look for debug interfaces**: JTAG (TDI/TDO/TCK/TMS/TRST), SWD (SWDIO/SWCLK), DAP, BDM, Aurora, custom OEM. Use **JTAGulator** or **JTAGenum** to find pinout.
4. **Bootmode pins**: pulling a pin during reset often forces ROM bootloader, which exposes a serial download interface (STM32 system bootloader, TriCore SSW, MPC5xxx BAM, Kinetis MSCAN-bootloader).
5. **Firmware extraction methods (in order of preference):**
   - Debug interface (JTAG/SWD) if not fused → **OpenOCD**, **PEmicro**, **Lauterbach Trace32**, **Segger J-Link**.
   - In-circuit SPI flash dump → **flashrom -p ch341a_spi**, or desolder + XGecu T48 / RT809F.
   - UDS ReadMemoryByAddress after SecurityAccess (Phase 3).
   - Bootloader exploit (BadUSB on STM32 system bootloader CVE-class, MPC5xxx BAM commands).
   - **Voltage glitching / EM fault injection** to bypass readout protection — **ChipWhisperer**, **PicoEMP**, **Riscure Inspector** (commercial).

### Glitching cheat sheet (ChipWhisperer)
- Target: defeat fuse check during boot (RDP1→RDP0 on STM32, JTAG-disable on TriCore HSM).
- Trigger: power-up edge or first I/O event.
- Sweep: width (~10–500 ns), offset (post-trigger), voltage (drop to ~0.6×Vcc).
- Glitch the **branch** that reads the fuse, not the fuse itself.

### Static analysis after dump
- **Ghidra** / **IDA Pro** with TriCore/PowerPC/RH850/V850 processor modules.
- Strings → find UDS handlers (`0x27`, seed text, OEM error codes).
- Cross-ref to find SecurityAccess algorithm and key material.
- Look for **HSM** (Hardware Security Module) firmware separately — usually a sub-MCU or core (Infineon HSM, Bosch CSM). HSM keys are typically locked away; attacking them = side-channel territory.

## Phase 6 — Wireless: Keyfob, TPMS, BLE, V2X

### RKE (Remote Keyless Entry) — passive press-button
- 315 MHz (US/JP), 433.92 MHz (EU/BR), 868 MHz (some EU). Some 902–928 MHz.
- Modulation: ASK/OOK or FSK. Encoding: Manchester, PWM.
- HW: **HackRF One**, **bladeRF**, **YARDStick One** (Sub-GHz), **CC1101** modules, **Flipper Zero** (good triage tool).
- Capture: `gqrx`, `urh` (Universal Radio Hacker — best for protocol RE), `inspectrum`.
- **Rolling code (KeeLoq, Hitag2, AES-rolling)**: replay fails by design. Attacks:
  - **RollJam** (Kamkar): jam fob channel, capture transmission N, let user retry (transmission N+1), forward N to car, keep N+1 to use later.
  - **KeeLoq key recovery**: side-channel against manufacturer key (Eisenbarth/Kasper 2008). Mostly historic but still in low-end aftermarket.
  - **Hitag2**: cryptanalysis published, practical attacks on older VAG/Renault/Ford. `RFCat` + `pyhitag2`.
- **Rolling code RNG bias**: some implementations have weak counters or replay window > 256 — capture a bunch and replay forward.

### PKE (Passive Keyless Entry) — walk-up unlock
- LF (125 kHz) wakeup from car → UHF response from fob.
- **Relay attack**: two SDRs/repeaters bridge the LF and UHF channels. Effective range: 100m+. Defeats most pre-2020 fobs.
  - HW: paired 125 kHz amplifier + 433/868 MHz transceiver, or commercial "key extender" device.
- **Mitigations to look for in test**: UWB ranging (Apple AirTag-style), motion sleep on fob, BLE with PSM, time-of-flight check.

### TPMS (Tire Pressure Monitoring)
- 315/433 MHz, FSK, manufacturer-specific protocol (Schrader, Continental, Pacific, etc.).
- Each sensor has unique 32-bit ID transmitted in clear with pressure/temp.
- Attacks:
  - **Tracking** — IDs are stable, allow vehicle tracking.
  - **Spoofing** — fake low-pressure to trigger warnings; some research shows ECU memory corruption via malformed packets.
- Tools: `rtl_433` (decoder for many TPMS protocols), `URH`.

### Bluetooth / BLE in IVI / TCU
Standard BLE attack surface — see GATT enum, pairing downgrades, KNOB, BIAS. Specific to auto:
- Phone-as-key (Tesla, BMW Digital Key, CCC Digital Key 3.0): UWB + BLE. UWB ranging vulnerabilities published (Tesla Model 3 relay attack via BLE, 2022).
- IVI Bluetooth often runs vendor stacks (BlueZ, custom) with HFP/A2DP/AVRCP — fuzz with `bluetoothctl` + `BSS` (Bluetooth Stack Smasher).

### Cellular / Telematics (TCU)
- IMSI catching only with proper authorization + spectrum license.
- Attack the **backend API** the TCU talks to — it's just HTTPS with mTLS or token auth. Pull TCU firmware (Phase 5) → extract certs/keys → impersonate vehicle to backend. Past finds: vehicle-to-vehicle command via tenant-ID confusion (Sam Curry et al. OEM API research, 2022–2023).
- **MQTT** is common between TCU and OEM cloud — look for shared creds, broker ACL bypass, wildcard topic subscribe.

### V2X (DSRC 802.11p / C-V2X PC5)
- HW: Cohda MK6, Autotalks, Qualcomm 9150 C-V2X.
- Messages: BSM (US, SAE J2735), CAM/DENM (EU, ETSI). Signed with IEEE 1609.2 certificates.
- Attacks: misbehavior reports, bogus certificate enrollment via SCMS, geo-spoofed BSMs causing AEB phantom braking.

## Phase 7 — IVI / Head Unit

Modern IVI is Linux (AGL, Yocto, Android Automotive) or QNX. Treat as embedded Linux + mobile pentest hybrid.

- **USB attack surface**: file system parsers (mp3/flac/jpg/usb-mass-storage), Apple CarPlay (USB iAP2 + ConfigFS gadget), Android Auto (AOAP).
- **Wi-Fi hotspot**: weak default WPA2-PSK from VIN/serial, exposed services on hotspot SSID.
- **Bluetooth PBAP/MAP** — phone book + SMS sync, often parsed by old libraries.
- **App store / installable apps** (Tesla, Polestar, Android Automotive Play Store) — sandbox escape research.
- **Pivot to gateway**: head unit usually has Ethernet to gateway. Once code-exec on IVI → SOME/IP / DoIP / CAN injection.

## Phase 8 — EV Charging

### Vehicle side (OBC / BMS)
- **CCS (Combined Charging System)**: PLC over Control Pilot (HomePlug GreenPHY) carrying ISO 15118 (or DIN 70121 legacy).
- **ISO 15118-2** (current widely deployed): TLS optional, X.509 certs for Plug & Charge. Lots of stacks ship with **demo CA / test certs**.
- **ISO 15118-20** (new): mandatory mutual TLS, bidirectional, V2G.
- **CHAdeMO**: CAN-based, lighter spec, fewer published attacks but reachable from charger side.
- **NACS (Tesla)**: now SAE J3400, similar flow.

Attack ideas (lab):
- MITM on Control Pilot PLC (need GreenPHY HomePlug device — **Codico QCA7000** dev boards, **switchEV V2G EVSE/PEV simulator**).
- TLS downgrade if both sides allow legacy DIN 70121.
- Identity spoofing via test PKI.

### Charger / EVSE side
- **OCPP 1.6 / 2.0.1** (Open Charge Point Protocol): JSON over WebSocket between charger and CSMS.
- 1.6 frequently runs **without TLS** in field deployments. Auth = endpoint URL + ID. Trivially spoofable.
- 2.0.1 mandates security profiles 2/3 (TLS + client cert) but adoption mixed.
- Tools: **MobilityHouse OCPP**, **SteVe** (test CSMS), **OCPP-Fuzzer** projects.
- Common finds: anonymous WebSocket endpoint, message replay (start/stop transaction for any RFID), command injection in firmware update URLs, default credentials on admin web UI.

## Tooling Reference

### Hardware
| Tool | Use | $ Tier |
|------|-----|--------|
| comma.ai panda | CAN/CAN-FD/Eth, Linux-friendly, cheap | $ |
| CANtact / CANtact Pro | SocketCAN, CAN-FD | $ |
| USB2CAN | Cheap classic CAN | $ |
| Macchina M2 | OBD-II + dev shield | $$ |
| PCAN-USB FD | Pro classic+FD | $$ |
| Kvaser Memorator / U100 | Pro logging, multi-bus | $$$ |
| Vector VN1640 / VN5640 | Industry standard, CAN/LIN/FlexRay/Eth | $$$$ |
| Intrepid RAD-Galaxy | Multi-protocol gateway logger | $$$$ |
| Tech2 / VCM2 / OEM scan tool | Trusted-tester routines | varies |
| HackRF One | RF capture/replay 1MHz–6GHz | $ |
| YARDStick One | Sub-GHz fobs | $ |
| Flipper Zero | Triage RF/NFC/IR | $ |
| ChipWhisperer-Lite/Husky | Glitching, side-channel | $$ |
| JTAGulator | Debug pin discovery | $ |
| Saleae Logic Pro 16 | Logic analyzer (UART/SPI/I2C/CAN) | $$ |

### Software
| Tool | Purpose |
|------|---------|
| can-utils (`candump`, `cansend`, `canplayer`, `cansniffer`, `canbusload`, `isotpsend`, `isotprecv`) | SocketCAN swiss army |
| SavvyCAN | GUI: capture, RE, ISO-TP, DBC, scripting |
| Caring Caribou (`cc.py`) | UDS, XCP, ISO-TP discovery & attacks |
| python-can / udsoncan / isotp / canmatrix | Python automation |
| ICSim (OpenGarages) | Practice CAN target with HUD |
| Kayak / Cabana | DBC viewer/editor |
| URH (Universal Radio Hacker) | RF protocol RE |
| rtl_433 | TPMS / sub-GHz decoders |
| GNU Radio | Custom RF chains |
| OpenOCD / J-Link / Trace32 | JTAG/SWD/BDM debug |
| Ghidra (with TriCore/RH850/PowerPC SLEIGH) | Static RE |
| Wireshark + SOME/IP / DoIP / OCPP dissectors | Eth analysis |
| Metasploit `hwbridge` | RF/CAN module integration |

### Practice ranges (legal, free)
- **OpenGarages ICSim** — Linux SocketCAN simulator
- **Car Hacking: The Mercedes-Benz CTF** archives, **DEF CON Car Hacking Village CTFs**
- **Synacktiv automotive challenges**, **Pwn2Own Automotive** writeups
- **CANCAT** sample logs
- **TrustZone Auto** lab images

## Reporting

- Map every finding to **MITRE ATT&CK for Embedded** + **Auto-ISAC TSP** category.
- For ISO/SAE 21434 customers, include **TARA delta** (threats discovered vs registered).
- Always include: bus, ECU, attack precondition (e.g., requires OBD physical access vs remote), safety impact rating (no-impact / non-safety / safety-relevant / safety-critical), reproduction steps.
- Coordinate disclosure through Auto-ISAC for Tier-1/OEM bugs; expect 90+ day windows due to type-approval re-cert (UN R155).

## Quick Triage Checklist

When you sit down at a vehicle/ECU with limited time:

1. Identify in-scope buses, get on the wire passively (`candump -tz`, `canbusload`).
2. Run UDS discovery: `cc.py uds discovery` → for each ECU: `services` and `dump_dids`.
3. Diff-replay safety-irrelevant body functions (door lock, windows, blinkers) to validate primitives.
4. Probe SecurityAccess at every supported level — collect 100+ seeds, look for repetition / structure.
5. If physical: enumerate JTAG/SWD/UART with JTAGulator; check bootmode pins.
6. Wireless: scan 315/433/868/2400 MHz with HackRF + URH; capture key press / TPMS.
7. If IVI/TCU in scope: enumerate Bluetooth services, hotspot, USB filesystems.
8. Charging: start a session with SteVe / open15118 simulator, see what the charger accepts.
9. Document non-destructive finds; gate destructive (reflash, glitching, bus-off) behind explicit go/no-go from customer.
