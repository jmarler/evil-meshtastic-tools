# evil-meshtastic-tools

A Python attack toolkit for demonstrating attack surface in the
[Meshtastic](https://meshtastic.org) mesh protocol, built for a DEF CON Ham
Radio Village talk. Companion to the
[evil-meshtastic-firmware](https://github.com/jmarler/evil-meshtastic-firmware).

Licensed under **GPL-3.0** (see [`LICENSE`](LICENSE)).

> ⚠️ **For education and authorized security research only.** These tools
> transmit spoofed, forged, and flooding traffic onto a mesh. Use them only on
> radios and a mesh you own or are explicitly authorized to test. Do **not**
> point them at public or shared Meshtastic networks. Interfering with radio
> communications you are not authorized to touch is illegal in most
> jurisdictions.

## Tools

| Script | Purpose |
|---|---|
| `capture.py` | Passive traffic analysis, CSV logging |
| `capture_tui.py` | Interactive Textual TUI for capture |
| `spam.py` | Message flood / duty-cycle abuse |
| `fake_position.py` | GPS position spoofing |
| `spoof.py` | Source node ID spoofing (needs evil firmware) |
| `forge.py` | AES-CTR ciphertext forgery end-to-end |
| `aes_ctr_demo.py` | Offline AES-CTR integrity-weakness demo |
| `replay.py` | Packet replay |
| `nodedb_flood.py` | NodeDB exhaustion via ghost-node injection |
| `map_poison.py` | MQTT bridge / mesh-map poisoning |
| `evil_ctrl.py` | Runtime control of the evil firmware |

Nothing here is a novel zero-day — the tools exercise **already-documented**
weaknesses of Meshtastic's PSK/AES-CTR channel model. The interesting part is how
fast a couple of non-experts built them with a coding agent.

## Run

Dependencies are managed with [uv](https://docs.astral.sh/uv/). Every script has
a `uv run` shebang with inline (PEP-723) dependencies, so you can run any tool
directly without setting up a venv:

```bash
./tools/capture.py --host 192.168.1.50      # TCP
./tools/spam.py --port /dev/ttyUSB0         # serial
```

Or set up the project venv:

```bash
uv sync
uv run tools/capture.py --help
```

All tools accept `--host <ip>` (TCP) or `--port <device>` (serial).

## Related repos

- [evil-meshtastic](https://github.com/jmarler/evil-meshtastic) — project overview
- [evil-meshtastic-firmware](https://github.com/jmarler/evil-meshtastic-firmware) — the evil firmware
- [evil-meshtastic-device-ui](https://github.com/jmarler/evil-meshtastic-device-ui) — evil operator panel

Not affiliated with or endorsed by the Meshtastic project.
