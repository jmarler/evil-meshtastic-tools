#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
evil_ctrl.py — Runtime control interface for the evil firmware (v3-evil / native-evil)

Sends EvilCtrlMsg packets (PRIVATE_APP portnum 256) addressed to the local
node. The firmware's EvilCtrlModule processes them without radio TX, updating
the runtime evil-feature state in EvilNode::state.

All features in heltec-v4-evil-full can be toggled without reflashing.
Boot defaults: transform=off, drop=0, hop=normal, flood=off.

NOTE on state semantics: every --set invocation overwrites ALL fields — any
field not specified resets to its off/zero default.  If you want multiple
features active simultaneously, specify all of them in a single --set call:
    evil_ctrl.py ... --set transform=rot13 drop=30

Usage:
    # Query current state (firmware replies via PacketAPI — no serial access needed)
    python tools/evil_ctrl.py --port /dev/cu.usbmodem4101 --evil --status

    # Enable ROT-13 text transform on relayed messages
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set transform=rot13

    # Drop 30% of relayed packets
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set drop=30

    # Force hop_limit=7 on all relayed packets (range amplifier)
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set hop=max

    # Enable ROT-13 AND drop 20%, combined in one call
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set transform=rot13 drop=20

    # Inject 50 fake nodes with public keys (immediate one-shot flood)
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set flood=on flood-count=50 flood-keys=true

    # Sync-word jam burst for 5 s (cage-only — run only on your own isolated mesh)
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set jam=on jam-ms=5000

    # Append " [EVIL]" suffix to all relayed messages
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set transform=suffix suffix=" [EVIL]"

    # Drop all packets from a specific node
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --set drop-node=0xf0f5bd4a

    # Reset all features to off
    python tools/evil_ctrl.py --port /dev/cu.SLAB_USBtoUART --evil --reset

Key=value options for --set:
    transform=off|rot13|reverse|suffix   Text transform mode (default: off)
    suffix=TEXT                          Suffix text appended when transform=suffix
    drop=0-100                           Random drop rate % (default: 0=off)
    drop-node=0xNODEID                   Silently drop all packets from node (0=off)
    drop-channel=0-254|off               Drop all packets on channel index (off=255)
    hop=normal|max|kill                  Hop limit override (default: normal)
    flood=on|off                         Trigger NodeInfo flood immediately
    flood-count=1-200                    Ghost node count (default: 50)
    flood-keys=true|false                Include fake 32-byte public keys in flood
    jam=on|off                           Trigger a sync-word jam burst immediately
    jam-ms=100-60000                     Jam burst duration (default: 5000)

Requires: heltec-v4-evil-full build (EVIL_NODE=1, all features compiled in).
"""

import argparse
import sys
import time

from common import add_connection_args, build_interface, evil_mode, print_banner

# PRIVATE_APP portnum: open range 256–511, no upstream Meshtastic conflicts
EVIL_CTRL_PORTNUM = 256

# ── Minimal protobuf/varint encoder ──────────────────────────────────────────
# EvilCtrlMsg field tags (see evil_control.pb.h):
#   1=transform  2=suffix  3=drop_rate   4=drop_node  5=drop_channel
#   6=hop_mode   7=flood   8=flood_count 9=flood_keys 10=get_status
#   11=token (fixed64, unused here)  12=is_reply  13=jam  14=jam_ms


def _varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    result = bytearray()
    while value > 127:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _field_uint32(field_num: int, value: int) -> bytes:
    """Encode a uint32 field (wire type 0). Proto3: field omitted if value == 0."""
    if value == 0:
        return b""
    return _varint((field_num << 3) | 0) + _varint(value)


def _field_bool(field_num: int, value: bool) -> bytes:
    """Encode a bool field (wire type 0). Proto3: field omitted if False."""
    if not value:
        return b""
    return _varint((field_num << 3) | 0) + b"\x01"


def _field_string(field_num: int, value: str) -> bytes:
    """Encode a string field (wire type 2, length-delimited). Omitted if empty."""
    if not value:
        return b""
    encoded = value.encode("utf-8")
    return _varint((field_num << 3) | 2) + _varint(len(encoded)) + encoded


def encode_evil_ctrl_msg(
    transform: int = 0,
    suffix: str = "",
    drop_rate: int = 0,
    drop_node: int = 0,
    drop_channel: int = 0,
    hop_mode: int = 0,
    flood: bool = False,
    flood_count: int = 0,
    flood_keys: bool = False,
    get_status: bool = False,
    jam: bool = False,
    jam_ms: int = 0,
) -> bytes:
    """
    Encode an EvilCtrlMsg as a nanopb-compatible protobuf byte string.

    Proto3 semantics: uint32 fields with value 0 are not encoded on the wire;
    the firmware decodes them as 0.  drop_channel=0 has special firmware
    handling — if drop_rate and drop_node are also 0, drop_channel is preserved.
    Use drop_channel=255 to explicitly disable channel filtering.
    """
    msg = bytearray()
    msg += _field_uint32(1, transform)
    msg += _field_string(2, suffix)
    msg += _field_uint32(3, drop_rate)
    msg += _field_uint32(4, drop_node)
    msg += _field_uint32(5, drop_channel)
    msg += _field_uint32(6, hop_mode)
    msg += _field_bool(7, flood)
    msg += _field_uint32(8, flood_count)
    msg += _field_bool(9, flood_keys)
    msg += _field_bool(10, get_status)
    msg += _field_bool(13, jam)
    msg += _field_uint32(14, jam_ms)
    return bytes(msg)


# ── Key=value parser ──────────────────────────────────────────────────────────

TRANSFORM_MAP = {"off": 0, "none": 0, "rot13": 1, "reverse": 2, "suffix": 3}
HOP_MAP       = {"normal": 0, "off": 0, "max": 1, "kill": 2}


def parse_set_args(pairs: list) -> dict:
    """
    Parse a list of KEY=VALUE strings into keyword args for encode_evil_ctrl_msg.
    Raises ValueError with a descriptive message on invalid input.
    """
    result = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"invalid KEY=VALUE pair: {pair!r}  (missing '=')")
        key, _, val = pair.partition("=")
        key = key.lower().strip()

        if key == "transform":
            v = val.lower()
            if v not in TRANSFORM_MAP:
                raise ValueError(
                    f"transform must be one of {list(TRANSFORM_MAP)}, got {val!r}"
                )
            result["transform"] = TRANSFORM_MAP[v]

        elif key == "suffix":
            if len(val.encode("utf-8")) > 63:
                raise ValueError("suffix too long (max 63 UTF-8 bytes)")
            result["suffix"] = val

        elif key == "drop":
            try:
                n = int(val)
            except ValueError:
                raise ValueError(f"drop must be an integer 0–100, got {val!r}")
            if not (0 <= n <= 100):
                raise ValueError(f"drop must be 0–100, got {n}")
            result["drop_rate"] = n

        elif key == "drop-node":
            try:
                result["drop_node"] = int(val, 0)
            except ValueError:
                raise ValueError(
                    f"drop-node must be a node ID (hex 0x... or decimal), got {val!r}"
                )

        elif key == "drop-channel":
            if val.lower() == "off":
                result["drop_channel"] = 255
            else:
                try:
                    n = int(val)
                except ValueError:
                    raise ValueError(
                        f"drop-channel must be 0–254 or 'off' (255), got {val!r}"
                    )
                if not (0 <= n <= 254):
                    raise ValueError(f"drop-channel must be 0–254, got {n}")
                result["drop_channel"] = n

        elif key == "hop":
            v = val.lower()
            if v not in HOP_MAP:
                raise ValueError(
                    f"hop must be one of {list(HOP_MAP)}, got {val!r}"
                )
            result["hop_mode"] = HOP_MAP[v]

        elif key == "flood":
            v = val.lower()
            if v in ("on", "true", "1", "yes"):
                result["flood"] = True
            elif v in ("off", "false", "0", "no"):
                result["flood"] = False
            else:
                raise ValueError(f"flood must be on/off, got {val!r}")

        elif key == "flood-count":
            try:
                n = int(val)
            except ValueError:
                raise ValueError(f"flood-count must be 1–200, got {val!r}")
            if not (1 <= n <= 200):
                raise ValueError(f"flood-count must be 1–200, got {n}")
            result["flood_count"] = n

        elif key in ("flood-keys", "flood_keys"):
            v = val.lower()
            if v in ("on", "true", "1", "yes"):
                result["flood_keys"] = True
            elif v in ("off", "false", "0", "no"):
                result["flood_keys"] = False
            else:
                raise ValueError(f"flood-keys must be true/false, got {val!r}")

        elif key == "jam":
            v = val.lower()
            if v in ("on", "true", "1", "yes"):
                result["jam"] = True
            elif v in ("off", "false", "0", "no"):
                result["jam"] = False
            else:
                raise ValueError(f"jam must be on/off, got {val!r}")

        elif key in ("jam-ms", "jam_ms"):
            try:
                n = int(val)
            except ValueError:
                raise ValueError(f"jam-ms must be an integer 100-60000, got {val!r}")
            if not (100 <= n <= 60000):
                raise ValueError(f"jam-ms must be 100-60000 (firmware clamps), got {n}")
            result["jam_ms"] = n

        else:
            raise ValueError(
                f"unknown key {key!r}.  Valid keys: "
                "transform, suffix, drop, drop-node, drop-channel, "
                "hop, flood, flood-count, flood-keys, jam, jam-ms"
            )

    return result


# ── Sending ───────────────────────────────────────────────────────────────────

def send_evil_ctrl(iface, payload: bytes, dest_node_num: int) -> None:
    """
    Send an EvilCtrlMsg payload as a PRIVATE_APP packet to dest_node_num.

    When dest == own node ID, the firmware routes this via Router::sendLocal()
    directly into the MeshModule dispatch loop (no radio TX).
    """
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2

    data = mesh_pb2.Data()
    data.portnum = EVIL_CTRL_PORTNUM
    data.payload = payload

    packet = mesh_pb2.MeshPacket()
    packet.to = dest_node_num
    packet.channel = 0
    packet.hop_limit = 0   # local delivery only
    packet.hop_start = 0
    packet.want_ack = False
    packet.decoded.CopyFrom(data)

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


# ── Status reply receiver ─────────────────────────────────────────────────────

def receive_status_reply(iface, timeout: float = 3.0) -> dict | None:
    """
    Wait up to `timeout` seconds for an EvilCtrlMsg reply (is_reply=true) on
    portnum 256. Returns a dict of state fields, or None on timeout.

    The firmware sends the reply via service->sendToPhone() over the Meshtastic
    PacketAPI USB interface — the same channel evil_ctrl.py already uses.
    This works on the production firmware (CDC_ON_BOOT=0) without any changes.
    """
    import threading

    reply_event = threading.Event()
    reply_data  = {}

    def on_receive(packet, interface):
        try:
            decoded = packet.get("decoded", {})
            if decoded.get("portnum") not in (EVIL_CTRL_PORTNUM, "PRIVATE_APP"):
                return
            raw = decoded.get("payload", b"")
            if not raw:
                return
            # Decode the EvilCtrlMsg manually (same varint parser used for encoding)
            fields = _decode_evil_ctrl_reply(raw)
            if fields.get("is_reply"):
                reply_data.update(fields)
                reply_event.set()
        except Exception:
            pass

    from pubsub import pub
    pub.subscribe(on_receive, "meshtastic.receive")
    try:
        reply_event.wait(timeout=timeout)
    finally:
        try:
            pub.unsubscribe(on_receive, "meshtastic.receive")
        except Exception:
            pass

    return reply_data if reply_data else None


def _decode_evil_ctrl_reply(raw: bytes) -> dict:
    """
    Minimal protobuf decoder for EvilCtrlMsg reply fields.
    Only decodes the fields needed for status display.
    """
    result = {}
    i = 0
    while i < len(raw):
        b = raw[i]
        i += 1
        field_num = b >> 3
        wire_type = b & 0x07

        if wire_type == 0:   # varint
            val = 0
            shift = 0
            while True:
                byte = raw[i]
                i += 1
                val |= (byte & 0x7F) << shift
                shift += 7
                if not (byte & 0x80):
                    break
            if field_num == 1:
                result["transform"] = val
            elif field_num == 3:
                result["drop_rate"] = val
            elif field_num == 4:
                result["drop_node"] = val
            elif field_num == 5:
                result["drop_channel"] = val
            elif field_num == 6:
                result["hop_mode"] = val
            elif field_num == 8:
                result["flood_count"] = val
            elif field_num == 9:
                result["flood_keys"] = bool(val)
            elif field_num == 12:
                result["is_reply"] = bool(val)
            elif field_num == 14:
                result["jam_ms"] = val

        elif wire_type == 1:  # 64-bit fixed
            i += 8  # skip token field

        elif wire_type == 2:  # length-delimited (string/bytes)
            length = 0
            shift = 0
            while True:
                byte = raw[i]
                i += 1
                length |= (byte & 0x7F) << shift
                shift += 7
                if not (byte & 0x80):
                    break
            chunk = raw[i:i + length]
            i += length
            if field_num == 2:
                result["suffix"] = chunk.decode("utf-8", errors="replace")

        else:
            break  # unknown wire type, stop parsing

    return result


# ── Display helpers ───────────────────────────────────────────────────────────

_TRANSFORM_NAMES = {0: "off", 1: "rot13", 2: "reverse", 3: "suffix"}
_HOP_NAMES       = {0: "normal", 1: "max(hop_limit=7)", 2: "kill(hop_limit=0)"}


def print_reply_summary(fields: dict) -> None:
    """Print a human-readable table of an EvilCtrlMsg status reply from the device."""
    transform    = fields.get("transform", 0)
    suffix       = fields.get("suffix", "")
    drop_rate    = fields.get("drop_rate", 0)
    drop_node    = fields.get("drop_node", 0)
    drop_channel = fields.get("drop_channel", 0)
    hop_mode     = fields.get("hop_mode", 0)
    flood_count  = fields.get("flood_count", 0)
    flood_keys   = fields.get("flood_keys", False)
    jam_ms       = fields.get("jam_ms", 0)

    t_name = _TRANSFORM_NAMES.get(transform, str(transform))
    if transform == 3 and suffix:
        t_name += f"  suffix={suffix!r}"

    dc_str = "off(255)" if drop_channel == 255 else str(drop_channel)

    print(f"    transform    : {t_name}")
    print(f"    drop         : rate={drop_rate}%  "
          f"node={'off' if drop_node == 0 else f'0x{drop_node:08x}'}  "
          f"channel={dc_str}")
    print(f"    hop_mode     : {_HOP_NAMES.get(hop_mode, hop_mode)}")
    fc = flood_count or 50
    fk = "yes" if flood_keys else "no"
    print(f"    flood        : armed  count={fc}  keys={fk}")
    print(f"    jam          : configured duration={jam_ms or 5000}ms (one-shot trigger, not persistent)")


def print_state_summary(kwargs: dict) -> None:
    """Print a human-readable table of the EvilCtrlMsg fields being sent."""
    transform    = kwargs.get("transform", 0)
    suffix       = kwargs.get("suffix", "")
    drop_rate    = kwargs.get("drop_rate", 0)
    drop_node    = kwargs.get("drop_node", 0)
    drop_channel = kwargs.get("drop_channel", 0)
    hop_mode     = kwargs.get("hop_mode", 0)
    flood        = kwargs.get("flood", False)
    flood_count  = kwargs.get("flood_count", 0)
    flood_keys   = kwargs.get("flood_keys", False)
    get_status   = kwargs.get("get_status", False)
    jam          = kwargs.get("jam", False)
    jam_ms       = kwargs.get("jam_ms", 0)

    t_name = _TRANSFORM_NAMES.get(transform, str(transform))
    if transform == 3 and suffix:
        t_name += f"  suffix={suffix!r}"

    dc_str = "off(255)" if drop_channel == 255 else str(drop_channel)

    print(f"    transform    : {t_name}")
    print(f"    drop         : rate={drop_rate}%  "
          f"node={'off' if drop_node == 0 else f'0x{drop_node:08x}'}  "
          f"channel={dc_str}")
    print(f"    hop_mode     : {_HOP_NAMES.get(hop_mode, hop_mode)}")
    if flood:
        print(f"    flood        : TRIGGER  count={flood_count or 50}  "
              f"keys={'yes' if flood_keys else 'no'}")
    else:
        print(f"    flood        : off")
    if jam:
        print(f"    jam          : TRIGGER  duration={jam_ms or 5000}ms")
    else:
        print("    jam          : off")
    if get_status:
        print(f"    get_status   : true  (check device serial for log output)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Send runtime control commands to the evil firmware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Requires:")[0].strip(),
    )
    add_connection_args(parser)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--status",
        action="store_true",
        help="Query current evil state. Firmware sends a reply packet via PacketAPI "
             "and evil_ctrl.py displays it — no serial port or debug firmware needed.",
    )
    mode.add_argument(
        "--set",
        nargs="+",
        metavar="KEY=VALUE",
        help="Set evil node state (see KEY=VALUE options in usage above)",
    )
    mode.add_argument(
        "--reset",
        action="store_true",
        help="Reset ALL evil features to off/zero defaults",
    )

    args = parser.parse_args()

    if not evil_mode(args):
        print("[!] WARNING: --evil not specified.")
        print("[!] EvilCtrlMsg requires evil firmware (EVIL_NODE=1).")
        print()

    print("[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    info, node_num = print_banner(iface, args, "evil_ctrl.py — runtime evil feature control")
    print()

    # ── Build the kwargs dict based on chosen mode ──────────────────────────
    if args.status:
        kwargs = {"get_status": True}

    elif args.reset:
        # Explicitly set all fields to their safe off/zero defaults.
        # drop_channel=255 is the "disabled" sentinel; sending 0 would mean
        # "drop packets on channel 0", so we must encode 255 explicitly.
        kwargs = {
            "transform":    0,
            "suffix":       "",
            "drop_rate":    0,
            "drop_node":    0,
            "drop_channel": 255,
            "hop_mode":     0,
            "flood":        False,
            "flood_count":  0,
            "flood_keys":   False,
            "get_status":   False,
            "jam":          False,
            "jam_ms":       0,
        }
        print("[*] Resetting all evil features to off:")

    else:  # --set
        try:
            kwargs = parse_set_args(args.set)
        except ValueError as e:
            print(f"[!] --set parse error: {e}", file=sys.stderr)
            sys.exit(1)
        print("[*] Setting evil state:")

    if not args.status:
        print_state_summary(kwargs)
        print()

    # ── Encode and send ─────────────────────────────────────────────────────
    payload = encode_evil_ctrl_msg(**kwargs)
    print(f"[*] Encoded payload: {len(payload)} bytes  [{payload.hex()}]")

    if args.status:
        # Subscribe before sending so we don't miss a fast reply
        import threading
        _reply_event = threading.Event()
        _reply_data  = {}

        def _on_status(packet, interface):
            try:
                dec = packet.get("decoded", {})
                if dec.get("portnum") not in (EVIL_CTRL_PORTNUM, "PRIVATE_APP"):
                    return
                raw = dec.get("payload", b"")
                if not raw:
                    return
                fields = _decode_evil_ctrl_reply(raw)
                if fields.get("is_reply"):
                    _reply_data.update(fields)
                    _reply_event.set()
            except Exception:
                pass

        from pubsub import pub
        pub.subscribe(_on_status, "meshtastic.receive")

    send_evil_ctrl(iface, payload, node_num)
    print(f"[*] Sent to 0x{node_num:08x} on portnum={EVIL_CTRL_PORTNUM} (PRIVATE_APP)")

    if args.status:
        print("[*] Waiting for status reply from device (up to 3 s)...")
        _reply_event.wait(timeout=3.0)
        try:
            pub.unsubscribe(_on_status, "meshtastic.receive")
        except Exception:
            pass
        reply = _reply_data if _reply_data else None
        if reply:
            print("[*] Device state:")
            print_reply_summary(reply)
        else:
            print("[!] No reply received — check that the firmware is built with "
                  "Phase 4.1.7 changes and the device is running heltec-v4-evil-full.")

    iface.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()
