#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
#   "pypubsub",
#   "pycryptodome",
# ]
# ///
"""
capture.py — Meshtastic passive traffic analysis tool

Listens to a node's radio receive stream and logs all packet headers.
All logged fields are UNENCRYPTED — visible to any observer without key material.

What this demonstrates:
  - Full traffic analysis without any PSK knowledge
  - Source/destination node IDs, routing topology, hop counts
  - MQTT vs RF origin (via_mqtt flag)
  - Message timing and frequency patterns
  - Channel hash (identifies channel without knowing its name)
  - Packet IDs (partially predictable: lower 10 bits are rolling counter)

Optional: if --psk is provided, also decrypts payload and logs plaintext.

Output:
  One line per packet with CSV-compatible format (also writes to --log if given)

Usage:
    # Passive sniff with header-only analysis
    python tools/capture.py --port /dev/cu.SLAB_USBtoUART

    # With default PSK decryption
    python tools/capture.py --port /dev/cu.SLAB_USBtoUART --decrypt-default

    # Log to file
    python tools/capture.py --port /dev/cu.SLAB_USBtoUART --log capture.csv
"""

import argparse
import csv
import datetime
import sys
import time
import signal
import struct

from pubsub import pub

import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface


# Default channel PSK: the well-known 16-byte AES-128 key that backs "AQ==" alias
# From Channels.h: defaultpsk[]
DEFAULT_PSK = bytes(
    [
        0xD4,
        0xF1,
        0xBB,
        0x3A,
        0x20,
        0x29,
        0x07,
        0x59,
        0xF0,
        0xBC,
        0xFF,
        0xAB,
        0xCF,
        0x4E,
        0x69,
        0x01,
    ]
)


def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-CTR encryption/decryption (symmetric). Matches Meshtastic's encryptAESCtr()."""
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
    return cipher.encrypt(data)


def meshtastic_nonce(packet_id: int, from_node: int) -> bytes:
    """
    Construct the 16-byte AES-CTR nonce used by Meshtastic.
    nonce = packetId (uint64 LE) || fromNode (uint32 LE) || 0x00000000 (uint32 LE)
    """
    return struct.pack(
        "<QII", packet_id & 0xFFFFFFFFFFFFFFFF, from_node & 0xFFFFFFFF, 0
    )


def fmt_position(pos_dict: dict) -> str | None:
    """Format a position dict (from the meshtastic library's decoded packet) as a readable string."""
    lat_i = pos_dict.get("latitudeI")
    lon_i = pos_dict.get("longitudeI")
    if not lat_i and not lon_i:
        return None
    lat = lat_i / 1e7
    lon = lon_i / 1e7
    alt = pos_dict.get("altitude")
    alt_str = f" alt={alt}m" if alt else ""
    return f"pos={lat:.6f},{lon:.6f}{alt_str}"


def try_decrypt(psk: bytes, packet: dict) -> str | None:
    """Attempt to decrypt a packet payload using the provided PSK."""
    try:
        import meshtastic.protobuf.mesh_pb2 as mesh_pb2
        import meshtastic.protobuf.portnums_pb2 as portnums_pb2

        raw = packet.get("raw")
        if raw is None:
            return None
        # The Python library decodes for us — if packet is already decoded, payload is in decoded
        if raw.HasField("decoded"):
            decoded = raw.decoded
            portnum = decoded.portnum
            if portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                return decoded.payload.decode("utf-8", errors="replace")
            elif portnum == portnums_pb2.PortNum.POSITION_APP:
                pos = mesh_pb2.Position()
                pos.ParseFromString(decoded.payload)
                lat = pos.latitude_i / 1e7
                lon = pos.longitude_i / 1e7
                alt_str = f" alt={pos.altitude}m" if pos.altitude else ""
                return f"pos={lat:.6f},{lon:.6f}{alt_str}"
            else:
                return f"<portnum={portnum} len={len(decoded.payload)}>"
        # If packet is still encrypted (e.g., unknown channel), try manual decrypt
        if len(raw.encrypted) > 0:
            packet_id = packet.get("id", 0)
            from_node = packet.get("from", 0)
            nonce = meshtastic_nonce(packet_id, from_node)
            plaintext_bytes = aes_ctr_crypt(psk, nonce, raw.encrypted)
            # Try to decode as a Data protobuf
            data_pb = mesh_pb2.Data()
            data_pb.ParseFromString(plaintext_bytes)
            if data_pb.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                return data_pb.payload.decode("utf-8", errors="replace")
            elif data_pb.portnum == portnums_pb2.PortNum.POSITION_APP:
                pos = mesh_pb2.Position()
                pos.ParseFromString(data_pb.payload)
                lat = pos.latitude_i / 1e7
                lon = pos.longitude_i / 1e7
                alt_str = f" alt={pos.altitude}m" if pos.altitude else ""
                return f"pos={lat:.6f},{lon:.6f}{alt_str}"
            return f"<portnum={data_pb.portnum} len={len(data_pb.payload)}>"
    except Exception:
        pass
    return None


def hops_away(packet: dict) -> int | None:
    """Calculate hops_away = hop_start - hop_limit (both from cleartext header)."""
    hop_limit = packet.get("hopLimit")
    hop_start = packet.get("hopStart")
    if hop_limit is not None and hop_start is not None:
        return hop_start - hop_limit
    return None


class Capture:
    def __init__(self, psk=None, log_path=None, verbose=False):
        self.psk = psk
        self.verbose = verbose
        self.count = 0
        self.log_file = None
        self.csv_writer = None
        if log_path:
            self.log_file = open(log_path, "w", newline="")
            self.csv_writer = csv.writer(self.log_file)
            self.csv_writer.writerow(
                [
                    "timestamp",
                    "packet_id",
                    "from_hex",
                    "to_hex",
                    "channel_hash",
                    "hop_limit",
                    "hop_start",
                    "hops_away",
                    "via_mqtt",
                    "snr",
                    "rssi",
                    "portnum",
                    "payload_len",
                    "plaintext",
                    "lat",
                    "lon",
                    "alt",
                ]
            )

    def on_receive(self, packet, interface):
        self.count += 1
        ts = datetime.datetime.now().isoformat(timespec="milliseconds")

        from_node = packet.get("from", 0)
        to_node = packet.get("to", 0)
        from_id = packet.get("fromId", f"!{from_node:08x}")
        packet_id = packet.get("id", 0)
        channel = packet.get("channel", 0)
        hop_limit = packet.get("hopLimit", "?")
        hop_start = packet.get("hopStart", "?")
        via_mqtt = packet.get("viaMqtt", False)
        snr = packet.get("rxSnr", "?")
        rssi = packet.get("rxRssi", "?")
        ha = hops_away(packet)

        decoded = packet.get("decoded", {})
        portnum = decoded.get("portnum", "?")
        payload_len = len(decoded.get("payload", b"") or b"")

        plaintext = None
        lat = lon = alt = None
        if self.psk:
            plaintext = try_decrypt(self.psk, packet)
        elif "decoded" in packet:
            if "text" in decoded:
                plaintext = decoded.get("text")  # library decoded text message for us
            elif "position" in decoded:
                # Library decoded a position packet — extract coordinates directly
                pos = decoded["position"]
                lat_i = pos.get("latitudeI", 0)
                lon_i = pos.get("longitudeI", 0)
                if lat_i or lon_i:
                    lat = lat_i / 1e7
                    lon = lon_i / 1e7
                    alt = pos.get("altitude")
                    alt_str = f" alt={alt}m" if alt else ""
                    plaintext = f"pos={lat:.6f},{lon:.6f}{alt_str}"

        # Fixed-width values keep columns aligned whether or not optional fields are present.
        ha_val = f"{ha:>2}" if ha is not None else " ?"
        snr_val = f"{snr:>6.2f}" if isinstance(snr, (int, float)) else f"{'?':>6}"
        rssi_val = f"{rssi:>5}" if isinstance(rssi, (int, float)) else f"{'?':>5}"

        mqtt_flag = " [MQTT]" if via_mqtt else ""
        pt_str = f"  {plaintext}" if plaintext else ""

        line = (
            f"[{self.count:>5}] {ts}  "
            f"from=!{from_node:08x}  to=!{to_node:08x}  "
            f"id=0x{packet_id:08x}  ch={channel}  "
            f"hop={hop_limit}/{hop_start}  ha={ha_val}  "
            f"snr={snr_val}dB  rssi={rssi_val}dBm"
            f"{mqtt_flag}{pt_str}"
        )
        print(line)

        if self.csv_writer:
            self.csv_writer.writerow(
                [
                    ts,
                    f"0x{packet_id:08x}",
                    f"!{from_node:08x}",
                    f"!{to_node:08x}",
                    channel,
                    hop_limit,
                    hop_start,
                    ha,
                    via_mqtt,
                    snr,
                    rssi,
                    portnum,
                    payload_len,
                    plaintext or "",
                    lat or "",
                    lon or "",
                    alt or "",
                ]
            )
            self.log_file.flush()

    def close(self):
        if self.log_file:
            self.log_file.close()


def main():
    parser = argparse.ArgumentParser(description="Meshtastic passive traffic analysis")
    from common import add_connection_args, build_interface, evil_mode

    add_connection_args(parser)
    parser.add_argument("--log", metavar="FILE", help="Write CSV log to FILE")
    parser.add_argument(
        "--decrypt-default",
        action="store_true",
        help="Attempt to decrypt using default PSK (AQ== / defaultpsk)",
    )
    parser.add_argument(
        "--psk",
        metavar="HEX",
        help="Hex PSK to use for decryption (e.g. d4f1bb3a20290759f0bcffabcf4e6901)",
    )
    args = parser.parse_args()

    psk = None
    if args.decrypt_default:
        psk = DEFAULT_PSK
        print(f"[*] Default PSK loaded: {DEFAULT_PSK.hex()}")
    elif args.psk:
        psk = bytes.fromhex(args.psk)
        print(f"[*] PSK loaded: {psk.hex()}")

    try:
        from Crypto.Cipher import AES
    except ImportError:
        if psk:
            print(
                "[!] pycryptodome not installed. Install with: pip install pycryptodome"
            )
            print("[!] Falling back to header-only analysis.")
            psk = None

    capture = Capture(psk=psk, log_path=args.log)

    print(f"[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    node_info = iface.getMyNodeInfo()
    node_num = node_info.get("num", 0)
    node_name = node_info.get("user", {}).get("longName", "?")
    fw = iface.metadata.firmware_version if iface.metadata else "?"
    print(f"[*] Connected: {node_name} (0x{node_num:08x})  fw={fw}")
    if evil_mode(args):
        print(
            f"[*] Evil mode: watching for spoofed source IDs and transformed messages"
        )
    print(f"[*] Listening for packets... (Ctrl+C to stop)")
    print(
        f"[*] {'Decryption enabled' if psk else 'Header-only analysis (no decryption)'}"
    )
    if args.log:
        print(f"[*] Logging to: {args.log}")
    print()
    # Column widths match the fixed-width fields in on_receive exactly.
    print(
        f"{'#':>7} {'timestamp':<23}  {'from':<14}  {'to':<12}  "
        f"{'packet_id':<13}  {'ch':<4}  {'hop l/s':<7}  {'ha':<5}  "
        f"{'snr':<12}  {'rssi':<13}  info"
    )
    print("-" * 130)

    pub.subscribe(capture.on_receive, "meshtastic.receive")

    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Captured {capture.count} packets.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    while running:
        time.sleep(0.1)

    capture.close()
    iface.close()


if __name__ == "__main__":
    main()
