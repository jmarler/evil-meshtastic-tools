#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
fake_position.py — Meshtastic fake GPS position broadcaster

Broadcasts arbitrary GPS coordinates from your node. This poisons the
position shown for your node on all mesh maps and apps. Useful for:
  - Pointing everyone on the map to the HRV booth
  - Demonstrating that position data is entirely trust-based
  - Testing map-based UIs

Note: broadcasts as YOUR node ID (cannot spoof source with stock firmware).
The fake position also updates the node's own internal position belief,
which affects display on connected apps.

Usage:
    # Single broadcast to a specific location
    python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \\
        --lat 36.1268 --lon -115.1745 --alt 600

    # Continuous broadcast (useful to maintain the fake position)
    python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \\
        --lat 36.1268 --lon -115.1745 --alt 600 --count 0 --interval 30

    # Walk a fake path (interpolate between two points)
    python tools/fake_position.py --port /dev/cu.SLAB_USBtoUART \\
        --lat 36.1268 --lon -115.1745 --alt 600 \\
        --to-lat 36.1350 --to-lon -115.1600 --steps 20 --interval 5

Interesting targets:
    DEF CON / Caesars Forum: 36.1268, -115.1745
    HRV area (approx):     36.1270, -115.1748
    Las Vegas Strip center: 36.1140, -115.1728
    Null Island (0,0):      0.0, 0.0
"""

import argparse
import sys
import time
import signal

from meshtastic import mesh_pb2, portnums_pb2

from common import add_connection_args, build_interface, evil_mode, print_banner


def send_position(iface, latitude, longitude, altitude, channel_index, hop_limit):
    """Broadcast a Position packet, bypassing meshtastic's sendPosition().

    sendPosition() only sets latitude_i/longitude_i when the value is
    non-zero, so it silently drops both fields when broadcasting exactly
    (0, 0) -- the packet goes out with no position data at all. Build the
    protobuf directly so an intentional (0, 0) still gets sent.
    """
    p = mesh_pb2.Position()
    p.latitude_i = int(latitude / 1e-7)
    p.longitude_i = int(longitude / 1e-7)
    if altitude != 0:
        p.altitude = int(altitude)

    return iface.sendData(
        p,
        destinationId="^all",
        portNum=portnums_pb2.PortNum.POSITION_APP,
        channelIndex=channel_index,
        hopLimit=hop_limit,
    )


def lerp(a, b, t):
    return a + (b - a) * t


def main():
    parser = argparse.ArgumentParser(description="Meshtastic fake GPS position broadcaster")
    add_connection_args(parser)

    parser.add_argument("--lat", type=float, required=True, help="Latitude (decimal degrees)")
    parser.add_argument("--lon", type=float, required=True, help="Longitude (decimal degrees)")
    parser.add_argument("--alt", type=int, default=0, help="Altitude in meters (default: 0)")

    # Walk mode
    parser.add_argument("--to-lat", type=float, help="End latitude for walk mode")
    parser.add_argument("--to-lon", type=float, help="End longitude for walk mode")
    parser.add_argument("--steps", type=int, default=10, help="Steps for walk mode (default: 10)")

    parser.add_argument("--count", type=int, default=1,
                        help="Number of position packets to send (0=infinite, default: 1)")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="Seconds between broadcasts in continuous mode (default: 10)")
    parser.add_argument("--hop-limit", type=int, default=3,
                        help="Hop limit (default: 3)")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel index (default: 0)")

    args = parser.parse_args()

    walk_mode = (args.to_lat is not None and args.to_lon is not None)

    print(f"[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    info, node_num = print_banner(iface, args, "fake_position.py — GPS position spoofing")

    running = True
    count = 0
    total = args.count

    if walk_mode:
        total = args.steps
        print(f"[*] Walk mode: {args.steps} steps from ({args.lat},{args.lon}) to ({args.to_lat},{args.to_lon})")

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Interrupted after {count} broadcasts.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    start = time.time()
    while running and (total == 0 or count < total):
        if walk_mode:
            t = count / max(args.steps - 1, 1)
            lat = lerp(args.lat, args.to_lat, t)
            lon = lerp(args.lon, args.to_lon, t)
        else:
            lat = args.lat
            lon = args.lon

        try:
            send_position(
                iface,
                latitude=lat,
                longitude=lon,
                altitude=args.alt,
                channel_index=args.channel,
                hop_limit=args.hop_limit,
            )
            count += 1
            print(f"  [{count:>4}] Broadcast position: ({lat:.6f}, {lon:.6f}, {args.alt}m)")
        except Exception as e:
            print(f"  [ERROR] {e}")

        if total == 0 or count < total:
            time.sleep(args.interval)

    print(f"\n[*] Done. Sent {count} position packets in {time.time()-start:.1f}s")
    iface.close()


if __name__ == "__main__":
    main()
