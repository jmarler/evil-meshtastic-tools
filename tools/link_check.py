#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
#   "pypubsub",
# ]
# ///
"""
link_check.py — Pairwise RF link quality check, no jam involved

Connects to two nodes (A and B), has each broadcast a uniquely-numbered ping
once per interval, and counts how many of each side's pings the other side
actually receives. Prints a running tally and a final summary. Bench/setup
diagnostic: run it on a suspect pair before blaming jam code or dedup logic
for what might just be a bad physical link (loose antenna, bad spacing,
wrong tx_power).

Each ping's content includes a running counter, since Meshtastic's own
(sender, packet_id) dedup cache silently drops repeated identical content --
confirmed 2026-08-04, see our internal notes session 24.

Usage:
    python tools/link_check.py --a-host 192.168.64.2 --b-host 192.168.64.3
    python tools/link_check.py --a-port /dev/cu.SLAB_USBtoUART --b-host 192.168.64.4 \\
        --duration 90 --interval 2
"""

import argparse
import threading
import time

from pubsub import pub

from common import build_interface

PING_INTERVAL_DEFAULT = 1.5
DURATION_DEFAULT = 60
STATUS_EVERY = 5.0


class Side:
    """One end of the link: its own connection, send loop, and receive count."""

    def __init__(self, name: str, node_args: argparse.Namespace, interval: float) -> None:
        self.name = name
        self.node_args = node_args
        self.interval = interval
        self.prefix = f"link-check-{name}"
        self.iface = None
        self.node_num: int = 0
        self.sent = 0
        self.received = 0
        self._stop = threading.Event()

    def connect(self) -> None:
        self.iface = build_interface(self.node_args)
        time.sleep(2.0)  # let the connection settle before sending/subscribing
        self.node_num = self.iface.getMyNodeInfo().get("num", 0)

    def on_receive(self, other_prefix: str, packet: dict, interface) -> None:
        if interface is not self.iface:
            return
        if packet.get("from") == self.node_num:
            return  # self-echo, not a real RX
        text = packet.get("decoded", {}).get("text", "")
        if text.startswith(other_prefix):
            self.received += 1

    def send_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.iface.sendText(
                    f"{self.prefix} {self.sent}",
                    destinationId="^all",
                    channelIndex=0,
                    hopLimit=3,
                    wantAck=False,
                )
                self.sent += 1
            except Exception as e:
                print(f"[{self.name}] send failed: {e}")
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        if self.iface is not None:
            self.iface.close()


def _node_args(host, port) -> argparse.Namespace:
    return argparse.Namespace(host=host, port=port)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pairwise RF link quality check between two nodes, no jam involved",
    )
    parser.add_argument("--a-host", help="TCP hostname for node A")
    parser.add_argument("--a-port", help="Serial port for node A")
    parser.add_argument("--b-host", help="TCP hostname for node B")
    parser.add_argument("--b-port", help="Serial port for node B")
    parser.add_argument(
        "--duration", type=float, default=DURATION_DEFAULT, help=f"Test duration in seconds (default: {DURATION_DEFAULT})"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=PING_INTERVAL_DEFAULT,
        help=f"Seconds between pings on each side (default: {PING_INTERVAL_DEFAULT})",
    )
    args = parser.parse_args()

    if not (args.a_host or args.a_port):
        parser.error("one of --a-host or --a-port is required")
    if not (args.b_host or args.b_port):
        parser.error("one of --b-host or --b-port is required")

    a = Side("A", _node_args(args.a_host, args.a_port), args.interval)
    b = Side("B", _node_args(args.b_host, args.b_port), args.interval)

    print(f"[A] connecting to {args.a_host or args.a_port}...")
    a.connect()
    print(f"[B] connecting to {args.b_host or args.b_port}...")
    b.connect()

    # pypubsub only holds a WEAK reference to subscribers -- an inline lambda passed
    # directly to subscribe() has no other referent and gets garbage collected almost
    # immediately, silently killing the subscription. Keep real names bound in this
    # scope so they survive for the life of the test.
    a_listener = lambda packet, interface: a.on_receive(b.prefix, packet, interface)
    b_listener = lambda packet, interface: b.on_receive(a.prefix, packet, interface)
    pub.subscribe(a_listener, "meshtastic.receive")
    pub.subscribe(b_listener, "meshtastic.receive")

    a_thread = threading.Thread(target=a.send_loop, daemon=True)
    b_thread = threading.Thread(target=b.send_loop, daemon=True)
    a_thread.start()
    b_thread.start()

    print(f"Running for {args.duration:.0f}s, ping every {args.interval:.1f}s (Ctrl-C to stop early)...")
    start = time.monotonic()
    try:
        while time.monotonic() - start < args.duration:
            time.sleep(STATUS_EVERY)
            elapsed = time.monotonic() - start
            print(
                f"  [{elapsed:5.1f}s] A: sent={a.sent:3d} received={a.received:3d}   "
                f"B: sent={b.sent:3d} received={b.received:3d}"
            )
    except KeyboardInterrupt:
        print("\nStopped early.")

    a.stop()
    b.stop()
    a_thread.join(timeout=2)
    b_thread.join(timeout=2)

    def pct(received: int, sent: int) -> str:
        return f"{100 * received / sent:.0f}%" if sent else "n/a"

    print("\n=== Summary ===")
    print(f"A -> B: A sent {a.sent}, B received {b.received} ({pct(b.received, a.sent)})")
    print(f"B -> A: B sent {b.sent}, A received {a.received} ({pct(a.received, b.sent)})")

    a.close()
    b.close()


if __name__ == "__main__":
    main()
