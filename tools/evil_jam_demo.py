#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
#   "pypubsub",
#   "textual",
# ]
# ///
"""
evil_jam_demo.py — Live sync-word jam demo (attacker + victim, one screen)

Two-pane Textual TUI, built for a room to watch, not a bench log. The attacker
pane fires the EVIL_SYNCWORD_JAM burst (see EvilCtrlModule / evil_ctrl.py) and
sends a broadcast heartbeat once a second whenever it is not jamming. The
victim pane just listens: every heartbeat it hears resets a "last seen" clock
and feeds a rolling activity sparkline. When the attacker jams, its one radio
cannot also send, so the heartbeat stops and the victim pane flips from
"LIVE" to "NO SIGNAL" until the burst ends and the heartbeat resumes.

One process holds both Meshtastic connections, so firing the jam (the 'j'
key) and watching it land on the victim pane happen in the same screen —
nothing to keep manually in sync across two terminal windows.

Usage:
    python tools/evil_jam_demo.py \\
        --attacker-host 192.168.64.2 --victim-host 192.168.64.3

    python tools/evil_jam_demo.py \\
        --attacker-port /dev/cu.SLAB_USBtoUART --victim-port /dev/cu.usbmodem1101 \\
        --jam-ms 8000

Keys: j = fire a jam burst, q = quit.
"""

import argparse
import time
from collections import deque
from typing import Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Sparkline, Static
from textual.worker import get_current_worker

from pubsub import pub

from common import build_interface
from evil_ctrl import (
    EVIL_CTRL_PORTNUM,
    _decode_evil_ctrl_reply,
    encode_evil_ctrl_msg,
    send_evil_ctrl,
)

HEARTBEAT_PREFIX = "sync-spam-heartbeat"
HEARTBEAT_INTERVAL = 1.5  # seconds between attacker heartbeats when not jamming
# Victim's own, independent beacon -- unrelated to anything the attacker sends. Lets a
# third node (e.g. watched via its own app) show that the jam disrupts ANY nearby traffic
# sharing the channel, not just the attacker's own outgoing heartbeat.
VICTIM_BEACON_PREFIX = "victim-beacon"
VICTIM_BEACON_INTERVAL = 1.5  # seconds; victim never jams, so this never pauses on its own
# Must comfortably exceed several missed heartbeats, not just one -- real-world reception
# is well under 100% even outside a jam (~44% per-heartbeat at 2s spacing, confirmed
# 2026-08-04), so a threshold close to one interval flags ordinary packet loss as a false
# "NO SIGNAL". A real jam is a multi-second sustained burst; require ~4 misses in a row
# (4x the interval) so isolated drops don't trip it but an actual jam always does.
NO_SIGNAL_THRESHOLD = 6.0  # seconds since last heartbeat before the victim reads dead
SPARKLINE_TICK = 0.5  # seconds per activity-sparkline sample
SPARKLINE_WINDOW = 40  # samples kept on screen
CONNECT_SETTLE = 2.0  # seconds to let a fresh connection settle before use


def _node_args(host: Optional[str], port: Optional[str]) -> argparse.Namespace:
    """Build a Namespace matching what common.build_interface() expects."""
    return argparse.Namespace(host=host, port=port)


class EvilJamDemoApp(App):
    TITLE = "Sync-Word Jam Demo"

    CSS = """
    Screen {
        layout: vertical;
    }
    #panes {
        height: 1fr;
    }
    .pane {
        width: 1fr;
        padding: 1 2;
    }
    #attacker-pane {
        border-right: heavy $accent;
    }
    .banner {
        text-style: bold;
        content-align: center middle;
        height: 5;
        text-align: center;
    }
    .label {
        color: $text-muted;
    }
    Sparkline {
        height: 3;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("j", "fire_jam", "Fire jam"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.cli_args = args
        self.jam_ms: int = args.jam_ms

        self.attacker_iface = None
        self.attacker_node_num: Optional[int] = None
        self.heartbeats_sent = 0

        self.victim_iface = None
        self.heartbeats_received = 0
        self.last_heartbeat_at: Optional[float] = None
        self.victim_beacons_sent = 0

        self.jamming = False
        self.jam_deadline = 0.0

        self._sparkline_data: deque = deque([0] * SPARKLINE_WINDOW, maxlen=SPARKLINE_WINDOW)
        self._sparkline_bucket = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="panes"):
            with Vertical(id="attacker-pane", classes="pane"):
                yield Static("ATTACKER", classes="label")
                yield Static("Connecting...", id="attacker-banner", classes="banner")
                yield Static("", id="attacker-status", classes="label")
                yield Static("heartbeats sent: 0", id="attacker-count")
            with Vertical(id="victim-pane", classes="pane"):
                yield Static("VICTIM", classes="label")
                yield Static("Connecting...", id="victim-banner", classes="banner")
                yield Static("last heartbeat: --", id="victim-last-seen")
                yield Static("heartbeats received: 0", id="victim-count")
                yield Sparkline(list(self._sparkline_data), id="victim-activity")
                yield Static("own beacons sent: 0", id="victim-beacon-count", classes="label")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"jam duration: {self.jam_ms}ms — press 'j' to fire"
        self._run_attacker()
        self._run_victim()
        self.set_interval(0.2, self._tick)

    # ── Attacker connection + heartbeat sender ──────────────────────────────

    @work(thread=True)
    def _run_attacker(self) -> None:
        worker = get_current_worker()
        try:
            iface = build_interface(_node_args(self.cli_args.attacker_host, self.cli_args.attacker_port))
        except Exception as e:
            self.call_from_thread(self._set_banner, "attacker-banner", f"[bold red]CONNECT FAILED\n{e}[/]")
            return

        self.attacker_iface = iface
        time.sleep(CONNECT_SETTLE)
        self.attacker_node_num = iface.getMyNodeInfo().get("num", 0)

        def on_reply(packet, interface):
            if interface is not iface:
                return
            decoded = packet.get("decoded", {})
            if decoded.get("portnum") not in (EVIL_CTRL_PORTNUM, "PRIVATE_APP"):
                return
            fields = _decode_evil_ctrl_reply(decoded.get("payload", b""))
            if fields.get("is_reply"):
                self.call_from_thread(self._set_attacker_status, fields)

        pub.subscribe(on_reply, "meshtastic.receive")
        self._query_attacker_status()
        self.call_from_thread(self._set_banner, "attacker-banner", "[bold green]● READY[/]")

        while not worker.is_cancelled:
            if not self.jamming:
                try:
                    # Identical repeated content gets silently suppressed by Meshtastic's
                    # own (sender, packet_id) dedup cache on the receiving node -- confirmed
                    # 2026-08-04 (unique content: 5/5 received; identical content: ~1/13,
                    # unaffected by power, antenna, or distance). Each heartbeat must differ.
                    iface.sendText(
                        f"{HEARTBEAT_PREFIX} {self.heartbeats_sent}",
                        destinationId="^all",
                        channelIndex=0,
                        hopLimit=3,
                        wantAck=False,
                    )
                    self.heartbeats_sent += 1
                    self.call_from_thread(self._refresh_attacker_count)
                except Exception:
                    pass
            time.sleep(HEARTBEAT_INTERVAL)

        pub.unsubscribe(on_reply, "meshtastic.receive")

    def _query_attacker_status(self) -> None:
        if self.attacker_iface is None or self.attacker_node_num is None:
            return
        payload = encode_evil_ctrl_msg(get_status=True)
        try:
            send_evil_ctrl(self.attacker_iface, payload, self.attacker_node_num)
        except Exception:
            pass

    def _set_attacker_status(self, fields: dict) -> None:
        jam_ms = fields.get("jam_ms") or 5000
        flood_count = fields.get("flood_count") or 50
        line = f"jam={jam_ms}ms  flood={flood_count}  hop={fields.get('hop_mode', 0)}"
        self.query_one("#attacker-status", Static).update(line)

    def _refresh_attacker_count(self) -> None:
        self.query_one("#attacker-count", Static).update(f"heartbeats sent: {self.heartbeats_sent}")

    # ── Victim connection + listener ────────────────────────────────────────

    @work(thread=True)
    def _run_victim(self) -> None:
        worker = get_current_worker()
        try:
            iface = build_interface(_node_args(self.cli_args.victim_host, self.cli_args.victim_port))
        except Exception as e:
            self.call_from_thread(self._set_banner, "victim-banner", f"[bold red]CONNECT FAILED\n{e}[/]")
            return

        self.victim_iface = iface
        time.sleep(CONNECT_SETTLE)
        victim_node_num = iface.getMyNodeInfo().get("num", 0)
        self.call_from_thread(self._set_banner, "victim-banner", "[bold green]● LIVE[/]")

        def on_receive(packet, interface):
            if interface is not iface:
                return
            if packet.get("from") == victim_node_num:
                return  # some clients echo your own sent packet back locally -- not a real RX
            if "text" not in packet.get("decoded", {}):
                return
            self.call_from_thread(self._on_heartbeat)

        pub.subscribe(on_receive, "meshtastic.receive")
        while not worker.is_cancelled:
            try:
                iface.sendText(
                    f"{VICTIM_BEACON_PREFIX} {self.victim_beacons_sent}",
                    destinationId="^all",
                    channelIndex=0,
                    hopLimit=3,
                    wantAck=False,
                )
                self.victim_beacons_sent += 1
                self.call_from_thread(self._refresh_victim_beacon_count)
            except Exception:
                pass
            time.sleep(VICTIM_BEACON_INTERVAL)
        pub.unsubscribe(on_receive, "meshtastic.receive")

    def _on_heartbeat(self) -> None:
        self.heartbeats_received += 1
        self.last_heartbeat_at = time.monotonic()
        self._sparkline_bucket += 1
        self.query_one("#victim-count", Static).update(f"heartbeats received: {self.heartbeats_received}")

    def _refresh_victim_beacon_count(self) -> None:
        self.query_one("#victim-beacon-count", Static).update(f"own beacons sent: {self.victim_beacons_sent}")

    # ── Jam control ──────────────────────────────────────────────────────────

    def action_fire_jam(self) -> None:
        if self.jamming or self.attacker_iface is None or self.attacker_node_num is None:
            return
        self.jamming = True
        self.jam_deadline = time.monotonic() + (self.jam_ms / 1000.0)
        payload = encode_evil_ctrl_msg(jam=True, jam_ms=self.jam_ms)
        try:
            send_evil_ctrl(self.attacker_iface, payload, self.attacker_node_num)
        except Exception:
            pass
        self._set_banner("attacker-banner", f"[bold red]▲ TRANSMITTING JAM ({self.jam_ms}ms)[/]")

    # ── Periodic UI tick ─────────────────────────────────────────────────────

    def _tick(self) -> None:
        now = time.monotonic()

        if self.jamming and now >= self.jam_deadline:
            self.jamming = False
            self._set_banner("attacker-banner", "[bold green]● READY[/]")
            self._query_attacker_status()

        if self.last_heartbeat_at is None:
            since = None
        else:
            since = now - self.last_heartbeat_at

        if since is None:
            self.query_one("#victim-last-seen", Static).update("last heartbeat: --")
        else:
            self.query_one("#victim-last-seen", Static).update(f"last heartbeat: {since:.1f}s ago")

        if not self.jamming:
            # Jam banner already reflects the attacker's own state above; only
            # the victim's live/dead read depends on elapsed time since heartbeat.
            pass
        if self.victim_iface is not None:
            if since is not None and since > NO_SIGNAL_THRESHOLD:
                self._set_banner("victim-banner", "[bold red]✕ NO SIGNAL[/]")
            else:
                self._set_banner("victim-banner", "[bold green]● LIVE[/]")

        self._sparkline_tick_accum = getattr(self, "_sparkline_tick_accum", 0.0) + 0.2
        if self._sparkline_tick_accum >= SPARKLINE_TICK:
            self._sparkline_tick_accum = 0.0
            self._sparkline_data.append(self._sparkline_bucket)
            self._sparkline_bucket = 0
            self.query_one("#victim-activity", Sparkline).data = list(self._sparkline_data)

    def _set_banner(self, widget_id: str, text: str) -> None:
        self.query_one(f"#{widget_id}", Static).update(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live sync-word jam demo: attacker + victim, one screen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Keys:")[0].strip(),
    )
    parser.add_argument("--attacker-host", help="TCP hostname for the attacker node")
    parser.add_argument("--attacker-port", help="Serial port for the attacker node")
    parser.add_argument("--victim-host", help="TCP hostname for the victim node")
    parser.add_argument("--victim-port", help="Serial port for the victim node")
    parser.add_argument(
        "--jam-ms",
        type=int,
        default=5000,
        help="Jam burst duration in ms fired by the 'j' key (100-60000, default: 5000)",
    )
    args = parser.parse_args()

    if not (args.attacker_host or args.attacker_port):
        parser.error("one of --attacker-host or --attacker-port is required")
    if not (args.victim_host or args.victim_port):
        parser.error("one of --victim-host or --victim-port is required")
    if not (100 <= args.jam_ms <= 60000):
        parser.error(f"--jam-ms must be 100-60000, got {args.jam_ms}")

    EvilJamDemoApp(args).run()


if __name__ == "__main__":
    main()
