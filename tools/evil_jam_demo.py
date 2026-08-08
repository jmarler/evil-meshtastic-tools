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
evil_jam_demo.py — Live sync-word jam demo (attacker + victim1 + optional victim2)

Textual TUI, built for a room to watch, not a bench log. The attacker pane
only fires the EVIL_SYNCWORD_JAM burst (see EvilCtrlModule / evil_ctrl.py) and
sends its own heartbeat once a second whenever it is not jamming; it is not
part of the conversation being demonstrated. With --victim2-host/-port set,
the real demo is victim1 and victim2 holding their own independent
back-and-forth (each broadcasts a beacon the other listens for) that has
nothing to do with the attacker. When the attacker jams, both sides' radios
are held off-channel, so both panes flip from "LIVE" to "NO SIGNAL" until the
burst ends and reception resumes -- proof this is channel jamming, not a
targeted attacker-victim MitM. Without victim2, it falls back to the original
two-pane form: victim1 listens for the attacker's own heartbeat instead.

One process holds all the Meshtastic connections, so firing the jam (the 'j'
key) and watching it land on the victim1 and victim2 panes happen in the
same screen -- nothing to keep manually in sync across terminal windows.

Usage:
    python tools/evil_jam_demo.py \\
        --attacker-host 192.168.64.2 --victim1-host 192.168.64.3 \\
        --victim2-host 192.168.64.4

    python tools/evil_jam_demo.py \\
        --attacker-port /dev/cu.SLAB_USBtoUART --victim1-port /dev/cu.usbmodem1101 \\
        --jam-ms 8000

victim2 is optional -- omit --victim2-host/--victim2-port for the original
two-pane attacker+victim1 demo.

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
# victim1's and victim2's own, independent beacons -- unrelated to anything the attacker
# sends. Each listens for the other's, so the jam disrupting BOTH proves it is channel
# jamming, not something specific to the attacker's own outgoing heartbeat.
VICTIM1_BEACON_PREFIX = "victim1-beacon"
VICTIM1_BEACON_INTERVAL = 1.5  # seconds; victim1 never jams, so this never pauses on its own
VICTIM2_BEACON_PREFIX = "victim2-beacon"
VICTIM2_BEACON_INTERVAL = 1.5  # seconds; victim2 never jams either
# Must comfortably exceed several missed heartbeats, not just one -- real-world reception
# is well under 100% even outside a jam (~44% per-heartbeat at 2s spacing, confirmed
# 2026-08-04), so a threshold close to one interval flags ordinary packet loss as a false
# "NO SIGNAL". A real jam is a multi-second sustained burst; require ~4 misses in a row
# (4x the interval) so isolated drops don't trip it but an actual jam always does.
NO_SIGNAL_THRESHOLD = 6.0  # seconds since last heard before a pane reads dead
SPARKLINE_TICK = 0.5  # seconds per activity-sparkline sample
SPARKLINE_WINDOW = 40  # samples kept on screen
CONNECT_SETTLE = 2.0  # seconds to let a fresh connection settle before use
CONNECT_RETRY_DELAY = 3.0  # seconds between reconnect attempts after a failed connect


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
        height: 100%;
        padding: 1 2;
        margin: 1;
        align: center middle;
        border: heavy $panel;
    }
    #attacker-pane {
        border: heavy $error;
    }
    #victim1-pane, #victim2-pane {
        border: heavy $success;
    }
    .banner {
        text-style: bold;
        content-align: center middle;
        height: 5;
        text-align: center;
        width: 100%;
    }
    .label {
        color: $text-muted;
        text-align: center;
        width: 100%;
    }
    Sparkline {
        height: 5;
        width: 100%;
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

        self.victim1_iface = None
        self.victim1_heard = 0
        self.victim1_last_heard_at: Optional[float] = None
        self.victim1_beacons_sent = 0

        self.has_victim2 = bool(args.victim2_host or args.victim2_port)
        self.victim2_iface = None
        self.victim2_heard = 0
        self.victim2_last_heard_at: Optional[float] = None
        self.victim2_beacons_sent = 0

        self.jamming = False
        self.jam_deadline = 0.0

        self._victim1_sparkline_data: deque = deque([0] * SPARKLINE_WINDOW, maxlen=SPARKLINE_WINDOW)
        self._victim1_sparkline_bucket = 0
        self._victim2_sparkline_data: deque = deque([0] * SPARKLINE_WINDOW, maxlen=SPARKLINE_WINDOW)
        self._victim2_sparkline_bucket = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="panes"):
            with Vertical(id="attacker-pane", classes="pane"):
                yield Static("Connecting...", id="attacker-banner", classes="banner")
                yield Static("", id="attacker-status", classes="label")
                yield Static("heartbeats sent: 0", id="attacker-count")
            with Vertical(id="victim1-pane", classes="pane"):
                yield Static("Connecting...", id="victim1-banner", classes="banner")
                yield Static("last heard: --", id="victim1-last-seen")
                yield Static("packets heard: 0", id="victim1-count")
                yield Sparkline(list(self._victim1_sparkline_data), id="victim1-activity")
                yield Static("own beacons sent: 0", id="victim1-beacon-count", classes="label")
            if self.has_victim2:
                with Vertical(id="victim2-pane", classes="pane"):
                    yield Static("Connecting...", id="victim2-banner", classes="banner")
                    yield Static("last heard: --", id="victim2-last-seen")
                    yield Static("packets heard: 0", id="victim2-count")
                    yield Sparkline(list(self._victim2_sparkline_data), id="victim2-activity")
                    yield Static("own beacons sent: 0", id="victim2-beacon-count", classes="label")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"jam duration: {self.jam_ms}ms — press 'j' to fire"

        attacker_pane = self.query_one("#attacker-pane")
        attacker_pane.border_title = "ATTACKER"
        attacker_pane.border_subtitle = "evil firmware"
        victim1_pane = self.query_one("#victim1-pane")
        victim1_pane.border_title = "VICTIM 1"
        victim1_pane.border_subtitle = "stock firmware"
        if self.has_victim2:
            victim2_pane = self.query_one("#victim2-pane")
            victim2_pane.border_title = "VICTIM 2"
            victim2_pane.border_subtitle = "stock firmware"

        self._run_attacker()
        self._run_victim1()
        if self.has_victim2:
            self._run_victim2()
        self.set_interval(0.2, self._tick)

    def _connect_with_retry(self, node_args: argparse.Namespace, banner_id: str, worker) -> Optional[object]:
        """Keep retrying build_interface() until it succeeds or the worker is
        cancelled (app quitting). A transient hiccup at the exact moment the
        TUI starts -- a slow VM, a brief firewall/network blip -- must not
        permanently strand a pane in CONNECT FAILED with no way to recover
        short of restarting the whole app.
        """
        attempt = 0
        while not worker.is_cancelled:
            attempt += 1
            try:
                return build_interface(node_args)
            except Exception as e:
                self.call_from_thread(
                    self._set_banner,
                    banner_id,
                    f"[bold red]CONNECT FAILED (attempt {attempt})\n{e}\nretrying...[/]",
                )
                time.sleep(CONNECT_RETRY_DELAY)
        return None

    # ── Attacker connection + heartbeat sender ──────────────────────────────

    @work(thread=True)
    def _run_attacker(self) -> None:
        worker = get_current_worker()
        iface = self._connect_with_retry(
            _node_args(self.cli_args.attacker_host, self.cli_args.attacker_port), "attacker-banner", worker
        )
        if iface is None:
            return  # worker cancelled (app quitting) while still retrying

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
        jam_ms = fields.get("jam_ms") or 8000
        flood_count = fields.get("flood_count") or 50
        line = f"jam={jam_ms}ms  flood={flood_count}  hop={fields.get('hop_mode', 0)}"
        self.query_one("#attacker-status", Static).update(line)

    def _refresh_attacker_count(self) -> None:
        self.query_one("#attacker-count", Static).update(f"heartbeats sent: {self.heartbeats_sent}")

    # ── victim1 connection + conversation partner ───────────────────────────
    # Without victim2, victim1 just listens for the attacker's own heartbeat
    # (the original two-pane demo). With victim2, victim1's own beacon and
    # victim2's own beacon form an independent back-and-forth that has nothing
    # to do with the attacker; only the jam can interrupt it.

    @work(thread=True)
    def _run_victim1(self) -> None:
        worker = get_current_worker()
        iface = self._connect_with_retry(
            _node_args(self.cli_args.victim1_host, self.cli_args.victim1_port), "victim1-banner", worker
        )
        if iface is None:
            return  # worker cancelled (app quitting) while still retrying

        self.victim1_iface = iface
        time.sleep(CONNECT_SETTLE)
        victim1_node_num = iface.getMyNodeInfo().get("num", 0)
        self.call_from_thread(self._set_banner, "victim1-banner", "[bold green]● LIVE[/]")

        def on_receive(packet, interface):
            if interface is not iface:
                return
            if packet.get("from") == victim1_node_num:
                return  # some clients echo your own sent packet back locally -- not a real RX
            if "text" not in packet.get("decoded", {}):
                return
            self.call_from_thread(self._on_victim1_heard)

        pub.subscribe(on_receive, "meshtastic.receive")
        while not worker.is_cancelled:
            try:
                iface.sendText(
                    f"{VICTIM1_BEACON_PREFIX} {self.victim1_beacons_sent}",
                    destinationId="^all",
                    channelIndex=0,
                    hopLimit=3,
                    wantAck=False,
                )
                self.victim1_beacons_sent += 1
                self.call_from_thread(self._refresh_victim1_beacon_count)
            except Exception:
                pass
            time.sleep(VICTIM1_BEACON_INTERVAL)
        pub.unsubscribe(on_receive, "meshtastic.receive")

    def _on_victim1_heard(self) -> None:
        self.victim1_heard += 1
        self.victim1_last_heard_at = time.monotonic()
        self._victim1_sparkline_bucket += 1
        self.query_one("#victim1-count", Static).update(f"packets heard: {self.victim1_heard}")

    def _refresh_victim1_beacon_count(self) -> None:
        self.query_one("#victim1-beacon-count", Static).update(f"own beacons sent: {self.victim1_beacons_sent}")

    # ── victim2 connection + conversation partner ───────────────────────────
    # Stock firmware, no evil_ctrl reply expected. Optional; symmetric to
    # victim1 above.

    @work(thread=True)
    def _run_victim2(self) -> None:
        worker = get_current_worker()
        try:
            iface = build_interface(_node_args(self.cli_args.victim2_host, self.cli_args.victim2_port))
        except Exception as e:
            self.call_from_thread(self._set_banner, "victim2-banner", f"[bold red]CONNECT FAILED\n{e}[/]")
            return

        self.victim2_iface = iface
        time.sleep(CONNECT_SETTLE)
        victim2_node_num = iface.getMyNodeInfo().get("num", 0)
        self.call_from_thread(self._set_banner, "victim2-banner", "[bold green]● LIVE[/]")

        def on_receive(packet, interface):
            if interface is not iface:
                return
            if packet.get("from") == victim2_node_num:
                return
            if "text" not in packet.get("decoded", {}):
                return
            self.call_from_thread(self._on_victim2_heard)

        pub.subscribe(on_receive, "meshtastic.receive")
        while not worker.is_cancelled:
            try:
                iface.sendText(
                    f"{VICTIM2_BEACON_PREFIX} {self.victim2_beacons_sent}",
                    destinationId="^all",
                    channelIndex=0,
                    hopLimit=3,
                    wantAck=False,
                )
                self.victim2_beacons_sent += 1
                self.call_from_thread(self._refresh_victim2_beacon_count)
            except Exception:
                pass
            time.sleep(VICTIM2_BEACON_INTERVAL)
        pub.unsubscribe(on_receive, "meshtastic.receive")

    def _on_victim2_heard(self) -> None:
        self.victim2_heard += 1
        self.victim2_last_heard_at = time.monotonic()
        self._victim2_sparkline_bucket += 1
        self.query_one("#victim2-count", Static).update(f"packets heard: {self.victim2_heard}")

    def _refresh_victim2_beacon_count(self) -> None:
        self.query_one("#victim2-beacon-count", Static).update(f"own beacons sent: {self.victim2_beacons_sent}")

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

        self._tick_pane(
            now,
            iface=self.victim1_iface,
            last_heard_at=self.victim1_last_heard_at,
            last_seen_id="victim1-last-seen",
            banner_id="victim1-banner",
        )
        if self.has_victim2:
            self._tick_pane(
                now,
                iface=self.victim2_iface,
                last_heard_at=self.victim2_last_heard_at,
                last_seen_id="victim2-last-seen",
                banner_id="victim2-banner",
            )

        self._sparkline_tick_accum = getattr(self, "_sparkline_tick_accum", 0.0) + 0.2
        if self._sparkline_tick_accum >= SPARKLINE_TICK:
            self._sparkline_tick_accum = 0.0
            self._victim1_sparkline_data.append(self._victim1_sparkline_bucket)
            self._victim1_sparkline_bucket = 0
            self.query_one("#victim1-activity", Sparkline).data = list(self._victim1_sparkline_data)
            if self.has_victim2:
                self._victim2_sparkline_data.append(self._victim2_sparkline_bucket)
                self._victim2_sparkline_bucket = 0
                self.query_one("#victim2-activity", Sparkline).data = list(self._victim2_sparkline_data)

    def _tick_pane(
        self,
        now: float,
        *,
        iface,
        last_heard_at: Optional[float],
        last_seen_id: str,
        banner_id: str,
    ) -> None:
        since = None if last_heard_at is None else now - last_heard_at
        if since is None:
            self.query_one(f"#{last_seen_id}", Static).update("last heard: --")
        else:
            self.query_one(f"#{last_seen_id}", Static).update(f"last heard: {since:.1f}s ago")
        if iface is not None:
            if since is not None and since > NO_SIGNAL_THRESHOLD:
                self._set_banner(banner_id, "[bold red]✕ NO SIGNAL[/]")
            else:
                self._set_banner(banner_id, "[bold green]● LIVE[/]")

    def _set_banner(self, widget_id: str, text: str) -> None:
        self.query_one(f"#{widget_id}", Static).update(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live sync-word jam demo: attacker + victim1 + optional victim2, one screen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Keys:")[0].strip(),
    )
    parser.add_argument("--attacker-host", help="TCP hostname for the attacker node")
    parser.add_argument("--attacker-port", help="Serial port for the attacker node")
    parser.add_argument("--victim1-host", help="TCP hostname for the victim1 node")
    parser.add_argument("--victim1-port", help="Serial port for the victim1 node")
    parser.add_argument("--victim2-host", help="TCP hostname for the optional victim2 node")
    parser.add_argument("--victim2-port", help="Serial port for the optional victim2 node")
    parser.add_argument(
        "--jam-ms",
        type=int,
        default=8000,
        help=(
            "Jam burst duration in ms fired by the 'j' key (100-60000, default: 8000). "
            f"Must comfortably exceed NO_SIGNAL_THRESHOLD ({NO_SIGNAL_THRESHOLD * 1000:.0f}ms) or "
            "the NO SIGNAL banner may never trigger if reception resumes right as the burst ends."
        ),
    )
    args = parser.parse_args()

    if not (args.attacker_host or args.attacker_port):
        parser.error("one of --attacker-host or --attacker-port is required")
    if not (args.victim1_host or args.victim1_port):
        parser.error("one of --victim1-host or --victim1-port is required")
    if not (100 <= args.jam_ms <= 60000):
        parser.error(f"--jam-ms must be 100-60000, got {args.jam_ms}")

    EvilJamDemoApp(args).run()


if __name__ == "__main__":
    main()
