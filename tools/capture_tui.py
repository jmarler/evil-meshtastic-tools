#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
#   "pypubsub",
#   "pycryptodome",
#   "textual",
# ]
# ///
"""
capture_tui.py — Meshtastic passive traffic analysis (Textual TUI)

Interactive terminal UI. Layout:
  - Left panel (75%): scrolling packet log, newest at bottom
  - Right panel (25%): last-known position per heard node, updated in place

The meshtastic pubsub callback fires from meshtastic's internal reader thread.
call_from_thread() is used to post all UI mutations back onto the Textual event loop.

Usage:
    python tools/capture_tui.py --port /dev/cu.usbmodem1101
    python tools/capture_tui.py --host 192.168.1.100
    python tools/capture_tui.py --port /dev/cu.usbmodem1101 --decrypt-default
    python tools/capture_tui.py --port /dev/cu.usbmodem1101 --psk d4f1bb3a...
"""

import argparse
import datetime
import struct
import time
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header
from textual import work
from textual.worker import get_current_worker

from pubsub import pub
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface


# From Channels.h: defaultpsk[] — backs the well-known "AQ==" channel alias
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


def _aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
    return cipher.encrypt(data)


def _meshtastic_nonce(packet_id: int, from_node: int) -> bytes:
    return struct.pack(
        "<QII", packet_id & 0xFFFFFFFFFFFFFFFF, from_node & 0xFFFFFFFF, 0
    )


def _hops_away(packet: dict) -> Optional[int]:
    hop_limit = packet.get("hopLimit")
    hop_start = packet.get("hopStart")
    if hop_limit is not None and hop_start is not None:
        return hop_start - hop_limit
    return None


def _extract_payload(
    psk: Optional[bytes], packet: dict
) -> tuple[str, Optional[float], Optional[float], Optional[int]]:
    """
    Pull human-readable info and optional GPS coords out of a packet dict.

    The meshtastic Python library pre-decodes packets on the default channel, so
    text and position are normally available in packet["decoded"] without any PSK
    work.  The PSK path handles manually-encrypted or non-default-channel packets.

    Returns (info_str, lat, lon, alt).
    """
    decoded = packet.get("decoded", {})
    lat = lon = alt = None
    info = ""

    if "text" in decoded:
        info = decoded["text"]
    elif "position" in decoded:
        pos = decoded["position"]
        lat_i = pos.get("latitudeI", 0)
        lon_i = pos.get("longitudeI", 0)
        if lat_i or lon_i:
            lat = lat_i / 1e7
            lon = lon_i / 1e7
            alt = pos.get("altitude") or None
            info = f"pos={lat:.6f},{lon:.6f}"
            if alt:
                info += f" alt={alt}m"
    elif psk:
        # Packet was not decoded by the library (unknown channel / non-default PSK).
        # Attempt manual AES-CTR decryption and protobuf parse.
        try:
            import meshtastic.protobuf.mesh_pb2 as mesh_pb2
            import meshtastic.protobuf.portnums_pb2 as portnums_pb2

            raw = packet.get("raw")
            if raw is None:
                return info, lat, lon, alt

            def _parse_data(portnum, payload_bytes: bytes) -> None:
                nonlocal lat, lon, alt, info
                if portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                    info = payload_bytes.decode("utf-8", errors="replace")
                elif portnum == portnums_pb2.PortNum.POSITION_APP:
                    pos = mesh_pb2.Position()
                    pos.ParseFromString(payload_bytes)
                    lat = pos.latitude_i / 1e7
                    lon = pos.longitude_i / 1e7
                    alt = pos.altitude or None
                    info = f"pos={lat:.6f},{lon:.6f}"
                    if alt:
                        info += f" alt={alt}m"
                else:
                    info = f"<portnum={portnum}>"

            if raw.HasField("decoded"):
                _parse_data(raw.decoded.portnum, raw.decoded.payload)
            elif len(raw.encrypted) > 0:
                nonce = _meshtastic_nonce(packet.get("id", 0), packet.get("from", 0))
                plaintext = _aes_ctr_crypt(psk, nonce, raw.encrypted)
                data_pb = mesh_pb2.Data()
                data_pb.ParseFromString(plaintext)
                _parse_data(data_pb.portnum, data_pb.payload)
        except Exception:
            pass

    return info, lat, lon, alt


class CaptureApp(App):
    TITLE = "Meshtastic Capture"

    CSS = """
    Screen {
        layout: vertical;
    }
    Horizontal {
        height: 1fr;
    }
    #packet-table {
        width: 3fr;
    }
    #node-panel {
        width: 1fr;
        border-left: tall $accent;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.cli_args = args
        self.psk: Optional[bytes] = None
        self.iface = None
        self.packet_count = 0
        self._connected_label = ""
        # node_hex -> {lat, lon, alt, last_seen}
        self._node_positions: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield DataTable(id="packet-table", cursor_type="row")
            yield DataTable(id="node-panel", cursor_type="none")
        yield Footer()

    def on_mount(self) -> None:
        pt = self.query_one("#packet-table", DataTable)
        pt.add_columns(
            "#",
            "Time",
            "From",
            "To",
            "Packet ID",
            "Ch",
            "Hop",
            "Ha",
            "SNR",
            "RSSI",
            "Info",
        )

        np = self.query_one("#node-panel", DataTable)
        np.add_columns("Node", "Lat / Lon", "Alt", "Last")

        self.sub_title = "Connecting..."
        self._run_capture()

    @work(thread=True)
    def _run_capture(self) -> None:
        worker = get_current_worker()
        args = self.cli_args

        if args.decrypt_default:
            self.psk = DEFAULT_PSK
        elif args.psk:
            self.psk = bytes.fromhex(args.psk)

        try:
            if args.host:
                self.iface = meshtastic.tcp_interface.TCPInterface(hostname=args.host)
            else:
                self.iface = meshtastic.serial_interface.SerialInterface(
                    devPath=args.port
                )
        except Exception as exc:
            self.call_from_thread(
                self._set_subtitle, f"[red]Connection failed: {exc}[/]"
            )
            return

        # Give the interface time to enumerate the node list before querying it.
        time.sleep(2)

        node_info = self.iface.getMyNodeInfo()
        node_num = node_info.get("num", 0)
        node_name = node_info.get("user", {}).get("longName", "?")
        mode = "PSK" if self.psk else "header-only"
        self._connected_label = f"Node: {node_name} (0x{node_num:08x})  [{mode}]"

        self.call_from_thread(
            self._set_subtitle,
            f"{self._connected_label}  Packets: 0",
        )

        pub.subscribe(self._on_packet_thread, "meshtastic.receive")

        while not worker.is_cancelled:
            time.sleep(0.5)

        if self.iface:
            self.iface.close()

    def _set_subtitle(self, text: str) -> None:
        self.sub_title = text

    def _on_packet_thread(self, packet, interface) -> None:
        # Called from meshtastic's internal reader thread — marshal to Textual's loop.
        try:
            self.call_from_thread(self._handle_packet, packet)
        except Exception:
            # App may already be shutting down; discard silently.
            pass

    def _handle_packet(self, packet: dict) -> None:
        self.packet_count += 1
        time_str = datetime.datetime.now().strftime("%H:%M:%S")

        from_node = packet.get("from", 0)
        to_node = packet.get("to", 0)
        packet_id = packet.get("id", 0)
        channel = packet.get("channel", 0)
        hop_limit = packet.get("hopLimit", "?")
        hop_start = packet.get("hopStart", "?")
        snr = packet.get("rxSnr", "?")
        rssi = packet.get("rxRssi", "?")
        ha = _hops_away(packet)

        info, lat, lon, alt = _extract_payload(self.psk, packet)

        snr_str = f"{snr:.2f}" if isinstance(snr, (int, float)) else "?"
        rssi_str = str(rssi) if isinstance(rssi, (int, float)) else "?"
        ha_str = str(ha) if ha is not None else "?"

        pt = self.query_one("#packet-table", DataTable)
        pt.add_row(
            str(self.packet_count),
            time_str,
            f"!{from_node:08x}",
            f"!{to_node:08x}",
            f"0x{packet_id:08x}",
            str(channel),
            f"{hop_limit}/{hop_start}",
            ha_str,
            snr_str,
            rssi_str,
            info,
        )
        pt.scroll_end(animate=False)

        if lat is not None:
            node_hex = f"!{from_node:08x}"
            self._node_positions[node_hex] = {
                "lat": lat,
                "lon": lon,
                "alt": alt,
                "last_seen": time_str,
            }
            self._refresh_node_panel()

        self.sub_title = f"{self._connected_label}  Packets: {self.packet_count}"

    def _refresh_node_panel(self) -> None:
        # Rebuild the node panel from the current position dict.
        # Row count stays small (one row per distinct heard node), so clear+readd is fine.
        np = self.query_one("#node-panel", DataTable)
        np.clear()
        for node_hex, data in sorted(self._node_positions.items()):
            lat = data["lat"]
            lon = data["lon"]
            alt = data.get("alt")
            last = data["last_seen"]
            pos_str = f"{lat:.5f},{lon:.5f}"
            alt_str = f"{alt}m" if alt else "—"
            np.add_row(node_hex, pos_str, alt_str, last)

    def action_quit(self) -> None:
        if self.iface:
            self.iface.close()
        self.exit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Meshtastic capture TUI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--port", help="Serial port (e.g. /dev/cu.usbmodem1101)")
    group.add_argument("--host", help="TCP hostname for Wi-Fi-connected node")
    parser.add_argument(
        "--decrypt-default",
        action="store_true",
        help="Decrypt with the default PSK (AQ== / defaultpsk)",
    )
    parser.add_argument(
        "--psk",
        metavar="HEX",
        help="Hex PSK for decryption (e.g. d4f1bb3a20290759f0bcffabcf4e6901)",
    )
    args = parser.parse_args()
    CaptureApp(args).run()


if __name__ == "__main__":
    main()
