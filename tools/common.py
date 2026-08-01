"""
common.py — Shared connection logic for evil-meshtastic tools

Supports both stock Meshtastic firmware and the evil firmware build.

Key differences when using evil firmware (heltec-v4-evil):
  - Serial protocol runs on UART0/CP2102 (SLAB_USBtoUART) with ARDUINO_USB_CDC_ON_BOOT=0
  - Opening the port triggers a device reset via DTR/RTS — boot takes ~10 seconds
  - EVIL_ALLOW_FROM_OVERRIDE lets Python set a non-zero 'from' field for source spoofing
  - 30-second timeout accommodates the longer boot cycle

Usage in a tool:
    from common import add_connection_args, build_interface, evil_mode, print_banner

    parser = argparse.ArgumentParser(...)
    add_connection_args(parser)
    args = parser.parse_args()
    iface = build_interface(args)
    if evil_mode(args):
        # evil-firmware-specific code
"""

import sys
import time
import meshtastic.serial_interface
import meshtastic.tcp_interface


# Default timeout: long enough for evil firmware boot cycle via CP2102 reset
CONNECT_TIMEOUT = 30


def add_connection_args(parser, require_port=True):
    """Add --port / --host / --evil arguments to an argparse parser."""
    group = parser.add_mutually_exclusive_group(required=require_port)
    group.add_argument(
        "--port",
        help="Serial port (e.g. /dev/cu.SLAB_USBtoUART)",
    )
    group.add_argument(
        "--host",
        help="TCP hostname for WiFi-connected node (port 4403)",
    )
    parser.add_argument(
        "--evil",
        action="store_true",
        help=(
            "Enable evil firmware mode. Unlocks source spoofing (--from) and "
            "other features that require EVIL_ALLOW_FROM_OVERRIDE in firmware. "
            "Also increases connection timeout to 30s for the CP2102 boot cycle."
        ),
    )
    return group


def build_interface(args):
    """Open a MeshInterface using --port or --host from parsed args."""
    timeout = CONNECT_TIMEOUT  # same for stock/evil — 30s is safe for both
    if args.host:
        return meshtastic.tcp_interface.TCPInterface(hostname=args.host)
    return meshtastic.serial_interface.SerialInterface(
        devPath=args.port, timeout=timeout
    )


def evil_mode(args):
    """Return True if --evil flag was specified."""
    return getattr(args, "evil", False)


def print_banner(iface, args, tool_name):
    """Print a standard connection banner with node info and firmware version."""
    info = iface.getMyNodeInfo()
    node_num = info.get("num", 0)
    node_name = info.get("user", {}).get("longName", "?")
    md = iface.metadata
    fw = md.firmware_version if md else "?"

    print(f"[*] {tool_name}")
    print(f"[*] Connected: {node_name} (0x{node_num:08x})  fw={fw}")
    if evil_mode(args):
        print(f"[*] Evil mode ENABLED — source spoofing and evil features active")
    else:
        print(f"[*] Stock mode — source=your node ID, no spoofing")
    return info, node_num


def detect_evil_firmware(iface):
    """
    Heuristic: check firmware version for evil build marker.
    Currently relies on --evil flag since the build doesn't embed a special string.
    Returns False always — use --evil flag explicitly.
    """
    return False
