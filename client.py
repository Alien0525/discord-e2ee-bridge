"""
client.py — Local CLI for E2E encrypted Discord messaging.

All cryptography happens HERE, on your machine.
The bot never sees plaintext, private keys, or the AES key.

Usage:
    python3 client.py keygen                        # generate your keypairs
    python3 client.py register                      # print keys to paste into Discord
    python3 client.py handshake <peer> <salt_hex>   # store peer's HKDF salt
    python3 client.py send <peer_username> <msg>    # encrypt + sign a message
    python3 client.py read <payload_json>           # decrypt + verify a message
    python3 client.py showkeys                      # display your public keys

Flow:
    1. Alice: python3 client.py keygen
    2. Alice: python3 client.py register    → paste output into Discord !register
    3. Bob:   same steps 1-2
    4. Alice: python3 client.py send bob#1234 "Hello Bob"
              → prints encrypted payload
              → Alice pastes into Discord: !send @Bob <payload>
    5. Alice: python3 client.py handshake   → prints salt
              → Alice pastes: !handshake @Bob <salt>
    6. Bob:   python3 client.py handshake alice#5678 <salt_from_discord>
    7. Bob:   python3 client.py read <payload_from_discord>
              → decrypts, verifies signature, checks replay
"""

import sys
import os
import json
import base64

from crypto.keygen import (
    generate_keypairs,
    load_all_keys,
    export_public_keys_bytes,
    import_peer_x25519_public,
    import_peer_ed25519_public,
)
from crypto.exchange import derive_shared_aes_key
from crypto.encrypt import build_payload, open_payload
from crypto.sign import attach_signature, verify_signature
from crypto.replay import check_and_record, get_next_sequence, reset_state

from pathlib import Path

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------

PEERS_FILE = Path("logs/peers.json")      # stores peer public keys + salts
KEYS_DIR   = Path("keys")


# -----------------------------------------------------------------------
# Peer storage helpers
# -----------------------------------------------------------------------

def load_peers() -> dict:
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not PEERS_FILE.exists():
        return {}
    try:
        return json.loads(PEERS_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_peers(peers: dict) -> None:
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PEERS_FILE.write_text(json.dumps(peers, indent=2))


def get_my_username() -> str:
    """Get username from keys/ directory — use first folder found."""
    dirs = [d for d in KEYS_DIR.iterdir() if d.is_dir()] if KEYS_DIR.exists() else []
    if not dirs:
        print("No keys found. Run: python3 client.py keygen <username>")
        sys.exit(1)
    return dirs[0].name


# -----------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------

def cmd_keygen(args):
    """
    Generate X25519 + Ed25519 keypairs for a user.
    Usage: python3 client.py keygen <username>
    """
    if not args:
        username = input("Enter your username (e.g. alice): ").strip()
    else:
        username = args[0]

    key_dir = KEYS_DIR / username
    if key_dir.exists():
        confirm = input(f"Keys for '{username}' already exist. Overwrite? [y/N]: ")
        if confirm.lower() != "y":
            print("Aborted.")
            return

    keys = generate_keypairs(username)
    pub_bytes = export_public_keys_bytes(username)

    print(f"\n✅ Keys generated for '{username}' in keys/{username}/")
    print(f"\nYour PUBLIC keys (safe to share):")
    print(f"  X25519  (ECDH)     : {pub_bytes['x25519_public'].hex()}")
    print(f"  Ed25519 (signature): {pub_bytes['ed25519_public'].hex()}")
    print(f"\nNext step: python3 client.py register")


def cmd_register(args):
    """
    Print your public keys formatted for Discord !register command.
    Usage: python3 client.py register
    """
    username = get_my_username()
    pub_bytes = export_public_keys_bytes(username)

    x25519_hex  = pub_bytes["x25519_public"].hex()
    ed25519_hex = pub_bytes["ed25519_public"].hex()

    print(f"\n📋 Copy and paste this into Discord:")
    print(f"\n!register {x25519_hex} {ed25519_hex}\n")


def cmd_addpeer(args):
    """
    Store a peer's public keys locally (from !getkey output).
    Usage: python3 client.py addpeer <peer_username> <x25519_hex> <ed25519_hex>
    """
    if len(args) < 3:
        print("Usage: python3 client.py addpeer <peer_username> <x25519_hex> <ed25519_hex>")
        sys.exit(1)

    peer_name, x25519_hex, ed25519_hex = args[0], args[1], args[2]

    peers = load_peers()
    peers[peer_name] = {
        "x25519":  x25519_hex,
        "ed25519": ed25519_hex,
    }
    save_peers(peers)
    print(f"✅ Stored public keys for peer '{peer_name}'")


def cmd_handshake(args):
    """
    Either generate and print your salt (no args),
    or store a peer's salt (with args).

    Generate: python3 client.py handshake
    Store:    python3 client.py handshake <peer_username> <salt_hex>
    """
    if not args:
        # Generate — Alice calls this to get the salt to share
        username = get_my_username()
        keys = load_all_keys(username)
        peers = load_peers()

        if not peers:
            print("No peers found. Run addpeer first.")
            sys.exit(1)

        # Use first peer for demo; in real client you'd specify peer
        peer_name = list(peers.keys())[0]
        peer_data = peers[peer_name]

        peer_x25519_pub = import_peer_x25519_public(
            bytes.fromhex(peer_data["x25519"])
        )

        _, salt = derive_shared_aes_key(
            keys["x25519_private"],
            peer_x25519_pub,
        )

        # Store salt locally too
        peers[peer_name]["salt"] = salt.hex()
        save_peers(peers)

        print(f"\n📋 Copy and paste this into Discord:")
        print(f"\n!handshake @{peer_name} {salt.hex()}\n")
        print(f"(Salt saved locally for '{peer_name}')")

    else:
        # Store — Bob calls this after receiving Alice's salt
        if len(args) < 2:
            print("Usage: python3 client.py handshake <peer_username> <salt_hex>")
            sys.exit(1)

        peer_name, salt_hex = args[0], args[1]
        peers = load_peers()

        if peer_name not in peers:
            print(f"Peer '{peer_name}' not found. Run addpeer first.")
            sys.exit(1)

        peers[peer_name]["salt"] = salt_hex
        save_peers(peers)
        print(f"✅ Salt stored for peer '{peer_name}'")
        print(f"   You can now decrypt messages from {peer_name}.")


def cmd_send(args):
    """
    Encrypt, sign, and print a message payload ready to post to Discord.
    Usage: python3 client.py send <peer_username> <message>
    """
    if len(args) < 2:
        print("Usage: python3 client.py send <peer_username> <message>")
        sys.exit(1)

    peer_name = args[0]
    message   = " ".join(args[1:])
    username  = get_my_username()

    # Load my private keys
    my_keys = load_all_keys(username)

    # Load peer's public keys
    peers = load_peers()
    if peer_name not in peers:
        print(f"Peer '{peer_name}' not found. Run addpeer first.")
        sys.exit(1)

    peer_data = peers[peer_name]

    if "salt" not in peer_data:
        print(f"No salt for '{peer_name}'. Run handshake first.")
        sys.exit(1)

    # Reconstruct peer's X25519 public key
    peer_x25519_pub = import_peer_x25519_public(
        bytes.fromhex(peer_data["x25519"])
    )

    # Derive shared AES key using stored salt
    salt = bytes.fromhex(peer_data["salt"])
    aes_key, _ = derive_shared_aes_key(
        my_keys["x25519_private"],
        peer_x25519_pub,
        salt=salt,
    )

    # Get next sequence number
    seq = get_next_sequence(username)

    # Encrypt the message
    payload_json = build_payload(aes_key, message, username, seq)

    # Sign the payload
    signed_payload = attach_signature(payload_json, my_keys["ed25519_private"])

    print(f"\n📋 Copy and paste this into Discord:")
    print(f"\n!send @{peer_name} {signed_payload}\n")


def cmd_read(args):
    """
    Decrypt and verify a message payload received from Discord.
    Usage: python3 client.py read <payload_json>
    """
    if not args:
        payload_json = input("Paste the payload JSON: ").strip()
    else:
        payload_json = " ".join(args)

    username = get_my_username()
    my_keys  = load_all_keys(username)
    peers    = load_peers()

    # Parse to find sender
    try:
        parsed = json.loads(payload_json)
        sender_id = parsed["sender_id"]
    except (json.JSONDecodeError, KeyError):
        print("❌ Invalid payload JSON.")
        sys.exit(1)

    if sender_id not in peers:
        print(f"❌ Unknown sender '{sender_id}'. Run addpeer first.")
        sys.exit(1)

    peer_data = peers[sender_id]

    # Step 1: Verify signature FIRST
    sender_ed25519_pub = import_peer_ed25519_public(
        bytes.fromhex(peer_data["ed25519"])
    )

    is_valid, clean_payload = verify_signature(payload_json, sender_ed25519_pub)

    if not is_valid:
        print(f"❌ SIGNATURE INVALID — message may be forged or tampered!")
        print(f"   Claimed sender: {sender_id}")
        sys.exit(1)

    print(f"✅ Signature valid — message is from {sender_id}")

    # Step 2: Replay check BEFORE decrypting
    inner = json.loads(clean_payload)
    nonce_hex = base64.b64decode(inner["nonce"]).hex()

    accepted, reason = check_and_record(
        sender_id=inner["sender_id"],
        timestamp=inner["timestamp"],
        sequence=inner["sequence"],
        nonce_hex=nonce_hex,
    )

    if not accepted:
        print(f"❌ REPLAY ATTACK DETECTED — {reason}")
        sys.exit(1)

    print(f"✅ Replay check passed (seq={inner['sequence']})")

    # Step 3: Derive shared AES key
    if "salt" not in peer_data:
        print(f"❌ No salt for '{sender_id}'. Complete handshake first.")
        sys.exit(1)

    peer_x25519_pub = import_peer_x25519_public(
        bytes.fromhex(peer_data["x25519"])
    )
    salt = bytes.fromhex(peer_data["salt"])
    aes_key, _ = derive_shared_aes_key(
        my_keys["x25519_private"],
        peer_x25519_pub,
        salt=salt,
    )

    # Step 4: Decrypt
    try:
        result = open_payload(aes_key, clean_payload)
    except Exception as e:
        print(f"❌ Decryption failed — {e}")
        sys.exit(1)

    print(f"\n{'─'*40}")
    print(f"  From    : {result['sender_id']}")
    print(f"  Message : {result['plaintext']}")
    print(f"  Seq     : {result['sequence']}")
    print(f"{'─'*40}\n")


def cmd_showkeys(args):
    """Print your public keys."""
    username  = get_my_username()
    pub_bytes = export_public_keys_bytes(username)
    print(f"\nPublic keys for '{username}':")
    print(f"  X25519  : {pub_bytes['x25519_public'].hex()}")
    print(f"  Ed25519 : {pub_bytes['ed25519_public'].hex()}")


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

COMMANDS = {
    "keygen"    : cmd_keygen,
    "register"  : cmd_register,
    "addpeer"   : cmd_addpeer,
    "handshake" : cmd_handshake,
    "send"      : cmd_send,
    "read"      : cmd_read,
    "showkeys"  : cmd_showkeys,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python3 client.py <command> [args]")
        print("Commands:", ", ".join(COMMANDS.keys()))
        sys.exit(1)

    command = sys.argv[1]
    args    = sys.argv[2:]
    COMMANDS[command](args)