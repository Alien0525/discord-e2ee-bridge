"""
client.py — Local CLI for E2E encrypted Discord messaging.

All cryptography happens HERE on your machine.
The bot never sees plaintext, private keys, or the AES key.

First-time setup:
    python3 client.py keygen <username>         # generate your keypairs
    python3 client.py login <username>          # set active session (do once)
    python3 client.py register                  # paste output into Discord !register

After login, you never type your username again:
    python3 client.py addpeer <peer> <x25519> <ed25519>
    python3 client.py handshake <peer>
    python3 client.py handshake <peer> <salt>   # receiving side
    python3 client.py send <peer> <message>
    python3 client.py read                      # prompts for payload
    python3 client.py peers                     # list known peers
    python3 client.py whoami                    # show active session
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

KEYS_DIR     = Path("keys")
LOGS_DIR     = Path("logs")
# -----------------------------------------------------------------------
# Session helpers
#
# Priority: DISCORD_E2E_USER env var > .session file
#
# On a shared machine with two users in separate terminals:
#   Terminal 1:  export DISCORD_E2E_USER=alien0x525
#   Terminal 2:  export DISCORD_E2E_USER=0x00ns
# They never conflict. "login" sets the env var for the current shell.
# -----------------------------------------------------------------------

SESSION_FILE = Path(".session")


def get_session() -> str | None:
    """Return active username. Env var takes priority over .session file."""
    env = os.environ.get("DISCORD_E2E_USER", "").strip()
    if env:
        return env
    if SESSION_FILE.exists():
        return SESSION_FILE.read_text().strip() or None
    return None


def require_session() -> str:
    username = get_session()
    if not username:
        print("❌ No active session.")
        print("   Option 1 (recommended for shared machine):")
        print("     export DISCORD_E2E_USER=your_username")
        print("   Option 2:")
        print("     python3 client.py login your_username")
        sys.exit(1)
    return username


def set_session(username: str) -> None:
    SESSION_FILE.write_text(username)


# -----------------------------------------------------------------------
# Peer storage (per-user: logs/<username>_peers.json)
# -----------------------------------------------------------------------

def _peers_file(username: str) -> Path:
    return LOGS_DIR / f"{username}_peers.json"


def load_peers(username: str) -> dict:
    f = _peers_file(username)
    f.parent.mkdir(parents=True, exist_ok=True)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except json.JSONDecodeError:
        return {}


def save_peers(peers: dict, username: str) -> None:
    f = _peers_file(username)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(peers, indent=2))


# -----------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------

def cmd_login(args):
    """Set your active username so you never need to type it again."""
    if args:
        username = args[0]
    else:
        username = input("Enter your Discord username: ").strip()

    key_dir = KEYS_DIR / username
    if not key_dir.exists():
        print(f"⚠️  No keys found for '{username}'.")
        print(f"   Run first:  python3 client.py keygen {username}")
        confirm = input("Set session anyway? [y/N]: ").strip().lower()
        if confirm != "y":
            return

    set_session(username)
    print(f"✅ Logged in as '{username}'")
    print(f"")
    print(f"   ⚡ To make this terminal always act as '{username}', run:")
    print(f"      export DISCORD_E2E_USER={username}")
    print(f"   Add it to your ~/.zshrc or ~/.bashrc to make it permanent,")
    print(f"   or just run it in each new terminal window for this user.")


def cmd_whoami(args):
    """Show the active session."""
    u = get_session()
    print(f"Active session: {u}" if u else "No active session. Run: python3 client.py login <username>")


def cmd_keygen(args):
    """Generate X25519 + Ed25519 keypairs."""
    if args:
        username = args[0]
    else:
        username = get_session()
        if not username:
            username = input("Enter your Discord username: ").strip()

    key_dir = KEYS_DIR / username
    if key_dir.exists():
        if input(f"Keys for '{username}' already exist. Overwrite? [y/N]: ").lower() != "y":
            print("Aborted.")
            return

    generate_keypairs(username)
    pub_bytes = export_public_keys_bytes(username)

    print(f"\n✅ Keys generated for '{username}'")
    print(f"  X25519  : {pub_bytes['x25519_public'].hex()}")
    print(f"  Ed25519 : {pub_bytes['ed25519_public'].hex()}")
    print(f"\n→ Next: set your session and register your keys with the bot:")
    print(f"    export DISCORD_E2E_USER={username}")
    print(f"    python3 client.py register")


def cmd_register(args):
    """Print the !register command to paste into Discord."""
    username  = require_session()
    pub_bytes = export_public_keys_bytes(username)
    x25519    = pub_bytes["x25519_public"].hex()
    ed25519   = pub_bytes["ed25519_public"].hex()

    print(f"\n📋 Paste into Discord (any channel with the bot):")
    print(f"\n!register {x25519} {ed25519}\n")
    print(f"→ Next: get your peer's keys from Discord and add them:")
    print(f"    !getkey <peer_username>          (in Discord)")
    print(f"    python3 client.py addpeer ...    (copy the line the bot gives you)")


def cmd_addpeer(args):
    """
    Store a peer's public keys.
    The bot's !getkey output gives you the exact command to paste here.

    Usage: python3 client.py addpeer <peer_username> <x25519_hex> <ed25519_hex>
    """
    username = require_session()

    if len(args) < 3:
        print("Usage: python3 client.py addpeer <peer_username> <x25519_hex> <ed25519_hex>")
        print("  Tip: !getkey <peer> in Discord gives you the exact line to run.")
        sys.exit(1)

    peer_name, x25519_hex, ed25519_hex = args[0], args[1], args[2]

    peers = load_peers(username)
    peers[peer_name] = {"x25519": x25519_hex, "ed25519": ed25519_hex}
    save_peers(peers, username)
    print(f"✅ Stored keys for peer '{peer_name}'")
    print(f"\n→ Next: do the handshake to establish a shared encryption key:")
    print(f"    python3 client.py handshake {peer_name}")
    print(f"    (or wait for a peer to initiate the handshake)")


def cmd_handshake(args):
    """
    Exchange the HKDF salt with a peer.

    You initiate:   python3 client.py handshake <peer>
                    → paste the !handshake command into Discord

    You received:   python3 client.py handshake <peer> <salt_hex>
                    → copy from the bot's DM
    """
    username = require_session()

    if not args:
        print("Usage: python3 client.py handshake <peer_username> [salt_hex]")
        sys.exit(1)

    peer_name = args[0]
    peers     = load_peers(username)

    if peer_name not in peers:
        print(f"❌ Peer '{peer_name}' not found.")
        print(f"   Run: python3 client.py addpeer {peer_name} <x25519> <ed25519>")
        sys.exit(1)

    if len(args) == 1:
        # Initiator path: generate salt
        keys     = load_all_keys(username)
        peer_pub = import_peer_x25519_public(bytes.fromhex(peers[peer_name]["x25519"]))
        _, salt  = derive_shared_aes_key(keys["x25519_private"], peer_pub)

        peers[peer_name]["salt"] = salt.hex()
        save_peers(peers, username)

        print(f"\n📋 Paste into Discord:")
        print(f"\n!handshake @{peer_name} {salt.hex()}\n")
        print(f"✅ Salt saved. Your peer will receive a DM from the bot with instructions.")
        print(f"")
        print(f"   Once they complete the handshake, both of you can send messages:")
        print(f"   Send:    python3 client.py send {peer_name} 'your message here'")
        print(f"   Decrypt: python3 client.py read   (paste the JSON from the bot DM)")

    else:
        # Receiver path: store the salt from the bot's DM
        salt_hex = args[1]
        peers[peer_name]["salt"] = salt_hex
        save_peers(peers, username)
        print(f"✅ Handshake complete with '{peer_name}'.")
        print(f"\n→ Next: you can now send and receive encrypted messages:")
        print(f"    python3 client.py send {peer_name} 'your message'")
        print(f"    python3 client.py read '{{...}}'   (or just: python3 client.py read, then paste)")


def cmd_send(args):
    """
    Encrypt a message and print the !send command for Discord.
    Usage: python3 client.py send <peer_username> <message>
    """
    username = require_session()

    if len(args) < 2:
        print("Usage: python3 client.py send <peer_username> <message>")
        sys.exit(1)

    peer_name = args[0]
    message   = " ".join(args[1:])
    my_keys   = load_all_keys(username)
    peers     = load_peers(username)

    if peer_name not in peers:
        print(f"❌ Unknown peer '{peer_name}'. Run addpeer first.")
        sys.exit(1)

    peer_data = peers[peer_name]
    if "salt" not in peer_data:
        print(f"❌ No salt for '{peer_name}'. Run handshake first.")
        sys.exit(1)

    peer_pub = import_peer_x25519_public(bytes.fromhex(peer_data["x25519"]))
    salt     = bytes.fromhex(peer_data["salt"])
    aes_key, _ = derive_shared_aes_key(my_keys["x25519_private"], peer_pub, salt=salt)

    seq            = get_next_sequence(username)
    payload_json   = build_payload(aes_key, message, username, seq)
    signed_payload = attach_signature(payload_json, my_keys["ed25519_private"])

    print(f"\n  Sending as : {username}  →  to : {peer_name}")
    print(f"\n📋 Paste into Discord:")
    print(f"\n!send @{peer_name} {signed_payload}\n")
    print(f"→ Your peer runs: python3 client.py read '{{...}}' to decrypt.")


def cmd_read(args):
    """
    Decrypt a message from Discord.
    Usage: python3 client.py read [payload_json]
    If no payload given, you'll be prompted to paste it.
    """
    username = require_session()

    if args:
        payload_json = " ".join(args)
    else:
        print("Paste the JSON payload from the bot's DM (then press Enter):")
        payload_json = input().strip()

    my_keys = load_all_keys(username)
    peers   = load_peers(username)

    try:
        parsed    = json.loads(payload_json)
        sender_id = parsed["sender_id"]
    except (json.JSONDecodeError, KeyError):
        print("❌ Invalid payload — copy the full JSON blob from the bot's DM.")
        sys.exit(1)

    if sender_id not in peers:
        print(f"❌ Unknown sender '{sender_id}'.")
        print(f"   Run !getkey {sender_id} in Discord, then addpeer.")
        sys.exit(1)

    peer_data = peers[sender_id]

    # Step 1: Verify signature
    sender_pub = import_peer_ed25519_public(bytes.fromhex(peer_data["ed25519"]))
    is_valid, clean_payload = verify_signature(payload_json, sender_pub)
    if not is_valid:
        print("❌ SIGNATURE INVALID — message may be forged or tampered!")
        sys.exit(1)

    # Step 2: Derive AES key BEFORE replay check so a bad key doesn't burn the seq
    if "salt" not in peer_data:
        print(f"❌ No salt for '{sender_id}'. Complete handshake first.")
        print(f"   Run: python3 client.py handshake {sender_id} <salt_from_their_dm>")
        sys.exit(1)

    peer_pub = import_peer_x25519_public(bytes.fromhex(peer_data["x25519"]))
    salt     = bytes.fromhex(peer_data["salt"])
    aes_key, _ = derive_shared_aes_key(my_keys["x25519_private"], peer_pub, salt=salt)

    # Step 3: Try decryption BEFORE recording replay state
    # This prevents a bad key or corrupted payload from permanently burning the seq number
    inner = json.loads(clean_payload)
    try:
        result = open_payload(aes_key, clean_payload)
    except Exception:
        print(f"❌ Decryption failed — GCM authentication tag mismatch.")
        print(f"   This usually means the AES key doesn't match.")
        print(f"   Possible causes:")
        print(f"     • You stored {sender_id}'s keys incorrectly — re-run addpeer")
        print(f"     • The handshake salt is from the wrong direction — redo handshake")
        print(f"     • The message was corrupted in transit")
        sys.exit(1)

    # Step 4: Replay check AFTER successful decryption
    nonce_hex = base64.b64decode(inner["nonce"]).hex()
    accepted, reason = check_and_record(
        sender_id=inner["sender_id"],
        timestamp=inner["timestamp"],
        sequence=inner["sequence"],
        nonce_hex=nonce_hex,
    )
    if not accepted:
        print(f"❌ REPLAY DETECTED — {reason}")
        sys.exit(1)

    import datetime
    ts = datetime.datetime.fromtimestamp(result['timestamp']).strftime('%H:%M:%S')
    print(f"\n{'─'*40}")
    print(f"  To      : {username}  (you)")
    print(f"  From    : {result['sender_id']}")
    print(f"  Time    : {ts}")
    print(f"  Message : {result['plaintext']}")
    print(f"{'─'*40}")
    print(f"\n→ Reply: python3 client.py send {result['sender_id']} 'your reply'")


def cmd_peers(args):
    """List known peers and their handshake status."""
    username = require_session()
    peers    = load_peers(username)
    if not peers:
        print("No peers yet. Use !getkey in Discord, then addpeer.")
        return
    print(f"\nPeers for '{username}':")
    for name, data in peers.items():
        status = "✅ ready" if "salt" in data else "⏳ needs handshake"
        print(f"  {name:25s}  {status}")
    print()


def cmd_debug(args):
    """Show raw peer data to diagnose key/salt mismatches."""
    username = require_session()
    peers = load_peers(username)
    if not peers:
        print("No peers stored.")
        return
    for name, data in peers.items():
        print(f"\nPeer: {name}")
        print(f"  x25519  : {data.get('x25519', 'MISSING')[:16]}...")
        print(f"  ed25519 : {data.get('ed25519', 'MISSING')[:16]}...")
        salt = data.get('salt')
        print(f"  salt    : {salt[:16] + '...' if salt else 'MISSING — run handshake'}")


def cmd_showkeys(args):
    """Show your public keys."""
    username  = require_session() if not args else args[0]
    pub_bytes = export_public_keys_bytes(username)
    print(f"\nPublic keys for '{username}':")
    print(f"  X25519  : {pub_bytes['x25519_public'].hex()}")
    print(f"  Ed25519 : {pub_bytes['ed25519_public'].hex()}")


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

COMMANDS = {
    "login"     : cmd_login,
    "whoami"    : cmd_whoami,
    "keygen"    : cmd_keygen,
    "register"  : cmd_register,
    "addpeer"   : cmd_addpeer,
    "handshake" : cmd_handshake,
    "send"      : cmd_send,
    "read"      : cmd_read,
    "peers"     : cmd_peers,
    "showkeys"  : cmd_showkeys,
    "debug"     : cmd_debug,
}

HELP = """
Usage: python3 client.py <command> [args]

  login <username>                    set active session (do once)
  whoami                              show active session
  keygen <username>                   generate keypairs
  register                            print !register command for Discord
  addpeer <peer> <x25519> <ed25519>   store peer's keys (from !getkey output)
  handshake <peer>                    generate salt, paste !handshake into Discord
  handshake <peer> <salt>             store salt from bot's DM (receiving side)
  send <peer> <message>               encrypt and print !send command
  read [payload]                      decrypt a message (paste when prompted)
  peers                               list known peers and status
  showkeys                            show your public keys
"""

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(HELP)
        sys.exit(0 if len(sys.argv) < 2 else 1)

    COMMANDS[sys.argv[1]](sys.argv[2:])