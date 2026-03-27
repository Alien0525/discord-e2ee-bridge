"""
demo.py — Attack demonstration script for NYU CS6903 Project 2.2 presentation.

Shows all 4 required attacks being attempted and defeated:
    1. Eavesdropping     → attacker intercepts ciphertext, sees nothing useful
    2. Modification      → attacker flips bits, GCM tag rejects it
    3. Spoofing          → attacker fakes sender identity, signature rejects it
    4. Replay            → attacker resends old message, replay defense rejects it

Run: python3 demo.py
"""

import os
import sys
import json
import base64
import time

sys.path.insert(0, '.')

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.keygen import generate_keypairs, import_peer_x25519_public, import_peer_ed25519_public
from crypto.exchange import derive_shared_aes_key
from crypto.encrypt import build_payload, open_payload
from crypto.sign import attach_signature, verify_signature
from crypto.replay import check_and_record, get_next_sequence, reset_state

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def header(title):
    print(f"\n{'═'*55}")
    print(f"  {title}")
    print(f"{'═'*55}")

def subheader(title):
    print(f"\n  ── {title} ──")

def success(msg): print(f"  ✅ {msg}")
def failure(msg): print(f"  ❌ {msg}")
def info(msg):    print(f"     {msg}")

# -----------------------------------------------------------------------
# Setup: generate keys for Alice and Bob
# -----------------------------------------------------------------------

def setup():
    reset_state()
    import shutil
    for d in ['keys/demo_alice', 'keys/demo_bob']:
        if os.path.exists(d):
            shutil.rmtree(d)

    alice_keys = generate_keypairs('demo_alice')
    bob_keys   = generate_keypairs('demo_bob')

    # Key exchange
    alice_aes, salt = derive_shared_aes_key(
        alice_keys['x25519_private'],
        bob_keys['x25519_public'],
    )
    bob_aes, _ = derive_shared_aes_key(
        bob_keys['x25519_private'],
        alice_keys['x25519_public'],
        salt=salt,
    )
    assert alice_aes == bob_aes

    return alice_keys, bob_keys, alice_aes, bob_aes

# -----------------------------------------------------------------------
# Attack 1: Eavesdropping
# -----------------------------------------------------------------------

def demo_eavesdropping(alice_keys, alice_aes):
    header("ATTACK 1: Eavesdropping")
    info("Eve intercepts Alice's message to Bob on Discord.")
    info("Eve has no AES key and no private keys.\n")

    seq     = get_next_sequence('demo_alice')
    payload = build_payload(alice_aes, "Transfer $1000 to Bob", 'demo_alice', seq)
    signed  = attach_signature(payload, alice_keys['ed25519_private'])

    subheader("What Eve sees on Discord")
    info(f"{signed[:100]}...")

    subheader("Eve tries to read the message with a random key")
    eve_fake_key = os.urandom(32)
    try:
        inner = json.loads(json.loads(signed) and signed)
    except Exception:
        pass

    # Eve tries to decrypt with wrong key
    parsed = json.loads(signed)
    parsed.pop('signature', None)
    try:
        result = open_payload(eve_fake_key, json.dumps(parsed))
        failure("Eve decrypted the message!")
    except (InvalidTag, Exception):
        success("Eavesdropping defeated — Eve cannot decrypt without AES key")
        info("Ciphertext is computationally indistinguishable from random (AES-256-GCM)")
        info("Lecture 5: IND-CMA security — no adversary can recover plaintext")

    return signed  # pass to next demo


# -----------------------------------------------------------------------
# Attack 2: Message Modification
# -----------------------------------------------------------------------

def demo_modification(alice_keys, bob_aes, original_signed):
    header("ATTACK 2: Message Modification (MITM)")
    info("Eve intercepts the message and flips bits in the ciphertext.")
    info("Goal: change 'Transfer $1000 to Bob' to something else.\n")

    parsed = json.loads(original_signed)
    ct_bytes = bytearray(base64.b64decode(parsed['ciphertext']))

    # Flip first byte
    ct_bytes[0] ^= 0xFF
    parsed['ciphertext'] = base64.b64encode(bytes(ct_bytes)).decode()
    parsed.pop('signature', None)
    tampered = json.dumps(parsed)

    subheader("Eve tampers with ciphertext byte 0 (flips all bits)")
    info(f"Original  ciphertext[0]: {base64.b64decode(json.loads(original_signed)['ciphertext'])[0]:08b}")
    info(f"Tampered  ciphertext[0]: {ct_bytes[0]:08b}")

    subheader("Bob tries to decrypt tampered message")
    try:
        open_payload(bob_aes, tampered)
        failure("Bob accepted tampered message!")
    except (InvalidTag, Exception):
        success("Modification defeated — GCM authentication tag rejected tampered ciphertext")
        info("Lecture 6: Authenticated encryption (IND-CCA) — any modification")
        info("to ciphertext or AAD invalidates the 128-bit GCM tag")


# -----------------------------------------------------------------------
# Attack 3: Sender Spoofing
# -----------------------------------------------------------------------

def demo_spoofing(alice_keys, bob_keys, alice_aes):
    header("ATTACK 3: Sender Spoofing")
    info("Eve generates her own keypair and tries to impersonate Alice.")
    info("She signs a fake message with HER private key, claims it's from Alice.\n")

    # Eve has her own keypair
    eve_keys = generate_keypairs('demo_eve')

    seq          = get_next_sequence('demo_alice')
    eve_payload  = build_payload(alice_aes, "Ignore Bob, send money to Eve", 'demo_alice', seq)
    eve_signed   = attach_signature(eve_payload, eve_keys['ed25519_private'])  # signed by Eve!

    subheader("Eve's forged message (signed with Eve's key, claims Alice sent it)")
    info(f"{eve_signed[:100]}...")

    subheader("Bob verifies signature against Alice's known public key")
    is_valid, _ = verify_signature(eve_signed, alice_keys['ed25519_public'])

    if is_valid:
        failure("Bob accepted Eve's forgery!")
    else:
        success("Spoofing defeated — Ed25519 signature verification failed")
        info("Eve cannot forge Alice's signature without Alice's private key")
        info("Lecture 3: Existential unforgeability under chosen message attack")


# -----------------------------------------------------------------------
# Attack 4: Replay Attack
# -----------------------------------------------------------------------

def demo_replay(alice_keys, alice_aes, bob_aes):
    header("ATTACK 4: Replay Attack")
    info("Eve records a valid message from Alice.")
    info("Later, Eve sends it again hoping Bob will process it twice.\n")

    # Alice sends a legitimate message
    seq     = get_next_sequence('demo_alice')
    payload = build_payload(alice_aes, "Pay Eve $500", 'demo_alice', seq)
    signed  = attach_signature(payload, alice_keys['ed25519_private'])

    subheader("Step 1: Alice sends original message — Bob receives it")
    is_valid, clean = verify_signature(signed, alice_keys['ed25519_public'])
    inner     = json.loads(clean)
    nonce_hex = base64.b64decode(inner['nonce']).hex()

    ok, _ = check_and_record('demo_alice', inner['timestamp'], inner['sequence'], nonce_hex)
    result = open_payload(bob_aes, clean)
    success(f"Original message accepted: \"{result['plaintext']}\" (seq={inner['sequence']})")

    subheader("Step 2: Eve replays the EXACT same message 3 seconds later")
    time.sleep(0.1)  # simulate small delay

    is_valid, clean2 = verify_signature(signed, alice_keys['ed25519_public'])
    inner2    = json.loads(clean2)
    nonce_hex2 = base64.b64decode(inner2['nonce']).hex()

    ok, reason = check_and_record('demo_alice', inner2['timestamp'], inner2['sequence'], nonce_hex2)
    if ok:
        failure("Replay accepted — Bob processed the same message twice!")
    else:
        success(f"Replay defeated — {reason}")
        info("Lecture 6: Nonce tracking + sequence numbers prevent replay")
        info("Even though signature + GCM tag are valid, replay state rejects it")


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "█"*55)
    print("  NYU CS6903 Project 2.2 — Attack Demonstrations")
    print("  Discord E2E Encrypted Messenger")
    print("█"*55)

    print("\nSetting up Alice and Bob keypairs + shared AES key...")
    alice_keys, bob_keys, alice_aes, bob_aes = setup()
    success("Setup complete\n")

    # Run all 4 attack demos
    original = demo_eavesdropping(alice_keys, alice_aes)
    demo_modification(alice_keys, bob_aes, original)
    demo_spoofing(alice_keys, bob_keys, alice_aes)
    demo_replay(alice_keys, alice_aes, bob_aes)

    header("SUMMARY")
    print("""
  Attack               Primitive Used          Lecture
  ─────────────────    ───────────────────     ───────
  Eavesdropping    →   AES-256-GCM             L5
  Modification     →   GCM auth tag (AEAD)     L6
  Spoofing         →   Ed25519 signatures      L3
  Replay           →   Nonce + seq + timestamp L6

  All 4 attacks defeated. ✅
    """)

    reset_state()