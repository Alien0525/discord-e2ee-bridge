"""
encrypt.py — AES-256-GCM authenticated encryption.

Lecture 5 (IND-CMA secure encryption):
    AES in CTR mode with a fresh random nonce per message.
    Enc(k, m) = (nonce, AES-CTR(k, nonce, m))
    A fresh nonce ensures the keystream is never reused.

Lecture 6 (Authenticated Encryption / IND-CCA):
    GCM appends a 128-bit authentication tag to the ciphertext.
    This is the "encrypt-then-MAC" construction:
        tag = GMAC(k, nonce, ciphertext, aad)
    Decryption REJECTS any ciphertext with an invalid tag.
    Defeats: eavesdropping, modification, and chosen-ciphertext attacks.

Why GCM specifically?
    - One key does both encryption AND authentication (efficient)
    - Tag covers Additional Authenticated Data (AAD) too — we use
      this to authenticate the sender_id and timestamp without
      encrypting them, so the bot can read metadata but not content.
    - Widely standardized, hardware-accelerated on modern CPUs.

Nonce rule (CRITICAL):
    NEVER reuse a (key, nonce) pair.
    Reuse lets an attacker XOR two ciphertexts and cancel the
    keystream — same flaw as reusing a one-time pad (Lecture 1).
    We use os.urandom(12) for each message → collision probability
    is negligible for any realistic number of messages.
"""

import os
import json
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

NONCE_LENGTH = 12          # 96 bits  — GCM standard nonce size
TAG_LENGTH   = 16          # 128 bits — GCM authentication tag (built-in)


# -----------------------------------------------------------------------
# Core encryption
# -----------------------------------------------------------------------

def encrypt(
    aes_key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        aes_key   : 32-byte AES-256 key from exchange.py
        plaintext : message bytes to encrypt
        aad       : Additional Authenticated Data (optional).
                    Authenticated but NOT encrypted — visible in transit.
                    Use for metadata like sender_id, timestamp.

    Returns:
        (nonce, ciphertext_with_tag)
        nonce              : 12 random bytes — send alongside ciphertext
        ciphertext_with_tag: encrypted bytes + 16-byte GCM auth tag

    From Lecture 5:
        Nonce plays the role of 'r' in Enc(k,m) = (r, F(k,r) XOR m)
        Fresh nonce per message = fresh keystream = IND-CMA secure
    """
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)}")

    # Fresh random nonce — NEVER reuse with the same key
    nonce = os.urandom(NONCE_LENGTH)

    aesgcm = AESGCM(aes_key)

    # encrypt() returns ciphertext + 16-byte tag concatenated
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext_with_tag


def decrypt(
    aes_key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes | None = None,
) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Raises:
        cryptography.exceptions.InvalidTag  if the tag is wrong —
        meaning the ciphertext was tampered with, the key is wrong,
        or the AAD doesn't match. NEVER use the output if this raises.

    From Lecture 6:
        GCM tag verification is the MAC check in "encrypt-then-MAC".
        If verification fails → message was modified → reject entirely.
        This gives IND-CCA security.
    """
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)}")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"Nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")

    aesgcm = AESGCM(aes_key)

    # Raises InvalidTag automatically if authentication fails
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    return plaintext


# -----------------------------------------------------------------------
# Message payload builder
# -----------------------------------------------------------------------

def build_payload(
    aes_key: bytes,
    plaintext: str,
    sender_id: str,
    sequence: int,
) -> str:
    """
    Build a complete encrypted message payload ready to post to Discord.

    Structure:
        {
            "sender_id"  : "alice",          # plaintext — for routing
            "timestamp"  : 1712345678.123,   # for replay defense
            "sequence"   : 42,               # for replay defense
            "nonce"      : "<base64>",       # 12 bytes
            "ciphertext" : "<base64>",       # encrypted msg + GCM tag
        }

    AAD (authenticated but not encrypted):
        sender_id + timestamp + sequence are included in the GCM tag
        computation. This means:
          - Bot/attacker can READ metadata (needed for routing)
          - But CANNOT MODIFY it without breaking the GCM tag
          → defeats message modification attack on metadata

    Returns:
        JSON string safe to post as a Discord message.
    """
    timestamp = time.time()

    # Build AAD from metadata — binds ciphertext to this exact sender/time/seq
    aad = _build_aad(sender_id, timestamp, sequence)

    nonce, ciphertext_with_tag = encrypt(
        aes_key,
        plaintext.encode("utf-8"),
        aad=aad,
    )

    payload = {
        "sender_id"  : sender_id,
        "timestamp"  : timestamp,
        "sequence"   : sequence,
        "nonce"      : base64.b64encode(nonce).decode(),
        "ciphertext" : base64.b64encode(ciphertext_with_tag).decode(),
    }

    return json.dumps(payload)


def open_payload(
    aes_key: bytes,
    payload_json: str,
) -> dict:
    """
    Decode and decrypt a payload produced by build_payload().

    Returns:
        {
            "plaintext"  : "hello bob",
            "sender_id"  : "alice",
            "timestamp"  : 1712345678.123,
            "sequence"   : 42,
        }

    Raises:
        InvalidTag   : ciphertext was tampered with
        KeyError     : payload is missing required fields
        ValueError   : nonce or ciphertext are malformed
    """
    payload = json.loads(payload_json)

    sender_id = payload["sender_id"]
    timestamp = payload["timestamp"]
    sequence  = payload["sequence"]
    nonce     = base64.b64decode(payload["nonce"])
    ciphertext_with_tag = base64.b64decode(payload["ciphertext"])

    # Reconstruct AAD — must match what sender used exactly
    aad = _build_aad(sender_id, timestamp, sequence)

    plaintext_bytes = decrypt(aes_key, nonce, ciphertext_with_tag, aad)

    return {
        "plaintext" : plaintext_bytes.decode("utf-8"),
        "sender_id" : sender_id,
        "timestamp" : timestamp,
        "sequence"  : sequence,
    }


# -----------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------

def _build_aad(sender_id: str, timestamp: float, sequence: int) -> bytes:
    """
    Encode metadata as AAD bytes.
    Format: "sender_id:timestamp:sequence" as UTF-8.
    Both sides must produce identical bytes for GCM tag to verify.
    """
    return f"{sender_id}:{timestamp}:{sequence}".encode("utf-8")


# -----------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------

if __name__ == "__main__":
    from cryptography.exceptions import InvalidTag

    # Simulate a 32-byte AES key (in real use, comes from exchange.py)
    aes_key = os.urandom(32)

    print("=" * 55)
    print("TEST 1: Basic encrypt / decrypt")
    print("=" * 55)
    msg = "Hello Bob, this is a secret message!"
    nonce, ct = encrypt(aes_key, msg.encode())
    recovered = decrypt(aes_key, nonce, ct)
    assert recovered.decode() == msg
    print(f"  Original  : {msg}")
    print(f"  Nonce     : {nonce.hex()} ({len(nonce)} bytes)")
    print(f"  Ciphertext: {ct.hex()[:48]}...  ({len(ct)} bytes incl. tag)")
    print(f"  Recovered : {recovered.decode()}")
    print("  PASS ✓\n")

    print("=" * 55)
    print("TEST 2: Tamper detection (modified ciphertext)")
    print("=" * 55)
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF          # flip bits in first byte
    try:
        decrypt(aes_key, nonce, bytes(tampered))
        print("  FAIL — should have raised InvalidTag!")
    except InvalidTag:
        print("  PASS ✓ — InvalidTag raised, tampered message rejected\n")

    print("=" * 55)
    print("TEST 3: Full payload (with sender_id, timestamp, sequence)")
    print("=" * 55)
    payload = build_payload(aes_key, "Meet me at 7pm", "alice", sequence=1)
    print(f"  Payload (Discord-ready):\n  {payload}\n")

    result = open_payload(aes_key, payload)
    print(f"  Decrypted plaintext : {result['plaintext']}")
    print(f"  Sender              : {result['sender_id']}")
    print(f"  Sequence            : {result['sequence']}")
    print("  PASS ✓\n")

    print("=" * 55)
    print("TEST 4: Modified metadata (AAD tampering)")
    print("=" * 55)
    import json as _json
    evil_payload = _json.loads(payload)
    evil_payload["sender_id"] = "eve"   # attacker tries to change sender
    try:
        open_payload(aes_key, _json.dumps(evil_payload))
        print("  FAIL — should have raised InvalidTag!")
    except InvalidTag:
        print("  PASS ✓ — sender_id tampering detected via AAD\n")