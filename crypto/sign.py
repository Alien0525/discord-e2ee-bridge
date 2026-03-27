"""
sign.py — Ed25519 message signing and verification.

Lecture 3 (Trapdoor Permutations / Digital Signatures):
    Signing   : signature = Sign(private_key, message)
    Verifying : Verify(public_key, message, signature) → True/False

    Only the holder of private_key can produce a valid signature.
    Anyone with the corresponding public_key can verify it.
    Security: existential unforgeability under chosen message attack.

Why signatures on top of GCM?
    GCM proves the message wasn't modified and came from someone
    with the AES key — but Alice AND Bob both have that key.
    Signatures prove the message came from Alice specifically,
    because only Alice holds her Ed25519 private key.
    → Defeats data originator spoofing (project spec requirement).

What we sign:
    We sign the CIPHERTEXT (not the plaintext).
    This is the "sign-then-encrypt" question — we actually do
    "encrypt-then-sign":
        1. Encrypt plaintext → ciphertext (encrypt.py)
        2. Sign ciphertext   → signature  (this file)
    This way the signature covers the exact bytes Bob will receive,
    including the nonce and all metadata. Any tampering invalidates
    both the GCM tag AND the signature.
"""

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# -----------------------------------------------------------------------
# Core sign / verify
# -----------------------------------------------------------------------

def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """
    Sign arbitrary bytes with Ed25519.

    Args:
        private_key : sender's Ed25519 private key (from keygen.py)
        data        : bytes to sign — we'll use the full payload JSON

    Returns:
        64-byte Ed25519 signature.

    From Lecture 3:
        signature = Sign(private_key, data)
        Based on Schnorr-style signatures over Curve25519.
        Deterministic — same input always gives same signature.
        (No nonce needed unlike some other schemes.)
    """
    return private_key.sign(data)          # returns 64 raw bytes


def verify(
    public_key: Ed25519PublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        public_key : claimed sender's Ed25519 public key
        data       : the exact bytes that were signed
        signature  : 64-byte signature to check

    Returns:
        True  — signature is valid, data was signed by private_key owner
        False — signature is invalid (tampered, wrong key, or forged)

    Never raises — always returns bool so callers don't need try/except.
    """
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


# -----------------------------------------------------------------------
# Payload-level helpers
# -----------------------------------------------------------------------

def attach_signature(
    payload_json: str,
    private_key: Ed25519PrivateKey,
) -> str:
    """
    Sign a payload JSON string and return a new JSON string with
    the signature embedded.

    Signing covers the entire payload bytes — including ciphertext,
    nonce, sender_id, timestamp, and sequence number. Any change to
    any of these fields will invalidate the signature.

    Input payload (from encrypt.build_payload):
        {"sender_id": "alice", "timestamp": ..., "sequence": ...,
         "nonce": "...", "ciphertext": "..."}

    Output (ready to post to Discord):
        {"sender_id": "alice", "timestamp": ..., "sequence": ...,
         "nonce": "...", "ciphertext": "...",
         "signature": "<base64-encoded 64 bytes>"}
    """
    # Sign the raw payload bytes — must be identical on verify side
    payload_bytes = payload_json.encode("utf-8")
    signature = sign(private_key, payload_bytes)

    # Embed signature into the payload dict
    payload_dict = json.loads(payload_json)
    payload_dict["signature"] = base64.b64encode(signature).decode()

    return json.dumps(payload_dict)


def verify_signature(
    signed_payload_json: str,
    sender_public_key: Ed25519PublicKey,
) -> tuple[bool, str]:
    """
    Extract and verify the signature from a signed payload.

    Args:
        signed_payload_json : full JSON string with "signature" field
        sender_public_key   : claimed sender's Ed25519 public key
                              (fetched from bot's key registry)

    Returns:
        (is_valid, payload_without_signature)
        is_valid                 : True if signature checks out
        payload_without_signature: original payload JSON for decryption

    How it works:
        1. Pull the signature field out of the JSON
        2. Reconstruct the original payload JSON (without signature)
        3. Verify signature over those exact bytes
        4. Return result + clean payload for open_payload()
    """
    payload_dict = json.loads(signed_payload_json)

    # Extract and remove signature — we need the original bytes
    sig_b64 = payload_dict.pop("signature", None)
    if sig_b64 is None:
        return False, ""

    signature = base64.b64decode(sig_b64)

    # Reconstruct original payload JSON exactly as sender built it
    original_payload_json = json.dumps(payload_dict)
    original_payload_bytes = original_payload_json.encode("utf-8")

    is_valid = verify(sender_public_key, original_payload_bytes, signature)

    return is_valid, original_payload_json


# -----------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------

if __name__ == "__main__":
    import os
    from crypto.encrypt import build_payload, open_payload

    print("=" * 55)
    print("TEST 1: Basic sign and verify")
    print("=" * 55)

    alice_priv = Ed25519PrivateKey.generate()
    alice_pub  = alice_priv.public_key()

    msg = b"Hello Bob, signed message"
    sig = sign(alice_priv, msg)

    print(f"  Message   : {msg}")
    print(f"  Signature : {sig.hex()[:48]}...  ({len(sig)} bytes)")
    assert verify(alice_pub, msg, sig), "Valid sig should pass"
    print("  PASS ✓ — valid signature verified\n")

    print("=" * 55)
    print("TEST 2: Tampered message rejected")
    print("=" * 55)

    tampered = b"Hello Bob, TAMPERED message"
    result = verify(alice_pub, tampered, sig)
    assert not result, "Tampered msg should fail"
    print("  PASS ✓ — tampered message signature rejected\n")

    print("=" * 55)
    print("TEST 3: Wrong public key rejected (spoofing attempt)")
    print("=" * 55)

    eve_priv = Ed25519PrivateKey.generate()
    eve_pub  = eve_priv.public_key()

    # Eve tries to verify Alice's signature using Eve's public key
    result = verify(eve_pub, msg, sig)
    assert not result, "Wrong public key should fail"
    print("  PASS ✓ — wrong public key (spoofing) rejected\n")

    print("=" * 55)
    print("TEST 4: Full payload — sign then verify")
    print("=" * 55)

    aes_key = os.urandom(32)
    payload = build_payload(aes_key, "Secret meeting at 9pm", "alice", sequence=5)
    signed  = attach_signature(payload, alice_priv)

    print(f"  Signed payload (Discord-ready):")
    print(f"  {signed[:120]}...\n")

    is_valid, clean_payload = verify_signature(signed, alice_pub)
    assert is_valid, "Should be valid"

    result = open_payload(aes_key, clean_payload)
    print(f"  Signature valid  : {is_valid}")
    print(f"  Decrypted message: {result['plaintext']}")
    print(f"  Sender           : {result['sender_id']}")
    print("  PASS ✓\n")

    print("=" * 55)
    print("TEST 5: Eve forges a message as Alice")
    print("=" * 55)

    # Eve builds her own payload and signs with HER key
    eve_payload = build_payload(aes_key, "Ignore Bob, talk to me", "alice", sequence=6)
    eve_signed  = attach_signature(eve_payload, eve_priv)   # signed with Eve's key

    # Bob checks against Alice's public key — should fail
    is_valid, _ = verify_signature(eve_signed, alice_pub)
    assert not is_valid, "Eve's forgery should be rejected"
    print("  PASS ✓ — Eve's forged message rejected\n")