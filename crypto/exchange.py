"""
exchange.py — ECDH shared secret derivation + HKDF key expansion.

Lecture 3 (Diffie-Hellman):
    shared_secret = ECDH(my_x25519_private, peer_x25519_public)
    Both sides compute the same value without ever transmitting it.

Lecture 6 (HKDF / hash-based key derivation):
    aes_key = HKDF(shared_secret, salt, info)
    Converts the raw ECDH output (which has mathematical structure)
    into a uniformly random AES-256 key safe to use for encryption.

Why HKDF and not just hash(shared_secret)?
    - HKDF uses a salt to prevent output bias even if the shared
      secret is weak or reused.
    - The 'info' field binds the derived key to a specific context
      (e.g. "discord-e2e-aes-key"), so the same shared secret can
      safely derive multiple independent keys for different purposes.
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

AES_KEY_LENGTH   = 32          # 256 bits  — for AES-256-GCM
SALT_LENGTH      = 32          # 256 bits  — random salt for HKDF
HKDF_INFO        = b"discord-e2e-aes-key-v1"   # context binding


# -----------------------------------------------------------------------
# Step 1: ECDH — compute raw shared secret
# -----------------------------------------------------------------------

def ecdh_shared_secret(
    my_private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """
    Perform ECDH: multiply my private scalar by peer's public point.

    Returns 32 raw bytes.

    From Lecture 3:
        shared = F(peer_public, my_private)
               = g^(my_private * peer_private) mod p
        Both sides get the same value. Neither private key is revealed.

    WARNING: Do NOT use this output directly as an AES key.
             Always pass it through derive_aes_key() first.
    """
    raw = my_private_key.exchange(peer_public_key)
    return raw   # 32 bytes, but NOT uniformly random — use HKDF next


# -----------------------------------------------------------------------
# Step 2: HKDF — derive a proper AES-256 key from the raw shared secret
# -----------------------------------------------------------------------

def derive_aes_key(
    shared_secret: bytes,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Run HKDF-SHA256 over the ECDH shared secret to produce an AES-256 key.

    Args:
        shared_secret : Raw bytes from ecdh_shared_secret().
        salt          : 32-byte random salt. If None, a fresh one is
                        generated. The salt must be sent to the peer
                        so they can reproduce the same AES key.

    Returns:
        (aes_key, salt) — both 32 bytes.
            aes_key : ready to use with AES-256-GCM
            salt    : must be shared with peer (not secret, just random)

    From Lecture 6:
        HKDF = HMAC-based Extract-and-Expand Key Derivation Function
        Extract phase : HMAC(salt, shared_secret) -> pseudorandom key
        Expand phase  : stretch pseudorandom key to desired length
        Result is computationally indistinguishable from random bytes.
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=salt,
        info=HKDF_INFO,
    )
    aes_key = hkdf.derive(shared_secret)
    return aes_key, salt


# -----------------------------------------------------------------------
# Step 3: Convenience — do ECDH + HKDF in one call
# -----------------------------------------------------------------------

def derive_shared_aes_key(
    my_private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Full key agreement: ECDH → HKDF → AES-256 key.

    Alice calls this as:
        aes_key, salt = derive_shared_aes_key(alice_priv, bob_pub)
        # Alice sends 'salt' to Bob (not secret)

    Bob calls this as:
        aes_key, _    = derive_shared_aes_key(bob_priv, alice_pub, salt=salt)
        # Bob uses the same salt Alice used -> same aes_key

    Returns:
        (aes_key, salt)
        aes_key : 32-byte AES-256 key  (KEEP SECRET)
        salt    : 32-byte HKDF salt    (share openly with peer)
    """
    raw_secret = ecdh_shared_secret(my_private_key, peer_public_key)
    aes_key, salt = derive_aes_key(raw_secret, salt)
    return aes_key, salt


# -----------------------------------------------------------------------
# Quick self-test
# -----------------------------------------------------------------------

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    # Simulate Alice and Bob each generating keypairs
    alice_priv = X25519PrivateKey.generate()
    alice_pub  = alice_priv.public_key()

    bob_priv   = X25519PrivateKey.generate()
    bob_pub    = bob_priv.public_key()

    # Alice derives the key first (generates salt)
    alice_aes_key, salt = derive_shared_aes_key(alice_priv, bob_pub)

    # Bob derives using same salt Alice used
    bob_aes_key, _      = derive_shared_aes_key(bob_priv, alice_pub, salt=salt)

    print("Alice AES key:", alice_aes_key.hex())
    print("Bob   AES key:", bob_aes_key.hex())
    print()

    assert alice_aes_key == bob_aes_key, "KEY MISMATCH — something is wrong!"
    print("PASS: Alice and Bob derived the same AES-256 key")
    print(f"      Key  : {alice_aes_key.hex()}")
    print(f"      Salt : {salt.hex()} (send this to peer, not secret)")
    print()
    print("Key properties:")
    print(f"  AES key length : {len(alice_aes_key)} bytes = {len(alice_aes_key)*8} bits")
    print(f"  Salt length    : {len(salt)} bytes = {len(salt)*8} bits")