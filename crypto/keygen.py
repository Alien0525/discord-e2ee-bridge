"""
keygen.py — X25519 + Ed25519 keypair generation, serialization, and loading.

Key files are stored under keys/<username>/ as PEM files:
  x25519_private.pem   — X25519 private key  (ECDH key exchange)
  x25519_public.pem    — X25519 public key
  ed25519_private.pem  — Ed25519 private key (signatures / anti-spoofing)
  ed25519_public.pem   — Ed25519 public key
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    BestAvailableEncryption,
    load_pem_private_key,
    load_pem_public_key,
)

# Root of the keys/ directory relative to this file's package
_KEYS_DIR = Path(__file__).parent.parent / "keys"


def _user_dir(username: str) -> Path:
    """Return (and create if needed) the per-user key directory."""
    d = _KEYS_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate a fresh X25519 keypair for ECDH key exchange."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair for message signing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_keypairs(username: str, password: bytes | None = None) -> dict:
    """
    Generate both keypairs for *username* and save them to keys/<username>/.

    Args:
        username: Identity string (e.g. Discord username).
        password: If provided, private keys are encrypted with this password
                  using AES-256-CBC (BestAvailableEncryption). Pass None to
                  store unencrypted (suitable for local dev / demos).

    Returns:
        Dict with keys 'x25519_private', 'x25519_public',
                        'ed25519_private', 'ed25519_public'.
    """
    x_priv, x_pub = generate_x25519_keypair()
    e_priv, e_pub = generate_ed25519_keypair()

    encryption = (
        BestAvailableEncryption(password) if password else NoEncryption()
    )

    user_dir = _user_dir(username)

    # --- X25519 ---
    (user_dir / "x25519_private.pem").write_bytes(
        x_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
    )
    (user_dir / "x25519_public.pem").write_bytes(
        x_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    # --- Ed25519 ---
    (user_dir / "ed25519_private.pem").write_bytes(
        e_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
    )
    (user_dir / "ed25519_public.pem").write_bytes(
        e_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    return {
        "x25519_private": x_priv,
        "x25519_public": x_pub,
        "ed25519_private": e_priv,
        "ed25519_public": e_pub,
    }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_private_keys(username: str, password: bytes | None = None) -> dict:
    """
    Load both private keys for *username* from keys/<username>/.

    Returns:
        Dict with 'x25519_private' and 'ed25519_private'.

    Raises:
        FileNotFoundError: if keys haven't been generated yet.
        ValueError: if the password is wrong or keys are corrupt.
    """
    user_dir = _user_dir(username)

    x_priv = load_pem_private_key(
        (user_dir / "x25519_private.pem").read_bytes(),
        password=password,
    )
    e_priv = load_pem_private_key(
        (user_dir / "ed25519_private.pem").read_bytes(),
        password=password,
    )

    if not isinstance(x_priv, X25519PrivateKey):
        raise ValueError("x25519_private.pem does not contain an X25519 key")
    if not isinstance(e_priv, Ed25519PrivateKey):
        raise ValueError("ed25519_private.pem does not contain an Ed25519 key")

    return {"x25519_private": x_priv, "ed25519_private": e_priv}


def load_public_keys(username: str) -> dict:
    """
    Load both public keys for *username* from keys/<username>/.

    Returns:
        Dict with 'x25519_public' and 'ed25519_public'.
    """
    user_dir = _user_dir(username)

    x_pub = load_pem_public_key(
        (user_dir / "x25519_public.pem").read_bytes()
    )
    e_pub = load_pem_public_key(
        (user_dir / "ed25519_public.pem").read_bytes()
    )

    if not isinstance(x_pub, X25519PublicKey):
        raise ValueError("x25519_public.pem does not contain an X25519 key")
    if not isinstance(e_pub, Ed25519PublicKey):
        raise ValueError("ed25519_public.pem does not contain an Ed25519 key")

    return {"x25519_public": x_pub, "ed25519_public": e_pub}


def load_all_keys(username: str, password: bytes | None = None) -> dict:
    """Convenience: load all four keys for *username*."""
    return {**load_private_keys(username, password), **load_public_keys(username)}


# ---------------------------------------------------------------------------
# Public-key export (raw bytes, for sharing over Discord)
# ---------------------------------------------------------------------------

def export_public_keys_bytes(username: str) -> dict[str, bytes]:
    """
    Return the raw 32-byte public key material for both keys.

    These compact representations are what gets exchanged during the
    handshake phase — small enough to embed in a Discord message.
    """
    keys = load_public_keys(username)
    return {
        "x25519_public": keys["x25519_public"].public_bytes_raw(),
        "ed25519_public": keys["ed25519_public"].public_bytes_raw(),
    }


def import_peer_x25519_public(raw_bytes: bytes) -> X25519PublicKey:
    """Reconstruct a peer's X25519 public key from 32 raw bytes."""
    return X25519PublicKey.from_public_bytes(raw_bytes)


def import_peer_ed25519_public(raw_bytes: bytes) -> Ed25519PublicKey:
    """Reconstruct a peer's Ed25519 public key from 32 raw bytes."""
    return Ed25519PublicKey.from_public_bytes(raw_bytes)


# ---------------------------------------------------------------------------
# CLI helper — run directly to generate keys for a user
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    username = sys.argv[1] if len(sys.argv) > 1 else input("Username: ")
    use_password = input("Password-protect private keys? [y/N]: ").strip().lower() == "y"
    password = None
    if use_password:
        import getpass
        pw = getpass.getpass("Key password: ")
        password = pw.encode()

    keys = generate_keypairs(username, password)
    print(f"\nKeys generated for '{username}' in keys/{username}/")
    print(f"  X25519  public : {keys['x25519_public'].public_bytes_raw().hex()}")
    print(f"  Ed25519 public : {keys['ed25519_public'].public_bytes_raw().hex()}")
