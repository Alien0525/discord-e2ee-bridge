# Discord E2E Encrypted Messenger
### NYU CS6903 Project 2.2

## Overview
End-to-end encrypted messaging over Discord, defending against:
- **Eavesdropping** → AES-256-GCM encryption
- **Modification** → GCM auth tag + HMAC-SHA256
- **Spoofing** → ECDSA signatures (Ed25519)
- **Replay** → Nonce + Timestamp + Sequence number

## Cryptographic Primitives (from class)
| Primitive | Usage | Lecture |
|-----------|-------|---------|
| ECDH (X25519) | Key exchange | Lecture 3 |
| AES-256-GCM | Encryption + integrity | Lecture 5-6 |
| HMAC-SHA256 | Message authentication | Lecture 6 |
| Ed25519 (ECDSA) | Signatures / anti-spoofing | Lecture 3 |
| Nonce + Timestamp | Replay defense | Lecture 6 |

## Project Structure
```
discord_e2e/
├── crypto/
│   ├── keygen.py       # ECDH + Ed25519 key generation
│   ├── exchange.py     # ECDH shared secret derivation
│   ├── encrypt.py      # AES-256-GCM encryption
│   ├── decrypt.py      # AES-256-GCM decryption + verification
│   ├── sign.py         # Ed25519 signing
│   └── replay.py       # Nonce/timestamp/sequence tracking
├── keys/               # Local key storage (NEVER uploaded)
├── bot.py              # Discord bot (dumb relay + key registry)
├── client.py           # Local CLI for send/receive
├── requirements.txt
└── README.md
```

## Setup
```bash
pip install -r requirements.txt
python3 client.py keygen          # Generate your keypair
python3 client.py register        # Register public key with bot
python3 client.py send @user msg  # Send encrypted message
python3 client.py read            # Read + decrypt latest message
```

## Security Notes
- Discord server sees ONLY ciphertext — never plaintext
- Bot is a dumb relay; it holds NO keys and performs NO crypto
- All crypto happens locally on sender/receiver machines
- Keys stored locally in `keys/` directory — keep private!
