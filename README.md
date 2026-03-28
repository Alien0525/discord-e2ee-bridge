# Discord E2E Encrypted Messenger

End-to-end encrypted messaging over Discord. Discord sees only ciphertext — never plaintext. The bot is a dumb relay; all cryptography happens locally on your machine.

## Security Guarantees

| Threat | Defense |
|--------|---------|
| Eavesdropping (Discord, bot, network) | AES-256-GCM encryption |
| Message tampering | GCM authentication tag |
| Spoofing (fake sender) | Ed25519 signatures |
| Replay attacks | Nonce + timestamp + per-sender sequence numbers |

## Cryptographic Primitives

| Primitive | Role | Lecture |
|-----------|------|---------|
| X25519 (ECDH) | Key exchange | Lecture 3 |
| HKDF-SHA256 | Key derivation from shared secret | Lecture 6 |
| AES-256-GCM | Authenticated encryption | Lectures 5–6 |
| Ed25519 | Message signing / anti-spoofing | Lecture 3 |
| Nonce + timestamp + sequence | Replay defense | Lecture 6 |

## Project Structure

```
discord_e2e/
├── crypto/
│   ├── keygen.py       # X25519 + Ed25519 keypair generation & loading
│   ├── exchange.py     # ECDH shared secret → HKDF → AES-256 key
│   ├── encrypt.py      # AES-256-GCM encrypt/decrypt + payload builder
│   ├── sign.py         # Ed25519 sign + verify
│   └── replay.py       # Nonce / timestamp / sequence tracking
├── keys/               # Local key storage — never leave this machine
├── logs/               # Per-user peer data + replay state
├── bot.py              # Discord bot: public key registry + message relay
├── client.py           # CLI: keygen, register, send, read, handshake
└── requirements.txt
```

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create a `.env` file with your bot token
```
DISCORD_TOKEN=your_token_here
```

### 3. Start the bot (leave this running)
```bash
python3 bot.py
```

### 4. Each user: set up their identity (once)
```bash
python3 client.py keygen              # generate keypairs
python3 client.py login <username>    # set active session
export DISCORD_E2E_USER=<username>    # lock this terminal to you
python3 client.py register            # paste the !register command into Discord
```

### 5. Add your peer (after they register)
```
!getkey <peer_username>               # run in Discord → copy the addpeer line
python3 client.py addpeer <peer> <x25519> <ed25519>
```

### 6. Handshake (once per pair)
```bash
python3 client.py handshake <peer>    # paste !handshake into Discord
# peer runs the command from the bot's DM to complete
```

### 7. Send and receive
```bash
python3 client.py send <peer> 'message'   # paste !send into Discord
python3 client.py read '<json>'           # decrypt a message from the bot DM
```

## Two Users on One Machine

Since keys and session are local, two users can share a machine by using separate terminals with the env var:

```bash
# Terminal 1
export DISCORD_E2E_USER=alice

# Terminal 2
export DISCORD_E2E_USER=bob
```

Each terminal acts as its own user — no conflicts.

## Bot Commands (Discord)

| Command | Description |
|---------|-------------|
| `!register <x25519> <ed25519>` | Publish your public keys |
| `!getkey <username>` | Get a peer's keys + ready-to-run addpeer command |
| `!send @user <payload>` | Forward encrypted message (bot DMs recipient) |
| `!handshake @user <salt>` | Share HKDF salt (bot DMs recipient with instructions) |
| `!whoregistered` | List all registered users |
| `!help` | Show all commands |

## Client Commands

| Command | Description |
|---------|-------------|
| `login <username>` | Set active session |
| `whoami` | Show active session |
| `keygen [username]` | Generate keypairs |
| `register` | Print `!register` command for Discord |
| `addpeer <peer> <x25519> <ed25519>` | Store a peer's public keys |
| `handshake <peer> [salt]` | Initiate or complete key agreement |
| `send <peer> <message>` | Encrypt and print `!send` command |
| `read [payload]` | Decrypt a received message |
| `peers` | List known peers and handshake status |
| `debug` | Show raw peer data (for diagnosing key mismatches) |
| `showkeys` | Display your public keys |

## Replay Attack Defense

Three interlocking layers (all must pass):

1. **Timestamp window** — messages older than 24 hours are rejected
2. **Sequence numbers** — per-sender strictly increasing counter; out-of-order or repeated sequences rejected
3. **Nonce tracking** — every GCM nonce is recorded; exact duplicates rejected even within the time window

State persists across restarts in `logs/replay_state.json`.

## Security Notes

- `keys/` contains your private keys — never share or upload this directory
- The bot holds only public keys; it cannot decrypt anything
- HKDF salt is not secret — it is safe to share over Discord
- Replay state must not be deleted between sessions or old messages could be re-delivered