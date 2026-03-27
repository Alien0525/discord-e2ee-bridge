"""
bot.py — Discord relay bot for E2E encrypted messaging.

This bot is intentionally a dumb relay. It:
    - Stores users' PUBLIC keys (never private keys)
    - Forwards encrypted payloads between users
    - Shares HKDF salts for key agreement
    - NEVER decrypts, NEVER sees plaintext

Security model:
    Discord + this bot = fully untrusted intermediary.
    Even if Discord or this bot is compromised, an attacker
    only sees ciphertext and public keys — nothing useful.

Setup:
    1. Create a Discord bot at https://discord.com/developers/applications
    2. Copy the bot token into a .env file:  DISCORD_TOKEN=your_token_here
    3. Invite the bot to your server with Send Messages + Read Messages perms
    4. Run: python3 bot.py

Commands:
    !register <x25519_hex> <ed25519_hex>   — register your public keys
    !getkey <username>                      — get someone's public keys
    !send @user <payload_json>              — send encrypted message
    !handshake @user <salt_hex>             — share HKDF salt
    !help                                   — show all commands
"""

import json
import os
import discord
from discord.ext import commands
from pathlib import Path
from dotenv import load_dotenv

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

# In-memory key registry: { "username": { "x25519": "hex...", "ed25519": "hex..." } }
# In a real deployment you'd persist this to a file or database
KEY_REGISTRY: dict[str, dict] = {}

# Persist registry to disk so it survives restarts
REGISTRY_FILE = Path("logs/key_registry.json")

# -----------------------------------------------------------------------
# Bot setup
# -----------------------------------------------------------------------

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


# -----------------------------------------------------------------------
# Registry persistence helpers
# -----------------------------------------------------------------------

def load_registry() -> None:
    """Load key registry from disk on startup."""
    global KEY_REGISTRY
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if REGISTRY_FILE.exists():
        try:
            KEY_REGISTRY = json.loads(REGISTRY_FILE.read_text())
            print(f"[registry] Loaded {len(KEY_REGISTRY)} users from disk")
        except json.JSONDecodeError:
            KEY_REGISTRY = {}


def save_registry() -> None:
    """Persist key registry to disk."""
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(KEY_REGISTRY, indent=2))


# -----------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------

@bot.event
async def on_ready():
    load_registry()
    print(f"[bot] Logged in as {bot.user}")
    print(f"[bot] Registered users: {list(KEY_REGISTRY.keys())}")
    print("[bot] Ready. Waiting for commands...")


# -----------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------

@bot.command(name="help")
async def help_cmd(ctx):
    """Show all available commands."""
    help_text = """
**Discord E2E Encrypted Messenger**
All messages are encrypted end-to-end. The bot only sees ciphertext.

**Commands:**
`!register <x25519_hex> <ed25519_hex>`
  Register your public keys. Run `client.py register` to get these.

`!getkey <username>`
  Get someone's public keys for ECDH key exchange.

`!send @user <payload>`
  Forward an encrypted payload to a user (bot DMs them).

`!handshake @user <salt_hex>`
  Share your HKDF salt so the other user can derive the same AES key.

`!whoregistered`
  List all registered usernames.

**How it works:**
1. Both users run `!register` to publish their public keys
2. Alice runs `client.py keygen` then `client.py send @bob "hello"`
3. Client does ECDH + encrypt + sign locally
4. Bot forwards the ciphertext blob to Bob
5. Bob runs `client.py read` to decrypt locally
"""
    await ctx.send(help_text)


@bot.command(name="register")
async def register(ctx, x25519_hex: str = None, ed25519_hex: str = None):
    """
    Register public keys for the calling user.
    Usage: !register <x25519_public_hex> <ed25519_public_hex>
    """
    if x25519_hex is None or ed25519_hex is None:
        await ctx.send(
            "❌ Usage: `!register <x25519_hex> <ed25519_hex>`\n"
            "Run `python3 client.py register` to get these values."
        )
        return

    # Validate hex strings are correct length (32 bytes = 64 hex chars)
    if len(x25519_hex) != 64 or len(ed25519_hex) != 64:
        await ctx.send(
            f"❌ Keys must be 64 hex characters (32 bytes) each.\n"
            f"Got x25519={len(x25519_hex)} chars, ed25519={len(ed25519_hex)} chars."
        )
        return

    try:
        bytes.fromhex(x25519_hex)
        bytes.fromhex(ed25519_hex)
    except ValueError:
        await ctx.send("❌ Invalid hex strings.")
        return

    username = str(ctx.author)
    KEY_REGISTRY[username] = {
        "x25519":  x25519_hex,
        "ed25519": ed25519_hex,
        "discord_id": ctx.author.id,
    }
    save_registry()

    await ctx.send(
        f"✅ Public keys registered for **{username}**\n"
        f"```\n"
        f"X25519  (ECDH)     : {x25519_hex[:16]}...{x25519_hex[-8:]}\n"
        f"Ed25519 (signature): {ed25519_hex[:16]}...{ed25519_hex[-8:]}\n"
        f"```"
    )
    print(f"[registry] Registered keys for {username}")


@bot.command(name="getkey")
async def getkey(ctx, username: str = None):
    """
    Retrieve a user's public keys.
    Usage: !getkey <username>
    """
    if username is None:
        await ctx.send("❌ Usage: `!getkey <username>`")
        return

    # Try exact match first, then partial
    entry = KEY_REGISTRY.get(username)
    if entry is None:
        # Try case-insensitive partial match
        matches = [k for k in KEY_REGISTRY if username.lower() in k.lower()]
        if len(matches) == 1:
            entry = KEY_REGISTRY[matches[0]]
            username = matches[0]
        elif len(matches) > 1:
            await ctx.send(f"❌ Multiple matches: {matches}. Be more specific.")
            return
        else:
            await ctx.send(
                f"❌ No keys found for `{username}`.\n"
                f"Registered users: {list(KEY_REGISTRY.keys())}"
            )
            return

    await ctx.send(
        f"🔑 Public keys for **{username}**\n"
        f"```\n"
        f"X25519  (ECDH)     : {entry['x25519']}\n"
        f"Ed25519 (signature): {entry['ed25519']}\n"
        f"```"
    )


@bot.command(name="send")
async def send_msg(ctx, recipient: discord.Member = None, *, payload: str = None):
    """
    Forward an encrypted payload to a recipient via DM.
    Usage: !send @user <encrypted_payload_json>

    The bot forwards the payload without reading it.
    Only the recipient (with the correct AES key) can decrypt.
    """
    if recipient is None or payload is None:
        await ctx.send("❌ Usage: `!send @user <encrypted_payload>`")
        return

    # Validate payload is JSON (basic sanity check — bot doesn't read content)
    try:
        parsed = json.loads(payload)
        required = {"sender_id", "timestamp", "sequence", "nonce", "ciphertext", "signature"}
        missing = required - set(parsed.keys())
        if missing:
            await ctx.send(f"❌ Payload missing fields: {missing}")
            return
    except json.JSONDecodeError:
        await ctx.send("❌ Payload must be valid JSON.")
        return

    sender_name = str(ctx.author)

    # Forward to recipient via DM
    try:
        await recipient.send(
            f"📨 **Encrypted message from {sender_name}**\n"
            f"```json\n{payload}\n```\n"
            f"*Run `python3 client.py read` to decrypt.*"
        )
        await ctx.send(f"✅ Encrypted message forwarded to **{recipient.display_name}**.")
        print(f"[relay] Forwarded message from {sender_name} to {recipient}")
    except discord.Forbidden:
        await ctx.send(
            f"❌ Cannot DM {recipient.mention}. "
            "They may have DMs disabled."
        )


@bot.command(name="handshake")
async def handshake(ctx, recipient: discord.Member = None, *, salt_hex: str = None):
    """
    Share your HKDF salt with a specific user.
    Usage: !handshake @user <salt_hex>

    The salt is NOT secret — it's safe to share publicly.
    The recipient needs it to derive the same AES key as you.
    """
    if recipient is None or salt_hex is None:
        await ctx.send("❌ Usage: `!handshake @user <salt_hex>`")
        return

    if len(salt_hex) != 64:
        await ctx.send(f"❌ Salt must be 64 hex chars (32 bytes). Got {len(salt_hex)}.")
        return

    try:
        bytes.fromhex(salt_hex)
    except ValueError:
        await ctx.send("❌ Invalid hex string.")
        return

    sender_name = str(ctx.author)

    try:
        await recipient.send(
            f"🤝 **Key handshake from {sender_name}**\n"
            f"```\nHKDF Salt: {salt_hex}\n```\n"
            f"*Run `python3 client.py handshake {sender_name} {salt_hex}` "
            f"to complete key agreement.*"
        )
        await ctx.send(f"✅ Handshake salt sent to **{recipient.display_name}**.")
        print(f"[handshake] {sender_name} → {recipient}: salt shared")
    except discord.Forbidden:
        await ctx.send(f"❌ Cannot DM {recipient.mention}.")


@bot.command(name="whoregistered")
async def who_registered(ctx):
    """List all users who have registered public keys."""
    if not KEY_REGISTRY:
        await ctx.send("No users registered yet. Use `!register` first.")
        return

    names = "\n".join(f"  • {name}" for name in KEY_REGISTRY.keys())
    await ctx.send(f"**Registered users ({len(KEY_REGISTRY)}):**\n{names}")


# -----------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Missing argument: `{error.param.name}`. Try `!help`.")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send(f"❌ User not found. Make sure to @mention them.")
    elif isinstance(error, commands.CommandNotFound):
        pass   # silently ignore unknown commands
    else:
        await ctx.send(f"❌ Error: {error}")
        raise error


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

if __name__ == "__main__":
    if not TOKEN:
        print("ERROR: DISCORD_TOKEN not found.")
        print("Create a .env file with:  DISCORD_TOKEN=your_bot_token_here")
        print("Get a token at: https://discord.com/developers/applications")
        exit(1)
    bot.run(TOKEN)