"""
bot.py — Discord relay bot for E2E encrypted messaging.

This bot is intentionally a dumb relay. It:
    - Stores users' PUBLIC keys (never private keys)
    - Forwards encrypted payloads between users via DM
    - Shares HKDF salts for key agreement

Setup:
    1. Create a Discord bot at https://discord.com/developers/applications
    2. Copy the bot token into a .env file:  DISCORD_TOKEN=your_token_here
    3. Invite the bot with Send Messages + Read Messages + Read Message History perms
    4. Run: python3 bot.py
"""

import json
import os
import discord
from discord.ext import commands
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

KEY_REGISTRY: dict[str, dict] = {}
REGISTRY_FILE = Path("logs/key_registry.json")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


# -----------------------------------------------------------------------
# Registry persistence
# -----------------------------------------------------------------------

def load_registry() -> None:
    global KEY_REGISTRY
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if REGISTRY_FILE.exists():
        try:
            KEY_REGISTRY = json.loads(REGISTRY_FILE.read_text())
            print(f"[registry] Loaded {len(KEY_REGISTRY)} users from disk")
        except json.JSONDecodeError:
            KEY_REGISTRY = {}


def save_registry() -> None:
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(KEY_REGISTRY, indent=2))


def find_user(query: str) -> tuple[str | None, dict | None]:
    """
    Look up a registry entry by:
      1. Exact username string match
      2. Discord mention <@id> — matched by stored discord_id
      3. Case-insensitive partial match on username
    Returns (username_key, entry) or (None, None).
    """
    # Strip Discord mention format <@123456789>
    mention_id = None
    if query.startswith("<@") and query.endswith(">"):
        try:
            mention_id = int(query[2:-1].lstrip("!"))
        except ValueError:
            pass

    if mention_id is not None:
        for key, entry in KEY_REGISTRY.items():
            if entry.get("discord_id") == mention_id:
                return key, entry
        return None, None

    # Exact match
    if query in KEY_REGISTRY:
        return query, KEY_REGISTRY[query]

    # Case-insensitive partial match
    matches = [k for k in KEY_REGISTRY if query.lower() in k.lower()]
    if len(matches) == 1:
        return matches[0], KEY_REGISTRY[matches[0]]
    if len(matches) > 1:
        return f"AMBIGUOUS:{matches}", None

    return None, None


# -----------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------

@bot.event
async def on_ready():
    load_registry()
    print(f"[bot] Logged in as {bot.user}")
    print(f"[bot] Registered users: {list(KEY_REGISTRY.keys())}")
    print("[bot] Ready.")


# -----------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------

@bot.command(name="help")
async def help_cmd(ctx):
    await ctx.send("""
**Discord E2E Encrypted Messenger**

`!register <x25519_hex> <ed25519_hex>` — register your public keys
`!getkey <username_or_@mention>` — get someone's keys + ready-to-run addpeer command
`!send @user <payload>` — forward an encrypted message (bot DMs them)
`!handshake @user <salt_hex>` — share your HKDF salt (bot DMs them)
`!whoregistered` — list all registered users

**Quick start:**
1. `python3 client.py keygen <you>` then `python3 client.py login <you>`
2. `python3 client.py register` → paste `!register ...` here
3. `!getkey @peer` → copy the `addpeer` line → run it in terminal
4. `python3 client.py handshake <peer>` → paste `!handshake @peer <salt>` here
5. `python3 client.py send <peer> "hello"` → paste `!send @peer ...` here
6. Receiver: `python3 client.py read` → paste the JSON from DM
""")


@bot.command(name="register")
async def register(ctx, x25519_hex: str = None, ed25519_hex: str = None):
    if x25519_hex is None or ed25519_hex is None:
        await ctx.send("❌ Usage: `!register <x25519_hex> <ed25519_hex>`\nRun `python3 client.py register` to get these.")
        return

    if len(x25519_hex) != 64 or len(ed25519_hex) != 64:
        await ctx.send(f"❌ Keys must be 64 hex chars each. Got {len(x25519_hex)} and {len(ed25519_hex)}.")
        return

    try:
        bytes.fromhex(x25519_hex)
        bytes.fromhex(ed25519_hex)
    except ValueError:
        await ctx.send("❌ Invalid hex strings.")
        return

    username = str(ctx.author)
    KEY_REGISTRY[username] = {
        "x25519":     x25519_hex,
        "ed25519":    ed25519_hex,
        "discord_id": ctx.author.id,
    }
    save_registry()

    await ctx.send(
        f"✅ Public keys registered for **{username}**\n"
        f"```\n"
        f"X25519  : {x25519_hex[:16]}...{x25519_hex[-8:]}\n"
        f"Ed25519 : {ed25519_hex[:16]}...{ed25519_hex[-8:]}\n"
        f"```"
    )
    print(f"[registry] Registered {username}")


@bot.command(name="getkey")
async def getkey(ctx, *, query: str = None):
    """
    Get a user's public keys. Accepts username or @mention.
    Outputs a ready-to-run terminal command for addpeer.
    """
    if query is None:
        await ctx.send("❌ Usage: `!getkey <username>` or `!getkey @mention`")
        return

    query = query.strip()
    username, entry = find_user(query)

    if username and username.startswith("AMBIGUOUS:"):
        matches = username[10:]
        await ctx.send(f"❌ Multiple matches: {matches}. Be more specific.")
        return

    if entry is None:
        registered = list(KEY_REGISTRY.keys())
        await ctx.send(
            f"❌ No keys found for `{query}`.\n"
            f"Registered users: `{'`, `'.join(registered) if registered else 'none'}`"
        )
        return

    x25519  = entry["x25519"]
    ed25519 = entry["ed25519"]

    # Give the exact terminal command to run — no manual copying of separate keys
    addpeer_cmd = f"python3 client.py addpeer {username} {x25519} {ed25519}"

    await ctx.send(
        f"🔑 **Keys for {username}**\n"
        f"Run this in your terminal:\n"
        f"```\n{addpeer_cmd}\n```"
    )


@bot.command(name="send")
async def send_msg(ctx, recipient: discord.Member = None, *, payload: str = None):
    if recipient is None or payload is None:
        await ctx.send("❌ Usage: `!send @user <encrypted_payload>`")
        return

    try:
        parsed = json.loads(payload)
        required = {"sender_id", "timestamp", "sequence", "nonce", "ciphertext", "signature"}
        missing  = required - set(parsed.keys())
        if missing:
            await ctx.send(f"❌ Payload missing fields: {missing}")
            return
    except json.JSONDecodeError:
        await ctx.send("❌ Payload must be valid JSON.")
        return

    sender_name = str(ctx.author)

    try:
        await recipient.send(
            f"📨 **Encrypted message from {sender_name}**\n"
            f"Run this command to decrypt:\n"
            f"```\npython3 client.py read '{payload}'\n```"
        )
        await ctx.send(f"✅ Message forwarded to **{recipient.display_name}**.")
        print(f"[relay] {sender_name} → {recipient}")
    except discord.Forbidden:
        await ctx.send(f"❌ Cannot DM {recipient.mention} — they may have DMs disabled.")


@bot.command(name="handshake")
async def handshake(ctx, recipient: discord.Member = None, *, salt_hex: str = None):
    if recipient is None or salt_hex is None:
        await ctx.send("❌ Usage: `!handshake @user <salt_hex>`")
        return

    if len(salt_hex) != 64:
        await ctx.send(f"❌ Salt must be 64 hex chars. Got {len(salt_hex)}.")
        return

    try:
        bytes.fromhex(salt_hex)
    except ValueError:
        await ctx.send("❌ Invalid hex string.")
        return

    sender_name = str(ctx.author)

    # Build the exact command the receiver needs to run
    handshake_cmd = f"python3 client.py handshake {sender_name} {salt_hex}"

    try:
        await recipient.send(
            f"🤝 **Key handshake from {sender_name}**\n"
            f"Run this in your terminal to complete key agreement:\n"
            f"```\n{handshake_cmd}\n```"
        )
        await ctx.send(f"✅ Handshake salt sent to **{recipient.display_name}**.")
        print(f"[handshake] {sender_name} → {recipient}")
    except discord.Forbidden:
        await ctx.send(f"❌ Cannot DM {recipient.mention}.")


@bot.command(name="whoregistered")
async def who_registered(ctx):
    if not KEY_REGISTRY:
        await ctx.send("No users registered yet.")
        return
    names = "\n".join(f"  • {name}" for name in KEY_REGISTRY.keys())
    await ctx.send(f"**Registered ({len(KEY_REGISTRY)}):**\n{names}")


# -----------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Missing argument: `{error.param.name}`. Try `!help`.")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send(f"❌ User not found. Use @mention to tag them.")
    elif isinstance(error, commands.CommandNotFound):
        pass
    else:
        await ctx.send(f"❌ Error: {error}")
        raise error


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

if __name__ == "__main__":
    if not TOKEN:
        print("ERROR: DISCORD_TOKEN not found in .env file.")
        print("Create a .env file:  DISCORD_TOKEN=your_token_here")
        exit(1)
    bot.run(TOKEN)