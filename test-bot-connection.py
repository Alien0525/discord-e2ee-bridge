"""
test_bot_connection.py — Verify your Discord token works.
Run this before bot.py to confirm setup is correct.

Usage: python3 test_bot_connection.py
"""

import os
import asyncio
import discord
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

if not TOKEN or TOKEN == "your_bot_token_here":
    print("❌ No token found.")
    print("   1. Copy .env.example to .env")
    print("   2. Replace 'your_bot_token_here' with your real token")
    exit(1)

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f"✅ Bot connected successfully!")
    print(f"   Username : {client.user.name}")
    print(f"   ID       : {client.user.id}")
    print(f"   Servers  : {[g.name for g in client.guilds]}")
    print()
    print("Your bot is working. Now run: python3 bot.py")
    await client.close()

print("Testing connection...")
client.run(TOKEN)