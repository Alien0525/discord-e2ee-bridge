"""
replay.py — Replay, re-ordering, and reflection attack defense.

Lecture 6 (Secure Message Transmission):
    The MAC security definition does NOT capture replay attacks.
    Solution: combine timestamps + session tokens (nonces) + sequence numbers.

    From the lecture's secure transmission scheme:
        Enc'(k,m): compute timestamp ts, ciphertext c1, tag t = Tag(k2, c1|ts)
        Dec'(k,…): check ts is 'recent'; verify tag; decrypt

    We implement three interlocking defenses:

    1. TIMESTAMP WINDOW (±60 seconds)
       Sender attaches time.time() to every message.
       Receiver rejects messages outside a 60-second window.
       → Replays more than 60s old are rejected automatically.
       Weakness alone: attacker can replay within the window.

    2. SEQUENCE NUMBERS (per sender, strictly increasing)
       Each sender maintains a counter: seq=1, seq=2, seq=3, ...
       Receiver tracks the highest seq seen per sender.
       Rejects any message with seq <= last seen.
       → Defeats re-ordering and replays of old messages.
       Weakness alone: attacker could replay the latest message
       within the same sequence slot.

    3. NONCE TRACKING (exact replay detection)
       Every message has a unique 12-byte GCM nonce (from encrypt.py).
       Receiver stores every nonce it has ever accepted.
       Rejects any message whose nonce was seen before.
       → Defeats exact replays even within the time window.

    All three together close every gap.

State persistence:
    Replay state is saved to logs/replay_state.json so it survives
    process restarts. Without persistence, an attacker could replay
    messages from a previous session after the receiver restarts.
"""

import json
import os
import time
from pathlib import Path

# -----------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------

TIMESTAMP_WINDOW_SECS = 60       # reject messages older than this
STATE_FILE = Path(__file__).parent.parent / "logs" / "replay_state.json"


# -----------------------------------------------------------------------
# State management
# -----------------------------------------------------------------------

def _load_state() -> dict:
    """
    Load replay-defense state from disk.

    State structure:
    {
        "seen_nonces":   ["aabbcc...", "ddeeff...", ...],
        "last_seq":      {"alice": 5, "bob": 3, ...}
    }
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not STATE_FILE.exists():
        return {"seen_nonces": [], "last_seq": {}}

    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, KeyError):
        # Corrupted state — start fresh (safe: just re-enables replays
        # of very old messages, which timestamp defense catches anyway)
        return {"seen_nonces": [], "last_seq": {}}


def _save_state(state: dict) -> None:
    """Persist replay-defense state to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


# -----------------------------------------------------------------------
# The three checks
# -----------------------------------------------------------------------

def _check_timestamp(timestamp: float) -> tuple[bool, str]:
    """
    Layer 1: Reject messages outside the ±60 second window.

    Why ±60 and not just "older than 60"?
        Clock skew — sender and receiver clocks may differ slightly.
        We allow small future timestamps for tolerance.
    """
    now = time.time()
    age = now - timestamp

    if age > TIMESTAMP_WINDOW_SECS:
        return False, f"Message too old: {age:.1f}s (max {TIMESTAMP_WINDOW_SECS}s)"

    if age < -TIMESTAMP_WINDOW_SECS:
        return False, f"Message timestamp too far in future: {-age:.1f}s"

    return True, ""


def _check_sequence(
    state: dict,
    sender_id: str,
    sequence: int,
) -> tuple[bool, str]:
    """
    Layer 2: Reject messages with sequence number <= last seen.

    Strictly increasing per sender — gaps are allowed (network drops)
    but going backwards is not.
    """
    last = state["last_seq"].get(sender_id, -1)

    if sequence <= last:
        return False, (
            f"Sequence number {sequence} already seen or out of order "
            f"(last seen from '{sender_id}': {last})"
        )

    return True, ""


def _check_nonce(state: dict, nonce_hex: str) -> tuple[bool, str]:
    """
    Layer 3: Reject exact duplicate nonces.

    Nonce is the GCM nonce from encrypt.py, stored as hex string.
    Even if timestamp and sequence somehow pass, a repeated nonce
    means this is an exact replay of a previously seen message.
    """
    if nonce_hex in state["seen_nonces"]:
        return False, f"Nonce already seen — exact replay detected: {nonce_hex[:16]}..."

    return True, ""


# -----------------------------------------------------------------------
# Main public interface
# -----------------------------------------------------------------------

def check_and_record(
    sender_id: str,
    timestamp: float,
    sequence: int,
    nonce_hex: str,
) -> tuple[bool, str]:
    """
    Run all three replay checks and, if they pass, record the message.

    Args:
        sender_id  : who claims to have sent the message
        timestamp  : time.time() value from the payload
        sequence   : per-sender incrementing counter from the payload
        nonce_hex  : GCM nonce as hex string (from payload["nonce"])

    Returns:
        (accepted, reason)
        accepted : True if message passes all checks
        reason   : empty string if accepted, explanation if rejected

    IMPORTANT: Only call this AFTER verifying the GCM tag and signature.
    Recording a nonce from a forged/tampered message would let an attacker
    perform a denial-of-service by burning your nonce slots.
    """
    state = _load_state()

    # Layer 1 — timestamp
    ok, reason = _check_timestamp(timestamp)
    if not ok:
        return False, f"[TIMESTAMP] {reason}"

    # Layer 2 — sequence number
    ok, reason = _check_sequence(state, sender_id, sequence)
    if not ok:
        return False, f"[SEQUENCE] {reason}"

    # Layer 3 — nonce
    ok, reason = _check_nonce(state, nonce_hex)
    if not ok:
        return False, f"[NONCE] {reason}"

    # All checks passed — record this message so future replays fail
    state["seen_nonces"].append(nonce_hex)
    state["last_seq"][sender_id] = sequence
    _save_state(state)

    return True, ""


def get_next_sequence(sender_id: str) -> int:
    """
    Get the next sequence number for sender_id to use when sending.

    Reads current state, increments, saves, returns new value.
    Starts at 1 for new senders.
    """
    state = _load_state()
    current = state["last_seq"].get(f"_sent_{sender_id}", 0)
    next_seq = current + 1
    state["last_seq"][f"_sent_{sender_id}"] = next_seq
    _save_state(state)
    return next_seq


def reset_state() -> None:
    """Wipe all replay state. Useful for testing."""
    if STATE_FILE.exists():
        STATE_FILE.unlink()


# -----------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------

if __name__ == "__main__":
    import base64

    # Always start clean for tests
    reset_state()

    print("=" * 55)
    print("TEST 1: Valid message accepted")
    print("=" * 55)
    nonce1 = base64.b64encode(os.urandom(12)).decode()
    ok, reason = check_and_record("alice", time.time(), 1, nonce1)
    assert ok, f"Should pass: {reason}"
    print(f"  PASS ✓ — message accepted\n")

    print("=" * 55)
    print("TEST 2: Exact replay rejected (same nonce)")
    print("=" * 55)
    ok, reason = check_and_record("alice", time.time(), 2, nonce1)
    assert not ok
    print(f"  PASS ✓ — {reason}\n")

    print("=" * 55)
    print("TEST 3: Old sequence number rejected")
    print("=" * 55)
    nonce2 = base64.b64encode(os.urandom(12)).decode()
    ok, reason = check_and_record("alice", time.time(), 1, nonce2)
    assert not ok
    print(f"  PASS ✓ — {reason}\n")

    print("=" * 55)
    print("TEST 4: Expired timestamp rejected")
    print("=" * 55)
    nonce3 = base64.b64encode(os.urandom(12)).decode()
    old_timestamp = time.time() - 120     # 2 minutes ago
    ok, reason = check_and_record("alice", old_timestamp, 5, nonce3)
    assert not ok
    print(f"  PASS ✓ — {reason}\n")

    print("=" * 55)
    print("TEST 5: Different sender has independent sequence")
    print("=" * 55)
    nonce4 = base64.b64encode(os.urandom(12)).decode()
    ok, reason = check_and_record("bob", time.time(), 1, nonce4)
    assert ok, f"Bob seq=1 should be fine: {reason}"
    print(f"  PASS ✓ — Bob's seq=1 accepted independently from Alice\n")

    print("=" * 55)
    print("TEST 6: Sequence gaps allowed (network drops)")
    print("=" * 55)
    nonce5 = base64.b64encode(os.urandom(12)).decode()
    ok, reason = check_and_record("alice", time.time(), 10, nonce5)
    assert ok, f"Gap in seq should be fine: {reason}"
    print(f"  PASS ✓ — seq jumped 1→10, gap allowed\n")

    print("=" * 55)
    print("TEST 7: get_next_sequence increments correctly")
    print("=" * 55)
    reset_state()
    s1 = get_next_sequence("alice")
    s2 = get_next_sequence("alice")
    s3 = get_next_sequence("alice")
    assert s1 == 1 and s2 == 2 and s3 == 3
    print(f"  PASS ✓ — sequences: {s1}, {s2}, {s3}\n")

    print("All replay tests passed ✓")
    reset_state()   # clean up after tests