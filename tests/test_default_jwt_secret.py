"""
Regression Test: Default JWT Secret Key

This test asserts that the default JWT signing key is NEVER used in production.
Unlike the PoC (docs/bounty_reports/poc_forge_jwt.py), this test validates the
*absence* of the vulnerability — it will PASS once the bug is fixed and FAIL
if the default secret creeps back in.

Usage:
    pytest tests/test_default_jwt_secret.py -v
"""

import pytest
from pathlib import Path

# Anchor to repo root regardless of where pytest is invoked
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PY = REPO_ROOT / "memanto" / "app" / "config.py"
SERVICE_PY = REPO_ROOT / "memanto" / "app" / "services" / "session_service.py"

DEFAULT_SECRET = "memanto-default-secret-change-in-production"


def test_default_secret_not_in_source():
    """
    Regression: the default secret should NOT appear in config.py or
    session_service.py.  As soon as the maintainers apply the recommended
    fix this test will pass; if the value is reintroduced it will fail.
    """
    for path, label in [(CONFIG_PY, "config.py"), (SERVICE_PY, "session_service.py")]:
        assert path.exists(), f"{label} not found at {path}"
        source = path.read_text()
        assert DEFAULT_SECRET not in source, (
            f"{label} still contains the hardcoded default secret "
            f"({DEFAULT_SECRET!r}).  Remove it and use a configured/provided "
            f"value instead."
        )


def test_secret_key_loaded_from_env(monkeypatch):
    """
    Verify that the Settings model picks up MEMANTO_SECRET_KEY from the
    environment and does NOT fall back to the hardcoded default.

    Restores the module state after the assertion so other tests are not
    affected by the reloaded settings.
    """
    import importlib

    monkeypatch.setenv("MEMANTO_SECRET_KEY", "test-secret-from-env")

    import memanto.app.config as cfg
    importlib.reload(cfg)

    try:
        assert cfg.settings.MEMANTO_SECRET_KEY == "test-secret-from-env", (
            "Settings should load MEMANTO_SECRET_KEY from the environment, "
            "not use a hardcoded default."
        )
    finally:
        # monkeypatch reverts MEMANTO_SECRET_KEY at teardown; reload config
        # so it reflects the original env state (or the hardcoded default)
        # rather than the test value.
        importlib.reload(cfg)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
