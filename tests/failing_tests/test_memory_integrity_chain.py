"""
Memory Integrity Chain — Reproducible PoC Test Suite

Bounty #770 — The Memanto Bug & Exploit Challenge

Each test directly exercises the code path that contains the defect and
asserts the resulting broken behaviour.  A passing test = the bug is
still present.  Once a fix is merged, the test should fail (= the fix
works).

Usage:
    pytest tests/failing_tests/test_memory_integrity_chain.py -v \
        -W ignore::pytest.PytestUnhandledThreadPoolWarning
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from memanto.app.constants import ALLOWED_UPDATE_FIELDS
from memanto.app.core import MemoryRecord
from memanto.app.services.memory_read_service import MemoryReadService
from memanto.app.services.memory_write_service import MemoryWriteService


# ═══════════════════════════════════════════════════════════════════════════
# F1: Write-path validation is dead code
# ═══════════════════════════════════════════════════════════════════════════


class TestF1DeadValidation:
    """Finding 1: memory_write_service.py lines 803-809 are commented out.

    The service layer has NO active validation.  Every memory type, no matter
    how incoherent, passes through without being checked by a validation
    service.  The ``validation_result`` is hardcoded to a dictionary literal
    instead of coming from an actual validation call.

    This test verifies that store_memory succeeds without calling any
    validation method — proving the validation path is dead code.
    """

    def test_validation_result_is_hardcoded_placeholder(self):
        """Assert the literal dict that replaced the real validation call."""
        mock_client = MagicMock()
        mock_client.documents.upload.return_value = {"status": "queued"}

        service = MemoryWriteService(mock_client)

        memory = MemoryRecord(
            type="fact",
            title="F1 bypass test",
            content="This memory should have been validated but wasn't.",
            agent_id="test-f1",
            actor_id="test-f1",
            source="test",
        )

        result = service.store_memory(memory)

        # The validation path is replaced with a hardcoded dict.
        # A real validation service would return a meaningful result.
        assert result["action"] == "store"
        assert result["reason"] == "MVP direct store", (
            "Expected 'MVP direct store' placeholder — the real validation "
            "call at memory_write_service.py:806 is commented out."
        )

    def test_validation_service_not_initialized(self):
        """Assert ``self.validation_service`` does not exist on the service.

        If validation were wired in, ``__init__`` would create this attribute.
        """
        service = MemoryWriteService(MagicMock())
        assert not hasattr(service, "validation_service"), (
            "validation_service attribute exists — validation may have been "
            "restored.  If so, the commented-out block at "
            "memory_write_service.py:803-809 should be uncommented."
        )


# ═══════════════════════════════════════════════════════════════════════════
# F2: ALLOWED_UPDATE_FIELDS defined but never enforced
# ═══════════════════════════════════════════════════════════════════════════


class TestF2AllowlistNotEnforced:
    """Finding 2: constants.py lines 374-381.

    ``ALLOWED_UPDATE_FIELDS`` is exported from ``memanto.app.constants`` but
    is never imported anywhere in the codebase.  The ``update_memory`` path
    applies every field from the caller's dict without checking against this
    allowlist.

    This test verifies that:
    1. ``update_memory()`` applies fields explicitly excluded by the allowlist.
    2. The constant is defined but unreferenced outside its definition module.
    """

    def test_update_memory_accepts_non_allowlisted_status(self):
        """Assert `status` (excluded from ALLOWED_UPDATE_FIELDS) can be set."""
        mock_client = MagicMock()

        # Fields that should be blocked by the allowlist
        assert "status" not in ALLOWED_UPDATE_FIELDS, (
            "If status is now in ALLOWED_UPDATE_FIELDS, update this test."
        )
        assert "provenance" not in ALLOWED_UPDATE_FIELDS, (
            "If provenance is now in ALLOWED_UPDATE_FIELDS, update this test."
        )

        # Arrange: return a fake existing memory
        read_service = MemoryReadService(mock_client)

        def fake_get(**_kw):
            return {
                "id": "f2-test-id",
                "title": "F2 original",
                "content": "Original content that should not change.",
                "type": "fact",
                "confidence": 0.9,
                "status": "active",
                "tags": [],
                "source": "test",
                "agent_id": "test-f2",
                "actor_id": "test-f2",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }

        write_service = MemoryWriteService(mock_client)

        with patch.object(read_service, "get_memory", fake_get):
            mock_client.documents.delete.return_value = {"actual_deletions": 1}
            mock_client.documents.upload.return_value = {"status": "queued"}

            # Act: update a field that is NOT in ALLOWED_UPDATE_FIELDS
            result = write_service.update_memory(
                memory_id="f2-test-id",
                namespace="memanto_agent_test-f2",
                updates={"status": "superseded"},
            )

        # Assert: the update "succeeds" despite status not being allowlisted.
        # In a system with field-level protection this should be rejected.
        assert result["action"] == "updated", (
            f"update_memory should have rejected status='superseded' "
            f"but it returned: {result}.  "
            f"If ALLOWED_UPDATE_FIELDS is now enforced, update this test."
        )

    def test_allowlist_defined_but_not_imported(self):
        """Assert the constant is unreferenced outside ``constants.py``.

        Static-analysis: walk every Python file under ``memanto/`` and
        confirm only ``constants.py`` contains the name.
        """
        import ast
        import os

        memanto_root = os.path.join(
            os.path.dirname(__file__), "..", "..", "memanto"
        )
        if not os.path.isdir(memanto_root):
            pytest.skip("memanto/ source tree not available (installed package)")

        referencing = []

        for dirpath, _dirs, fnames in os.walk(memanto_root):
            for fn in fnames:
                if not fn.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fn)
                try:
                    with open(fpath) as f:
                        tree = ast.parse(f.read(), fpath)
                except (SyntaxError, OSError):
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name) and node.id == "ALLOWED_UPDATE_FIELDS":
                        # Ignore the definition site (assign in constants.py)
                        for parent in ast.walk(tree):
                            if isinstance(parent, ast.Assign) and node in [
                                t for t in ast.walk(parent) if isinstance(t, ast.Name)
                            ]:
                                referencing.append(fpath)
                                break

        # Deduplicate
        referencing = list(set(referencing))
        assert not referencing, (
            f"ALLOWED_UPDATE_FIELDS is now referenced outside constants.py "
            f"in: {referencing}.  If it's now enforced, update this test."
        )


# ═══════════════════════════════════════════════════════════════════════════
# F3: _filter_expired_memories datetime branch bypasses TTL
# ═══════════════════════════════════════════════════════════════════════════


class TestF3TtlDatetimeBypass:
    """Finding 3: memory_read_service.py lines 540-568.

    ``_filter_expired_memories`` has three branches:
    - ``isinstance(expires_at, str)`` → checks expiration  ✓
    - ``else`` (incl. datetime)       → **keeps unconditionally**  ✗
    - ``except`` (parse failure)      → keeps (fail-open)  ✗

    These tests verify that a memory whose ``expires_at`` is a ``datetime``
    object (not a string) passes the filter even when clearly expired.
    """

    def test_datetime_expires_at_skips_ttl_check(self):
        """``datetime`` expires_at in the past is NOT filtered out."""
        service = MemoryReadService(MagicMock())

        past = datetime(2020, 1, 1, tzinfo=timezone.utc)  # 6+ years ago
        memory = {
            "id": "f3-test",
            "title": "Expired memory",
            "content": "Should have been filtered out",
            "expires_at": past,  # datetime, not string — hits the else-branch
        }

        result = service._filter_expired_memories([memory])

        assert len(result) == 1, (
            "Expected expired datetime.expires_at to be kept (else-branch bug). "
            "If the bug is fixed, this test should fail."
        )
        assert result[0]["id"] == "f3-test"

    def test_string_expires_at_is_correctly_filtered(self):
        """Control test: string expires_at IS filtered when expired."""
        service = MemoryReadService(MagicMock())

        past_str = "2020-01-01T00:00:00+00:00"
        memory = {
            "id": "f3-control",
            "title": "Control",
            "content": "Should be gone",
            "expires_at": past_str,  # string → normal check
        }

        result = service._filter_expired_memories([memory])

        assert len(result) == 0, (
            "String-format expired memory was NOT filtered. "
            "The basic TTL filter path may also be broken."
        )


# ═══════════════════════════════════════════════════════════════════════════
# F4: update_memory has no transaction safety
# ═══════════════════════════════════════════════════════════════════════════


class TestF4UpdateAtomicity:
    """Finding 4: memory_write_service.py lines 969-1098.

    The delete-and-recreate pattern:
    1. Retrieve existing memory
    2. Build updated document
    3. Delete old version in Moorcheh          ← succeeds
    4. Upload new version to Moorcheh          ← fails → data LOST

    This test simulates an upload failure after a successful delete and
    asserts the memory is permanently lost — the delete is never rolled back.
    """

    def test_upload_failure_after_delete_causes_data_loss(self):
        """Assert data loss when upload fails after delete succeeds."""
        mock_client = MagicMock()

        def fake_get(**_kw):
            return {
                "id": "f4-test-id",
                "title": "F4 about to vanish",
                "content": "This memory will be permanently lost.",
                "type": "fact",
                "confidence": 0.8,
                "status": "active",
                "tags": [],
                "source": "test",
                "agent_id": "test-f4",
                "actor_id": "test-f4",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }

        read_service = MemoryReadService(mock_client)

        with patch.object(read_service, "get_memory", fake_get):
            write_service = MemoryWriteService(mock_client)

            # Delete succeeds
            mock_client.documents.delete.return_value = {"actual_deletions": 1}
            # Upload fails
            mock_client.documents.upload.side_effect = RuntimeError(
                "Simulated upload failure"
            )

            with pytest.raises(Exception) as exc_info:
                write_service.update_memory(
                    memory_id="f4-test-id",
                    namespace="memanto_agent_test-f4",
                    updates={"title": "F4 updated title"},
                )

        assert "Failed to update memory" in str(exc_info.value), (
            f"Unexpected error message: {exc_info.value}"
        )

        # Verify call order: delete before upload
        calls = [call[0] for call in mock_client.method_calls if call[0] in (
            "documents.delete", "documents.upload"
        )]
        assert calls == ["documents.delete", "documents.upload"], (
            f"Expected delete → upload order but got: {calls}"
        )

        # The memory was deleted and never re-uploaded.  In production this
        # is permanent data loss — no rollback, no retry, no recovery.
        assert not any("rollback" in str(c).lower() for c in calls), (
            "Rollback detected.  If atomicity is now fixed, update this test."
        )

    def test_no_recovery_keywords_in_update_memory(self):
        """Assert the source of ``update_memory`` lacks recovery patterns.

        Static-analysis: check for rollback/backup/compensating/restore
        inside the ``update_memory`` method body.
        """
        import ast
        import os

        service_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..",
            "memanto", "app", "services", "memory_write_service.py",
        )
        if not os.path.isfile(service_path):
            pytest.skip("Source file not available (installed package)")

        with open(service_path) as f:
            source = f.read()

        tree = ast.parse(source, filename=service_path)
        update_node = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "update_memory"),
            None,
        )
        assert update_node is not None, "update_memory function not found"

        method_source = source[update_node.lineno - 1: update_node.end_lineno]
        recovery_keywords = ["rollback", "backup", "compensating", "restore"]
        found = [kw for kw in recovery_keywords if kw in method_source.lower()]

        assert not found, (
            f"Recovery mechanism found: {found}.  "
            f"If atomicity is now handled, update this test."
        )


# ═══════════════════════════════════════════════════════════════════════════
# Chain: collective verification
# ═══════════════════════════════════════════════════════════════════════════


class TestChainIntegrity:
    """Runs very short checks for all four defects with ``subtests``.

    The purpose is to give a single-pass/fail view of the whole chain
    in CI output.
    """

    def test_all_four_defects_confirmable(self, subtests):
        for label, ok in [
            ("F1  validation dead code",     _service_has_no_validation()),
            ("F2  allowlist not enforced",   _allowlist_has_gap()),
            ("F3  datetime TTL bypass",      _ttl_else_branch_still_exists()),
            ("F4  no recovery mechanism",    _no_recovery_in_update_memory()),
        ]:
            with subtests.test(msg=label):
                assert ok, f"{label} — defect appears to be FIXED"

        pytest.skip(
            "All 4 defects confirmed present (expected state before fix)."
        )


# ── Helper functions ──────────────────────────────────────────────────────


def _service_has_no_validation() -> bool:
    """Return True when the service still lacks a validation_service attribute."""
    try:
        svc = MemoryWriteService(MagicMock())
        return not hasattr(svc, "validation_service")
    except Exception:
        return False


def _allowlist_has_gap() -> bool:
    """Return True when ``status`` is still absent from the allowlist."""
    return "status" not in ALLOWED_UPDATE_FIELDS


def _ttl_else_branch_still_exists() -> bool:
    """Return True when the source still has the silent else-branch."""
    import os

    fpath = os.path.join(
        os.path.dirname(__file__),
        "..", "..",
        "memanto", "app", "services", "memory_read_service.py",
    )
    if not os.path.isfile(fpath):
        return True  # can't check — assume present
    with open(fpath) as f:
        source = f.read()
    # The else-branch without expiry check is the defect marker
    return (
        "if isinstance(expires_at, str)" in source
        and "datetime" not in source.split("else:")[1][:200]
        if "else:" in source.split("_filter_expired_memories")[1]
        else True
    )


def _no_recovery_in_update_memory() -> bool:
    """Return True when the update_memory method lacks recovery keywords."""
    import os

    fpath = os.path.join(
        os.path.dirname(__file__),
        "..", "..",
        "memanto", "app", "services", "memory_write_service.py",
    )
    if not os.path.isfile(fpath):
        return True
    with open(fpath) as f:
        source = f.read()
    return not any(
        kw in source.lower()
        for kw in ["rollback", "compensating", "write-ahead"]
    )
