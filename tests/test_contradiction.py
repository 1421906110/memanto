import pytest
from unittest.mock import MagicMock
from memanto.app.services.memory_write_service import MemoryWriteService
from memanto.app.core import MemoryRecord

class TestContradictionHandling:
    """
    Test suite demonstrating that the memory write service fails to properly resolve direct contradictions.
    """

    def test_store_memory_skips_validation(self):
        """
        Demonstrates that store_memory bypasses contradiction validation and forces an MVP direct store.
        This allows logically contradictory memories to be stored blindly.
        """
        mock_client = MagicMock()
        mock_client.documents.upload.return_value = {"status": "success"}
        
        write_service = MemoryWriteService(mock_client)
        
        memory = MemoryRecord(
            content="The user's favorite color is red.",
            type="fact",
            title="Favorite Color",
            agent_id="test-agent"
        )
        
        result = write_service.store_memory(memory)
        
        # The test expects proper contradiction validation to be active.
        # Currently, the code skips validation with the reason "MVP direct store", meaning
        # it will blindly store contradictions instead of resolving them.
        assert result.get("reason") != "MVP direct store", "Contradiction validation is completely skipped (MVP direct store)."

    def test_batch_store_memories_skips_validation(self):
        """
        Demonstrates that batch_store_memories also bypasses contradiction validation.
        """
        mock_client = MagicMock()
        mock_client.documents.upload.return_value = {"status": "success"}
        
        write_service = MemoryWriteService(mock_client)
        
        memory1 = MemoryRecord(
            content="The user lives in New York.",
            type="fact",
            title="Location",
            agent_id="test-agent"
        )
        
        memory2 = MemoryRecord(
            content="The user lives in London.",
            type="fact",
            title="Location",
            agent_id="test-agent"
        )
        
        result = write_service.batch_store_memories([memory1, memory2])
        
        for res in result["results"]:
            assert res.get("reason") != "MVP direct store", "Contradiction validation is skipped for batch storage (MVP direct store)."
