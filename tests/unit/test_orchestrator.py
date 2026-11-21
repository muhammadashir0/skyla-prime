import pytest

from skyla.core.orchestrator import Orchestrator
from skyla.models.router import ModelRouter


@pytest.mark.asyncio
async def test_task_lifecycle_with_mock(db):
    orch = Orchestrator(db, ModelRouter())
    tid = db.create_task("Test task", "Summarize the quarterly results", "general", 0)
    task = await orch.run_task(tid)
    assert task["status"] == "completed"
    assert task["result"], "completed task must have a result"
    assert task["verification"], "independent verification must be recorded"
    assert len(task["steps"]) >= 2
    assert task["model_used"] == "skyla-mock-0.1"
    # audit trail exists
    assert any(a["action"] == "task.completed" for a in db.audit_recent())


@pytest.mark.asyncio
async def test_interrupted_recovery(db):
    tid = db.create_task("Stuck", "Do something", "general", 0)
    db.update_task(tid, status="running")
    assert db.recover_interrupted() == 1
    assert db.get_task(tid)["status"] == "interrupted"
