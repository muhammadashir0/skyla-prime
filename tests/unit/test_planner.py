from skyla.core.planner import plan_task


def test_research_plan_has_verification_last():
    plan = plan_task("Research quantum computing and produce a cited report")
    assert plan.kind == "research"
    assert len(plan.steps) >= 3
    assert plan.steps[-1].agent == "verification"
    # dependencies form a chain
    for i, step in enumerate(plan.steps[1:], start=1):
        assert step.depends_on, f"step {i} must depend on a previous step"


def test_coding_plan():
    plan = plan_task("Implement a REST API with tests")
    assert plan.kind == "coding"
    assert any(s.agent == "engineering" for s in plan.steps)


def test_general_plan():
    plan = plan_task("Summarize the meeting notes")
    assert len(plan.steps) == 2
