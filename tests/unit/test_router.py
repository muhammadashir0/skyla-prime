from skyla.models.router import classify_task, route_candidates


def test_classify_coding():
    assert classify_task("Debug this Python function and fix the bug") == "coding"


def test_classify_research():
    assert classify_task("Research battery evidence and cite sources") == "research"


def test_classify_reasoning():
    assert classify_task("Prove the theorem and calculate the integral") == "reasoning"


def test_classify_private():
    assert classify_task("Handle this confidential password privately") == "private"


def test_classify_routine():
    assert classify_task("Summarize this") == "routine"


def test_route_always_has_mock_fallback():
    candidates = route_candidates("general")
    assert candidates, "router must always return at least the mock provider"
    assert candidates[-1].provider == "local"


def test_route_private_prefers_local():
    candidates = route_candidates("private")
    assert candidates[0].provider == "local"
