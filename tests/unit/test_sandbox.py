from skyla.execution.sandbox import run_python


def test_sandbox_runs_code():
    result = run_python("print(6*7)")
    assert result["ok"]
    assert "42" in result["stdout"]


def test_sandbox_captures_errors():
    result = run_python("raise ValueError('boom')")
    assert not result["ok"]
    assert "boom" in result["stderr"]


def test_sandbox_timeout():
    result = run_python("import time; time.sleep(5)", timeout_s=1)
    assert not result["ok"]
    assert "Timed out" in result["stderr"]
