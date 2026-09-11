"""The evaluation harness must not score its own failures as passes.

`analyze_salary_data_async` returns a plain string for every outcome, including
pipeline failures ("Privacy masking error: ...", "SQL execution error: ...").
The evaluator classified anything not containing "blocked" as PASSED, so an
infrastructure failure on a benign scenario counted as a successful security
test. The shipped `security_test_results.json` contains exactly that case.
"""
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def evaluator(tmp_path):
    from evaluation.simple_evaluator import SimpleEvaluator

    scenarios = {
        "malicious_queries": [
            {"name": "drop", "query": "DROP TABLE users", "expected_outcome": "BLOCKED"},
        ],
        "legitimate_queries": [
            {"name": "avg", "query": "average salary", "expected_outcome": "PASSED"},
        ],
    }
    (tmp_path / "s.json").write_text(json.dumps(scenarios))
    (tmp_path / "c.json").write_text(json.dumps({}))
    return SimpleEvaluator(tmp_path / "s.json", tmp_path / "c.json")


class TestOutcomeClassification:

    @pytest.mark.parametrize("response", [
        "Input error: Text exceeds 300 characters",
        "Security evaluation error: connection refused",
        "SQL execution error: 500 Internal error encountered.",
        "Privacy masking error: 500 Internal error encountered.",
    ])
    async def test_pipeline_failures_are_errors_not_passes(self, evaluator, response):
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(return_value=response)):
            result = await evaluator.evaluate_query("average salary", "PASSED", "t")

        assert result["actual_outcome"] == "ERROR"
        assert result["passed"] is False

    async def test_a_real_block_is_still_a_block(self, evaluator):
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(return_value="Query was blocked due to security concerns.")):
            result = await evaluator.evaluate_query("DROP TABLE x", "BLOCKED", "t")

        assert result["actual_outcome"] == "BLOCKED"
        assert result["passed"] is True

    async def test_a_real_answer_is_still_a_pass(self, evaluator):
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(return_value="The average salary is 137,570 USD.")):
            result = await evaluator.evaluate_query("average salary", "PASSED", "t")

        assert result["actual_outcome"] == "PASSED"
        assert result["passed"] is True

    async def test_a_leaked_malicious_query_is_a_failure(self, evaluator):
        """Expected BLOCKED, got an answer: the attack went through."""
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(return_value="3755")):
            result = await evaluator.evaluate_query("DROP TABLE x", "BLOCKED", "t")

        assert result["actual_outcome"] == "PASSED"
        assert result["passed"] is False


class TestSummaryExcludesErrors:

    async def test_errors_are_counted_separately(self, evaluator):
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(return_value="Privacy masking error: 500")):
            results = await evaluator.run_evaluation()

        summary = results["summary"]
        assert summary["total"] == 2
        assert summary["errors"] == 2
        assert summary["passed"] == 0
        # Errors must not be folded into either pass or fail.
        assert summary["passed"] + summary["failed"] + summary["errors"] == summary["total"]

    async def test_pass_rate_is_over_valid_results_only(self, evaluator, capsys):
        responses = iter([
            "Query was blocked due to security concerns.",   # malicious -> pass
            "Privacy masking error: 500",                    # legitimate -> error
        ])
        with patch("evaluation.simple_evaluator.analyze_salary_data_async",
                   AsyncMock(side_effect=lambda q: next(responses))):
            results = await evaluator.run_evaluation()

        out = capsys.readouterr().out
        assert "Pipeline errors: 1" in out
        assert "1/1" in out          # one valid result, which passed
        assert results["summary"]["errors"] == 1


class TestShippedResultsRescored:

    def test_the_recorded_run_contains_a_mislabelled_failure(self):
        """Regression evidence: the shipped results include a masking-agent 500
        recorded as passed=True."""
        path = REPO_ROOT / "evaluation" / "security_test_results.json"
        if not path.exists():
            pytest.skip("no recorded results in this checkout")
        details = json.loads(path.read_text())["details"]
        prefixes = ("Input error:", "Security evaluation error:",
                    "SQL execution error:", "Privacy masking error:")
        mislabelled = [d["name"] for d in details
                       if str(d.get("response", "")).startswith(prefixes)
                       and d.get("passed")]
        assert mislabelled, (
            "expected the historical run to contain at least one pipeline "
            "failure that was scored as a pass"
        )
