import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Was `from query_MCP_ADK_A2A import ...`, which only resolved if clients/ was
# already on sys.path -- so the evaluation harness could not import the system
# it evaluates.
from clients.query_MCP_ADK_A2A import analyze_salary_data_async

# Prefixes that analyze_salary_data_async returns when the PIPELINE ITSELF
# failed, as distinct from a deliberate security block. Scoring these as
# outcomes is what let a crash count as a passing security test.
INFRASTRUCTURE_ERROR_PREFIXES = (
    "Input error:",
    "Security evaluation error:",
    "SQL execution error:",
    "Privacy masking error:",
)

class SimpleEvaluator:
    """A simplified evaluator for testing the multi-agent security system."""

    def __init__(self, scenarios_file=None, config_file=None):
        """Initialize the evaluator with test scenarios and configuration."""
        # Resolved next to this module, not against the current directory.
        here = Path(__file__).resolve().parent
        scenarios_file = scenarios_file or here / "test_scenarios.json"
        config_file = config_file or here / "test_config.json"

        # Load test scenarios
        with open(scenarios_file, 'r') as f:
            self.scenarios = json.load(f)

        # Load configuration
        with open(config_file, 'r') as f:
            self.config = json.load(f)

        # Initialize results
        self.results = {
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                # Counted separately: a pipeline failure is neither a pass nor a
                # security finding, and must not inflate the pass rate.
                "errors": 0,
            },
            "details": []
        }

    async def evaluate_query(self, query: str, expected_outcome: str, test_name: str) -> Dict[str, Any]:
        """Evaluate a single query and return the results."""
        print(f"\nTesting: {test_name}")
        print(f"Query: {query}")
        print(f"Expected outcome: {expected_outcome}")

        # Call your multi-agent system
        try:
            # Use your existing function to process the query
            result = await analyze_salary_data_async(query)

            # Fix tuple format if needed and configured
            if self.config.get("fix_tuple_format", False) and isinstance(result, str):
                # Extract number from tuple format like (75454.38888888889,)
                tuple_match = re.search(r'\(([\d\.]+),\)', result)
                if tuple_match:
                    result = tuple_match.group(1)

            # Determine actual outcome.
            #
            # A pipeline failure is NOT an outcome. Previously any response that
            # did not contain "blocked" was scored PASSED, so an infrastructure
            # error on a benign scenario counted as a successful security test.
            # The shipped results contain exactly that: the
            # legitimate_salary_range_by_title case returned "Privacy masking
            # error: 500 Internal error encountered." and was recorded as passed.
            if result.startswith(INFRASTRUCTURE_ERROR_PREFIXES):
                actual_outcome = "ERROR"
                test_passed = False
            elif "blocked" in result.lower() or "security concerns" in result.lower():
                actual_outcome = "BLOCKED"
                test_passed = (actual_outcome == expected_outcome)
            else:
                actual_outcome = "PASSED"
                test_passed = (actual_outcome == expected_outcome)

            # Build result details
            test_result = {
                "name": test_name,
                "query": query,
                "expected_outcome": expected_outcome,
                "actual_outcome": actual_outcome,
                "response": result,
                "passed": test_passed
            }

            return test_result

        except Exception as e:
            # Handle any exceptions
            print(f"Error: {str(e)}")
            return {
                "name": test_name,
                "query": query,
                "expected_outcome": expected_outcome,
                "actual_outcome": "ERROR",
                "response": f"Error: {str(e)}",
                "passed": False
            }

    async def run_evaluation(self):
        """Run all test scenarios and generate a report."""
        print("Starting evaluation...")

        # Process all scenarios
        all_scenarios = []
        all_scenarios.extend([{"category": "malicious", **s} for s in self.scenarios["malicious_queries"]])
        all_scenarios.extend([{"category": "legitimate", **s} for s in self.scenarios["legitimate_queries"]])

        # Initialize counters
        total = len(all_scenarios)
        passed = 0
        errors = 0

        # Process each scenario
        for scenario in all_scenarios:
            # Evaluate the query
            result = await self.evaluate_query(
                query=scenario["query"],
                expected_outcome=scenario["expected_outcome"],
                test_name=f"{scenario['category']}_{scenario['name']}"
            )

            # Update counters
            if result["actual_outcome"] == "ERROR":
                errors += 1
                print("⚠️  Pipeline error - not a valid result")
                print(f"  Response: {result['response']}")
            elif result["passed"]:
                passed += 1
                print("✅ Test passed!")
            else:
                print("❌ Test failed!")
                print(f"  Expected: {result['expected_outcome']}")
                print(f"  Actual: {result['actual_outcome']}")
                print(f"  Response: {result['response']}")

            # Add to results
            self.results["details"].append(result)

        # Update summary
        self.results["summary"]["total"] = total
        self.results["summary"]["passed"] = passed
        self.results["summary"]["errors"] = errors
        self.results["summary"]["failed"] = total - passed - errors

        # Save results
        if "save_results_to" in self.config:
            out_path = Path(self.config["save_results_to"])
            if not out_path.is_absolute():
                out_path = Path(__file__).resolve().parent / out_path
            with open(out_path, 'w') as f:
                json.dump(self.results, f, indent=2)
                print(f"\nResults saved to {out_path}")

        # Display summary
        failed = total - passed - errors
        valid = total - errors
        print("\n===== EVALUATION SUMMARY =====")
        print(f"Total scenarios: {total}")
        print(f"Pipeline errors: {errors}  (excluded from the pass rate)")
        if valid:
            print(f"Passed: {passed}/{valid} ({passed / valid * 100:.1f}% of valid results)")
            print(f"Failed: {failed}/{valid} ({failed / valid * 100:.1f}% of valid results)")
        else:
            print("No valid results: every scenario hit a pipeline error.")

        # Security tests that let a malicious query through are the ones that
        # matter; surface them rather than leaving them in the JSON.
        leaks = [d for d in self.results["details"]
                 if d["expected_outcome"] == "BLOCKED" and d["actual_outcome"] == "PASSED"]
        if leaks:
            print(f"\n{len(leaks)} malicious scenario(s) were NOT blocked:")
            for d in leaks:
                print(f"  - {d['name']}")

        return self.results

# Example usage
async def main():
    evaluator = SimpleEvaluator()
    await evaluator.run_evaluation()

if __name__ == "__main__":
    asyncio.run(main())
