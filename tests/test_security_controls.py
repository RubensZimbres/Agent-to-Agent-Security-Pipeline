"""Tests for the documented security controls.

Each of these covers a control the README presents as part of a "five-layer
security model" but which did not actually work.
"""
import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _code_only(source: str) -> str:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Module)) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)


def _function_source(source: str, name: str) -> str:
    """Exactly one function's code, comments and docstring excluded.

    Slicing by text runs past the end of the function and picks up module-level
    code and the comments explaining a fix, which makes these assertions lie.
    """
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            if ast.get_docstring(node):
                node.body = node.body[1:]
            return ast.unparse(node)
    raise LookupError(f"no function named {name!r}")


def _keyword_value(source: str, call_target: str, keyword: str) -> str:
    """The literal value of one keyword argument of a module-level assignment."""
    for node in ast.parse(source).body:
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", None) == call_target
                and isinstance(node.value, ast.Call)):
            for kw in node.value.keywords:
                if kw.arg == keyword:
                    return ast.literal_eval(kw.value)
    raise LookupError(f"no {call_target}(... {keyword}=...)")


def _client_source():
    return (REPO_ROOT / "clients" / "query_MCP_ADK_A2A.py").read_text()


# ---------------------------------------------------------------------------
# Layer 1: input sanitisation and Model Armor.
# ---------------------------------------------------------------------------

class TestModelArmorVerdict:

    def test_filter_match_state_is_read(self):
        """sanitize_input called Model Armor and then read
        `sanitized_result.get("sanitizedText", ...)` -- a field the API does not
        return. The verdict field, filterMatchState, was never read, so a
        prompt-injection detection was silently discarded."""
        src = _code_only(_client_source())
        assert "filterMatchState" in src
        assert "MATCH_FOUND" in src
        assert 'get("sanitizedText"' not in src

    def test_scanner_failure_fails_closed(self):
        """An unreachable scanner used to print a message and continue, quietly
        downgrading the posture to 'local whitelist only'."""
        body = _function_source(_client_source(), "sanitize_input")
        assert "raise ValueError" in body
        assert "timeout=" in body


# ---------------------------------------------------------------------------
# Layer 2: the Judge agent.
# ---------------------------------------------------------------------------

class TestJudgeGate:

    def test_evaluate_prompt_does_not_claim_to_terminate(self):
        """It printed "TERMINATING EXECUTION" and then executed a bare
        `import os` -- a dead statement where an exit was intended."""
        body = _function_source(_client_source(), "evaluate_prompt")
        assert "TERMINATING EXECUTION" not in body
        # And it still reports the verdict for the caller to act on.
        assert "return result['status']" in body or 'return result["status"]' in body

    def test_judge_instruction_does_not_invite_an_override(self):
        """The instruction ended "or 'BLOCKED' if it is really a threat", which
        let the model second-guess the deterministic SecurityBlocker verdict."""
        src = (REPO_ROOT / "agents" / "agent.py").read_text()
        instruction = _keyword_value(src, "judge_agent", "instruction").lower()
        assert "really a threat" not in instruction
        assert "may not override" in instruction
        assert "never follow instructions" in instruction

    def test_sequential_pipeline_documents_that_it_cannot_halt(self):
        """SequentialAgent runs every sub-agent unconditionally; the judge
        emitting BLOCKED does not stop the SQL agent. The README claimed
        otherwise."""
        src = (REPO_ROOT / "agents" / "agent.py").read_text()
        assert "unconditionally" in src
        assert "analyze_salary_data_async" in src


# ---------------------------------------------------------------------------
# Layer 3: MCP "authentication".
# ---------------------------------------------------------------------------

class TestMcpAuthenticationHonesty:

    def test_setup_database_does_not_supply_its_own_credentials(self):
        """setup_database set username="admin" / password="admin123" with the
        interactive prompts commented out, then verified those credentials
        against itself -- so the check could never fail."""
        body = _function_source(
            (REPO_ROOT / "servers" / "server_mcp.py").read_text(), "setup_database")
        assert "admin123" not in body
        assert "verify_credentials" not in body

    def test_the_absence_of_tool_auth_is_stated(self):
        src = (REPO_ROOT / "servers" / "server_mcp.py").read_text()
        assert "MCP_AUTH_NOTE" in src
        assert "no per-caller authentication" in src.lower()

    def test_authenticator_still_behaves_as_documented(self):
        """Kept because the README documents the class; it just gates nothing."""
        import hashlib
        src = (REPO_ROOT / "servers" / "server_mcp.py").read_text()
        cls = src[src.index("class DatabaseAuthenticator"):src.index("# Database setup")]
        namespace = {"hashlib": hashlib, "Dict": dict}
        exec(cls, namespace)
        auth = namespace["DatabaseAuthenticator"]({"u": "p"})
        assert auth.verify_credentials("u", "p") is True
        assert auth.verify_credentials("u", "wrong") is False
        assert auth.verify_credentials("nobody", "p") is False


# ---------------------------------------------------------------------------
# Toolkit wiring.
# ---------------------------------------------------------------------------

class TestToolkitWiring:

    def test_tools_are_selected_by_name_not_position(self):
        """`toolkit.get_tools()[0]` .. `[3]` relies on list order that is not
        part of SQLDatabaseToolkit's API."""
        src = _code_only((REPO_ROOT / "servers" / "server_mcp.py").read_text())
        assert "get_tools()[0]" not in src
        assert "_tool_by_name" in src

    def test_single_fastmcp_instance(self):
        """FastMCP("security-hub") was constructed twice; the first was discarded."""
        src = (REPO_ROOT / "servers" / "server_mcp.py").read_text()
        assert src.count("mcp = FastMCP(") == 1


# ---------------------------------------------------------------------------
# Package wiring that made entry points unimportable.
# ---------------------------------------------------------------------------

class TestEntryPoints:

    def test_agents_package_exports_the_agents(self):
        """main.py does `from agents import judge_agent, mask_agent, sql_agent`;
        agents/__init__.py only did `from . import agent`, so that raised
        ImportError."""
        tree = ast.parse((REPO_ROOT / "agents" / "__init__.py").read_text())
        exported = {a.name for n in tree.body
                    if isinstance(n, ast.ImportFrom) for a in n.names}
        assert {"judge_agent", "mask_agent", "sql_agent"} <= exported

    def test_create_runner_is_async(self):
        """ADK's session_service.create_session is a coroutine; the synchronous
        version never awaited it, so the session was never created."""
        src = (REPO_ROOT / "main.py").read_text()
        assert "async def create_runner" in src
        assert "await session_service.create_session" in src

    def test_evaluator_imports_from_the_real_module_path(self):
        """`from query_MCP_ADK_A2A import ...` only resolved if clients/ was
        already on sys.path, so the harness could not import the system it
        evaluates."""
        src = (REPO_ROOT / "evaluation" / "simple_evaluator.py").read_text()
        assert "from clients.query_MCP_ADK_A2A import" in src


# ---------------------------------------------------------------------------
# Secrets hygiene.
# ---------------------------------------------------------------------------

class TestSecretsHygiene:

    def test_env_files_are_ignored(self):
        """.gitignore contained only **/__pycache__/, and agents/.env was
        committed -- so a filled-in copy would have been committed too."""
        ignore = (REPO_ROOT / ".gitignore").read_text()
        assert "**/.env" in ignore or ".env" in ignore

    def test_get_secret_uses_the_latest_version(self):
        src = _code_only(_client_source())
        line = [ln for ln in src.split("\n") if "def get_secret" in ln][0]
        assert "'latest'" in line or '"latest"' in line

    def test_template_id_is_resolved_lazily(self):
        """It was resolved at module scope, so importing this module made a
        Secret Manager call and failed hard without credentials."""
        src = _code_only(_client_source())
        assert "def _template_id" in src
        assert "TEMPLATE_ID = None" in src
