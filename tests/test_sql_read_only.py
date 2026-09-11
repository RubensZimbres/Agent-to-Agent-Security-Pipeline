"""The SQL tool is the pipeline's last line of defence.

The whole system exists to stop SQL injection reaching the database, and
`query_data` used to run whatever it was handed through `cursor.execute()`
followed by `conn.commit()` -- so a Judge bypass, or simply an unlucky
generation, could DROP or DELETE the table permanently.
"""
import ast
import re
import sqlite3
from pathlib import Path

import pytest


def _code_only(source: str) -> str:
    """Source with comments and docstrings stripped.

    Assertions about code must not match the prose explaining the fix.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Module)) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_guard():
    """Load assert_read_only without importing the LLM/toolkit chain."""
    src = (REPO_ROOT / "servers" / "server_mcp.py").read_text()
    block = src[src.index("MAX_ROWS = 500"):src.index("llm = ChatGoogleGenerativeAI")]
    namespace = {"re": re}
    exec(block, namespace)
    return namespace["assert_read_only"]


assert_read_only = _load_guard()


class TestReadOnlyGuard:

    @pytest.mark.parametrize("sql", [
        "SELECT AVG(salary_in_usd) FROM salaries",
        "SELECT job_title, COUNT(*) FROM salaries GROUP BY job_title",
        "WITH t AS (SELECT * FROM salaries) SELECT COUNT(*) FROM t",
        "select * from salaries limit 10",
        "SELECT * FROM salaries WHERE company_size = 'S' ORDER BY salary DESC",
    ])
    def test_reads_are_allowed(self, sql):
        assert_read_only(sql)

    @pytest.mark.parametrize("sql", [
        "DROP TABLE salaries",
        "DELETE FROM salaries",
        "DELETE FROM salaries WHERE 1=1",
        "UPDATE salaries SET salary = 0",
        "INSERT INTO salaries VALUES (1)",
        "CREATE TABLE evil (a int)",
        "ALTER TABLE salaries ADD COLUMN x int",
        "TRUNCATE TABLE salaries",
        "ATTACH DATABASE '/tmp/x.db' AS x",
        "PRAGMA writable_schema = 1",
        "VACUUM",
        "REPLACE INTO salaries VALUES (1)",
    ])
    def test_writes_are_refused(self, sql):
        with pytest.raises(ValueError):
            assert_read_only(sql)

    @pytest.mark.parametrize("sql", [
        "SELECT 1; DROP TABLE salaries",
        "SELECT * FROM salaries; DELETE FROM salaries",
        "SELECT 1;DROP TABLE salaries;",
    ])
    def test_stacked_queries_are_refused(self, sql):
        """Semicolon-chained statements are the classic injection shape."""
        with pytest.raises(ValueError):
            assert_read_only(sql)

    def test_comment_hidden_write_is_refused(self):
        """A comment must not be able to smuggle a second statement past the
        single-statement check."""
        with pytest.raises(ValueError):
            assert_read_only("SELECT 1 -- ;\nDROP TABLE salaries")

    def test_block_comment_hidden_write_is_refused(self):
        with pytest.raises(ValueError):
            assert_read_only("SELECT 1 /* ; */ ; DROP TABLE salaries")

    def test_keyword_inside_a_string_literal_is_allowed(self):
        """A legitimate query must not be refused because a value happens to
        contain a SQL keyword."""
        assert_read_only(
            "SELECT * FROM salaries WHERE job_title = 'DROP TABLE Engineer'")
        assert_read_only(
            "SELECT * FROM salaries WHERE fictitious_name = 'Update Delete'")

    def test_empty_statement_is_refused(self):
        for sql in ("", "   ", ";"):
            with pytest.raises(ValueError):
                assert_read_only(sql)


class TestDatabaseIsOpenedReadOnly:

    def test_sqlite_itself_rejects_writes_in_ro_mode(self, tmp_path):
        """Defence in depth: even if the guard were bypassed, the connection
        mode must prevent a write. The old code called conn.commit()."""
        db = tmp_path / "t.db"
        with sqlite3.connect(db) as setup:
            setup.execute("CREATE TABLE salaries (salary int)")
            setup.execute("INSERT INTO salaries VALUES (100)")

        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            assert conn.execute("SELECT salary FROM salaries").fetchone() == (100,)
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("DELETE FROM salaries")
        finally:
            conn.close()

    def test_query_data_opens_in_read_only_mode(self):
        src = _code_only((REPO_ROOT / "servers" / "server_mcp.py").read_text())
        body = src[src.index("def query_data("):]
        assert "mode=ro" in body
        assert "conn.commit()" not in body

    def test_both_sql_tools_call_the_guard(self):
        src = _code_only((REPO_ROOT / "servers" / "server_mcp.py").read_text())
        for tool in ("def query_data(", "def execute_sql_query("):
            body = src[src.index(tool):]
            nxt = body.find("\ndef ", 1)
            if nxt > 0:
                body = body[:nxt]
            assert "assert_read_only" in body, tool
