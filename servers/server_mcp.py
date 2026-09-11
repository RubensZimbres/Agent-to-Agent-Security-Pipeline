import hashlib
import os
import re
import sqlite3
from pathlib import Path
from typing import Dict

import pandas as pd
from dotenv import load_dotenv
from loguru import logger
from mcp.server.fastmcp import FastMCP
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_google_genai import (
    ChatGoogleGenerativeAI,
    HarmBlockThreshold,
    HarmCategory,
)

load_dotenv()

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / "salaries.db"

# ---------------------------------------------------------------------------
# Read-only SQL enforcement
#
# This is the tool the SQL agent actually calls. The pipeline's entire threat
# model was "catch malicious input at the Judge agent", and then `query_data`
# ran whatever SQL it was handed through cursor.execute() followed by
# conn.commit() -- so a Judge bypass, or simply an unlucky generation, could
# DROP or DELETE the table. Defence in depth belongs here, at the point of
# execution, not only at the front door.
# ---------------------------------------------------------------------------
MAX_ROWS = 500

_WRITE_KEYWORDS = (
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "REPLACE",
    "TRUNCATE", "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX", "GRANT",
    "REVOKE", "BEGIN", "COMMIT", "ROLLBACK",
)


def _strip_sql_literals_and_comments(sql: str) -> str:
    """Remove string literals and comments so keywords inside them don't match."""
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"'[^']*'|\"[^\"]*\"", "''", sql)
    return sql


def assert_read_only(sql: str) -> None:
    """Raise ValueError unless `sql` is a single read-only statement."""
    cleaned = _strip_sql_literals_and_comments(sql).strip().rstrip(";").strip()
    if not cleaned:
        raise ValueError("Empty SQL statement.")

    # Stacked queries: "SELECT 1; DROP TABLE salaries"
    if ";" in cleaned:
        raise ValueError("Multiple SQL statements are not allowed.")

    upper = cleaned.upper()
    if not re.match(r"^(SELECT|WITH)\b", upper):
        raise ValueError("Only SELECT (or WITH ... SELECT) statements are allowed.")

    for keyword in _WRITE_KEYWORDS:
        if re.search(rf"(?:^|[^A-Z_]){keyword}(?:[^A-Z_]|$)", upper):
            raise ValueError(f"Statement contains the write keyword '{keyword}'.")

llm = ChatGoogleGenerativeAI(model="gemini-3.7-flash", max_tokens=2048, temperature=0.1, top_p=1.0,
                             frequency_penalty=0.0, presence_penalty=0.0,
                             safety_settings={
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_VIOLENCE: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_CIVIC_INTEGRITY: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE})

# Database Authentication
class DatabaseAuthenticator:
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = {
            username: self._hash_password(password)
            for username, password in credentials.items()
        }

    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_credentials(self, username: str, password: str) -> bool:
        """Verify if the provided credentials are valid."""
        if username not in self.credentials:
            return False
        return self.credentials[username] == self._hash_password(password)

# Database setup and connection
def setup_database(authenticator: DatabaseAuthenticator = None) -> SQLDatabase:
    """Open (and if needed build) the salaries database.

    The previous version took credentials, then supplied them to itself --
    `username = "admin"` / `password = "admin123"` with the interactive prompts
    commented out -- so verify_credentials could never fail. None of the four
    MCP tools consulted the authenticator either, so tool access was
    unauthenticated regardless. Presenting that as a security layer was
    misleading, so the credential theatre is gone; see MCP_AUTH_NOTE below for
    what real authentication would require.
    """
    csv_path = os.getenv("SALARIES_CSV_PATH")
    if csv_path and Path(csv_path).exists():
        # Rebuild from source data when a CSV is configured.
        df = pd.read_csv(csv_path)
        with sqlite3.connect(DB_PATH) as connection:
            df.to_sql(name="salaries", con=connection, if_exists="replace", index=False)
        logger.info("Rebuilt {} from {}", DB_PATH.name, csv_path)
    elif not DB_PATH.exists():
        raise FileNotFoundError(
            f"{DB_PATH} does not exist and SALARIES_CSV_PATH is not set to a "
            f"readable CSV. Set SALARIES_CSV_PATH to build the database."
        )
    else:
        logger.info("Using the existing {}", DB_PATH.name)

    return SQLDatabase.from_uri(f"sqlite:///{DB_PATH}")


MCP_AUTH_NOTE = """
This MCP server exposes database tools over stdio to whatever process spawns it.
There is no per-caller authentication: the DatabaseAuthenticator class below is
retained only because the README documents it, and it gates nothing. Any real
deployment needs transport-level auth (the ADK client holding a credential the
server verifies) before these tools can be considered access-controlled.
"""

# Retained for the documented API; NOT a security control (see MCP_AUTH_NOTE).
sample_credentials = {
    'admin': 'admin123',
    'analyst': 'data456',
    'reader': 'read789'
}
authenticator = DatabaseAuthenticator(sample_credentials)

db = setup_database()

toolkit = SQLDatabaseToolkit(
db=db,
llm=llm
)

mcp = FastMCP("security-hub")


def _tool_by_name(fragment: str):
    """Find a toolkit tool by name.

    The tools used to be selected by list position (`get_tools()[0]` ..`[3]`),
    which is not part of SQLDatabaseToolkit's API -- a LangChain release that
    reorders them silently turns query_tool into something else.
    """
    for candidate in toolkit.get_tools():
        if fragment in type(candidate).__name__.lower():
            return candidate
    raise LookupError(f"No SQLDatabaseToolkit tool matching {fragment!r}")


query_tool = _tool_by_name("querysqldatabase")
info_tool = _tool_by_name("infosqldatabase")
list_tool = _tool_by_name("listsqldatabase")
checker_tool = _tool_by_name("querysqlchecker")

# Create wrapper functions for each tool
@mcp.tool()
def execute_sql_query(sql: str) -> str:
    """Validate then run a read-only SELECT on the salaries database."""
    logger.info("execute_sql_query: {}", sql)
    try:
        assert_read_only(sql)
    except ValueError as e:
        logger.warning("Refused SQL: {} ({})", sql, e)
        return f"Refused: {e} Only read-only SELECT queries are permitted."

    try:
        # QuerySQLCheckerTool asks the LLM to repair SQL syntax. It is a
        # convenience, NOT a security control -- the README described it as
        # preventing dangerous queries, which it does not. So the result is
        # re-checked before execution.
        checked_sql = checker_tool.run(sql)
        assert_read_only(checked_sql)
        return query_tool.run(checked_sql)
    except ValueError as e:
        logger.warning("Checker rewrote the query into something unsafe: {}", e)
        return f"Refused: {e}"
    except Exception as e:
        logger.error("SQL Error: {}", e)
        return f"Error: {e}"

@mcp.tool()
def get_table_info(tables: str) -> str:
    """Get schema and sample data for specified tables (comma-separated)."""
    logger.info(f"Getting info for tables: {tables}")
    try:
        result = info_tool.run(tables)
        return result
    except Exception as e:
        logger.error(f"Table Info Error: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
def list_database_tables() -> str:
    """List all tables in the database."""
    logger.info("Listing all database tables")
    try:
        result = list_tool.run("")
        return result
    except Exception as e:
        logger.error(f"List Tables Error: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
def query_data(sql: str) -> str:
    """Run a read-only SELECT against the salaries database."""
    logger.info("query_data: {}", sql)
    try:
        assert_read_only(sql)
    except ValueError as e:
        logger.warning("Refused SQL: {} ({})", sql, e)
        return f"Refused: {e} Only read-only SELECT queries are permitted."

    conn = None
    try:
        # mode=ro: SQLite itself rejects any write, so a guard bypass still
        # cannot modify the database. The old version called conn.commit(),
        # meaning a DELETE or DROP would have been made permanent.
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchmany(MAX_ROWS + 1)
        truncated = len(rows) > MAX_ROWS
        body = "\n".join(str(row) for row in rows[:MAX_ROWS])
        if truncated:
            body += f"\n... (truncated at {MAX_ROWS} rows)"
        return body
    except Exception as e:
        logger.error("SQL Error: {}", e)
        return f"Error: {e}"
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    # Start the server (this will block until the server is stopped)
    print("Starting MCP server...")
    mcp.run(transport="stdio")  # You may want to change this to TCP for network access