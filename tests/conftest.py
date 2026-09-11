"""Test bootstrap.

Importing this project's modules pulls in google-adk, Vertex AI, Google Cloud
DLP, Secret Manager and a live SQLite build of the salaries table. Those are
mocked here so the suite runs with no credentials and no network, the way the
other projects in this repository do it.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("PROJECT_ID", "test-project")
os.environ.setdefault("LOCATION", "us-central1")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")

for _module in (
    "google.adk",
    "google.adk.agents",
    "google.adk.artifacts",
    "google.adk.artifacts.in_memory_artifact_service",
    "google.adk.cli",
    "google.adk.runners",
    "google.adk.sessions",
    "google.adk.tools",
    "google.adk.tools.function_tool",
    "google.adk.tools.mcp_tool",
    "google.adk.tools.mcp_tool.mcp_toolset",
    "google.generativeai",
    "google.genai",
    # The parent package must be mocked too. Listing only the leaves worked
    # while a real google-cloud-* wheel happened to be installed (which creates
    # the google.cloud namespace); in a clean environment
    # `from google.cloud import dlp_v2` then fails on google.cloud itself.
    "google.cloud",
    "google.cloud.dlp_v2",
    "google.cloud.secretmanager",
    "langchain_google_genai",
    "langchain_community",
    "langchain_community.utilities",
    "langchain_community.agent_toolkits",
    "mcp",
    "mcp.server",
    "mcp.server.fastmcp",
):
    sys.modules.setdefault(_module, MagicMock())


# server_mcp looks its SQL tools up by class name rather than list position, so
# the toolkit mock has to expose realistically-named tools. (Selecting by
# position was the bug: get_tools() ordering is not part of the API.)
class _QuerySQLDatabaseTool:
    def run(self, sql):
        return f"ran: {sql}"


class _InfoSQLDatabaseTool:
    def run(self, tables):
        return f"schema for: {tables}"


class _ListSQLDatabaseTool:
    def run(self, _):
        return "salaries"


class _QuerySQLCheckerTool:
    def run(self, sql):
        return sql


class _FakeToolkit:
    def __init__(self, *args, **kwargs):
        pass

    def get_tools(self):
        return [_QuerySQLDatabaseTool(), _InfoSQLDatabaseTool(),
                _ListSQLDatabaseTool(), _QuerySQLCheckerTool()]


sys.modules["langchain_community.agent_toolkits"].SQLDatabaseToolkit = _FakeToolkit
