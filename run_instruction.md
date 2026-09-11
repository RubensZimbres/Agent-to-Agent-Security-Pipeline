# Run Instructions — Secure Multi-Agent Evaluation (A2A + ADK + MCP)

A three-agent pipeline over a salaries database, wired together with Google ADK,
exposed over the A2A protocol, and fronted by an MCP server that owns the SQL
tools. A security harness replays adversarial scenarios against the whole thing.

```
query → judge agent   (Model Armor: prompt injection / jailbreak screening)
      → SQL agent     (MCP tools, read-only SELECT over salaries.db)
      → mask agent    (Cloud DLP de-identification of the answer)
```

---

## 1. Layout

```
agents/agent.py              LlmAgent definitions + the SequentialAgent pipeline
agents/mcp_agent.py          Agent that talks to the MCP server over stdio
agents/.env                  Vertex AI project config -- TRACKED, see §2
servers/server_mcp.py        FastMCP server: SQL tools, read-only guard, salaries.db
servers/a2a_servers.py       A2A HTTP wrappers (judge :10002, mask :10003, sql :10004)
servers/run_servers.py       Starts all three A2A servers in threads
servers/task_manager.py      A2A task lifecycle
clients/query_MCP_ADK_A2A.py The pipeline: Model Armor, DLP, agent orchestration
clients/a2a_client.py        Async A2A client
evaluation/simple_evaluator.py  Replays test_scenarios.json, writes results
evaluation/test_scenarios.json  Adversarial + benign scenarios
main.py                      Hands off to the ADK CLI
tests/                       53 tests; ADK, DLP, Secret Manager and MCP mocked
```

---

## 2. `agents/.env` is tracked in git

It is committed with the project and holds `GOOGLE_GENAI_USE_VERTEXAI`,
`GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION` — configuration, not
credentials. Nothing here needs changing to run, but be aware that **edits to it
are committed by default**, and that the project id is visible to anyone who can
read the repository.

To stop tracking it without deleting your local copy:

```bash
git rm --cached agents/.env
git commit -m "Stop tracking agents/.env"
```

`.gitignore` now covers `.env` and `**/.env` (with `!.env.example`), so a
*new* `.env` anywhere in the tree will not be committed. That rule does not
retroactively untrack `agents/.env` — git ignores patterns for files it already
tracks. Nothing in this repository runs the command above for you.

Use `.env.example` as the template for everything else:

```bash
GOOGLE_GENAI_USE_VERTEXAI=TRUE
GOOGLE_CLOUD_PROJECT=your-gcp-project
GOOGLE_CLOUD_LOCATION=us-central1
PROJECT_ID=your-gcp-project        # read by the Model Armor / DLP helpers
LOCATION=us-central1
GOOGLE_API_KEY=...                 # ChatGoogleGenerativeAI in server_mcp.py
TEMPLATE_ID=...                    # Model Armor template; falls back to Secret Manager
SALARIES_CSV_PATH=/path/to/salaries.csv
```

---

## 3. Prerequisites

- **Python 3.11+**
- A Google Cloud project with **Vertex AI**, **Cloud DLP**, **Model Armor** and
  **Secret Manager** enabled
- A Model Armor template (its id goes in `TEMPLATE_ID`, or in a Secret Manager
  secret of that name)

```bash
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then edit
gcloud auth application-default login
```

> `google-adk` was pinned to `==0.1.0`, the very first release. The APIs this
> code uses — `LlmAgent`, `SequentialAgent`, `MCPToolset`, `FunctionTool` — post-
> date it, so a clean install could not import the agents. Now pinned to the 1.x
> line.
>
> `aiohttp` is imported by `clients/a2a_client.py` but was not declared at all; a
> fresh install failed on the first client import.

---

## 4. Build the database

`servers/server_mcp.py` builds `salaries.db` on first use:

```bash
export SALARIES_CSV_PATH=/path/to/salaries.csv
python -c "from servers.server_mcp import setup_database; setup_database()"
```

If `salaries.db` is absent and `SALARIES_CSV_PATH` is unset, `setup_database()`
raises `FileNotFoundError` with the variable named. It previously carried on and
produced an empty or partial database, so the SQL agent answered salary questions
about no rows without anything indicating why.

---

## 5. Run

### The whole pipeline through the ADK CLI

```bash
adk run agents          # or: python main.py
adk web                 # browser UI
```

### The A2A servers

```bash
python servers/run_servers.py
```

Starts three HTTP servers in threads — judge on **10002**, mask on **10003**,
SQL on **10004** — each exposing an agent card at `/.well-known/agent.json`.

### The MCP server on its own

```bash
python servers/server_mcp.py       # stdio transport
```

### One query end to end

```bash
python clients/query_MCP_ADK_A2A.py
```

---

## 6. The security harness

```bash
cd evaluation && python simple_evaluator.py
```

Replays `test_scenarios.json` and writes `security_test_results.json`.

**Read the `errors` count, not just the pass rate.** `analyze_salary_data_async`
returns a plain string for every outcome, pipeline failures included — `"Input
error: …"`, `"Security evaluation error: …"`, `"SQL execution error: …"`,
`"Privacy masking error: …"`. The evaluator used to score anything *not*
containing `"blocked"` as **PASSED**, so a crash on a benign scenario counted as a
successful security test and inflated the headline number.

Those prefixes are now `INFRASTRUCTURE_ERROR_PREFIXES`, counted as `errors`,
excluded from the pass rate, and `tests/test_evaluator_scoring.py` asserts it.
The tracked `evaluation/security_test_results.json` is kept deliberately: it is a
recorded run containing a masking-agent 500 scored as `passed: true`, and a test
reads it as evidence.

`simple_evaluator.py` also used `from query_MCP_ADK_A2A import …`, which only
resolved when `clients/` happened to be on `sys.path` — the harness could not
import the system it evaluates. It now resolves from the repository root, and
finds its JSON files next to itself rather than relative to the current
directory.

---

## 7. Guardrails worth knowing

- **SQL is read-only, enforced in `servers/server_mcp.py`.** `assert_read_only()`
  rejects an empty statement, **multiple statements** (`SELECT 1; DROP TABLE
  salaries`), anything that is not `SELECT` / `WITH … SELECT`, and any remaining
  write keyword. Literals and comments are stripped first
  (`_strip_sql_literals_and_comments`) so a salary row containing the word
  "update" is not rejected, and `--`/`/* */` cannot smuggle a keyword past the
  check. It is applied to the LLM's SQL **and** to the checker tool's rewrite —
  `checker_tool` is itself an LLM and may reintroduce a write.

- **MCP tools are looked up by name, not list position.** They were selected as
  `get_tools()[0] … [3]`; that ordering is not part of the `SQLDatabaseToolkit`
  API, so a LangChain upgrade that reorders them would silently turn
  `query_tool` into the checker or the schema tool. `_tool_by_name()` raises
  `LookupError` instead.

- **`evaluate_prompt()` returns `BLOCKED`/`PASS`; the caller halts.** It used to
  print `!!! MALICIOUS CONTENT DETECTED - TERMINATING EXECUTION !!!` and then run
  a bare `import os` — the `os._exit(1)` beside it was commented out. Nothing was
  terminated, and the banner said otherwise.

- **There is no per-caller authentication, and the previous version only looked
  like there was.** `setup_database` took credentials and then supplied them to
  itself — `username = "admin"`, `password = "admin123"`, interactive prompts
  commented out — so `verify_credentials` could never fail. None of the four MCP
  tools consulted the authenticator anyway, so tool access was unauthenticated
  either way. The credential theatre is gone rather than left to reassure;
  `MCP_AUTH_NOTE` in `server_mcp.py` records what real authentication would
  require. Anything that can reach the MCP server or ports 10002–10004 can
  query, so do not expose them beyond localhost as-is.

---

## 8. Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # 53 passed
```

ADK, Model Armor, Cloud DLP, Secret Manager and MCP are mocked in
`tests/conftest.py`, so no credentials, no network and no database are needed.

Two things that bootstrap has to get right, both of which have bitten:

- **Mock the parent package, not just the leaves.** Listing
  `google.cloud.dlp_v2` alone worked only while some real `google-cloud-*` wheel
  was installed to create the `google.cloud` namespace; in a clean environment
  `from google.cloud import dlp_v2` fails on `google.cloud` itself. `google.cloud`
  is now in the mock list.
- **`pytest-asyncio` is required** by `asyncio_mode = auto` in `pytest.ini`.
  Without it the async tests are reported as *failures* rather than as a missing
  dependency. It lives in `requirements-dev.txt`.

```bash
flake8 --max-line-length=140 --select=E9,F63,F7,F82,F401 . --exclude=venv,examples
```

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| `ImportError` on `LlmAgent` / `MCPToolset` | `google-adk` resolved to 0.1.0 (§3) |
| `ModuleNotFoundError: aiohttp` | Pre-fix `requirements.txt` (§3) |
| `FileNotFoundError` naming `SALARIES_CSV_PATH` | Intended — `salaries.db` absent and no CSV given (§4) |
| SQL agent answers about zero rows | Old behaviour: the database was built empty. Rebuild per §4 |
| `ValueError: Multiple SQL statements are not allowed.` | The guard working (§7) |
| `LookupError: No SQLDatabaseToolkit tool matching …` | LangChain renamed a tool class; update the fragments in `_tool_by_name` calls |
| Model Armor template errors | `TEMPLATE_ID` unset and no Secret Manager secret of that name |
| Pass rate looks suspiciously high | Check `summary.errors` — pipeline failures are no longer counted as passes (§6) |
| Async tests reported as failures | `pytest-asyncio` not installed (§8) |

---

## 10. Before you change anything

- **Gemini is pinned at 8 call sites**, all `gemini-3.7-flash`:
  `agents/agent.py` (×3), `clients/query_MCP_ADK_A2A.py` (×3),
  `agents/mcp_agent.py`, `servers/server_mcp.py`. There is no shared constant.
- **`assert_read_only` is called at three sites on purpose** — on the LLM's SQL,
  again on the checker tool's rewrite, and in the second query path. Removing any
  of them reopens the write path.
- **Keep `evaluation/security_test_results.json` tracked** (§6).
- **`tests/conftest.py` exposes realistically-named tool mocks**
  (`_QuerySQLDatabaseTool`, `_QuerySQLCheckerTool`, …) because production code
  now looks tools up by name. Renaming those classes breaks the lookup tests.
