# Agent-to-Agent (A2A) Security Pipeline with MCP Integration

A security-focused, multi-agent data processing pipeline that combines the **Agent-to-Agent (A2A) protocol**, **Google Agent Development Kit (ADK)**, and the **Model Context Protocol (MCP)**. The system enables secure natural-language querying of a salary database through a sequential pipeline of specialized agents that enforce threat detection, SQL execution, and PII masking.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Agent Pipeline](#agent-pipeline)
- [Security Model](#security-model)
- [MCP Integration](#mcp-integration)
- [A2A Protocol](#a2a-protocol)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Evaluation & Testing](#evaluation--testing)
- [Deployment](#deployment)
- [Documentation](#documentation)

---

## Architecture Overview

The system is composed of three independent layers that collaborate to process every request securely:

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                         │
│          query_MCP_ADK_A2A.py  ·  a2a_client.py            │
└────────────────────┬────────────────────────────────────────┘
                     │  JSON-RPC 2.0 over HTTP
┌────────────────────▼────────────────────────────────────────┐
│                     A2A PROTOCOL LAYER                       │
│   Judge Server :10002  ·  SQL Server :10004  ·  Mask :10003 │
│              a2a_servers.py  ·  task_manager.py              │
└────────────────────┬────────────────────────────────────────┘
                     │  ADK agent callbacks
┌────────────────────▼────────────────────────────────────────┐
│                      ADK AGENT LAYER                         │
│       Judge Agent  →  SQL Agent  →  Mask Agent               │
│                      agent.py                                │
└──────┬─────────────────┬───────────────────┬────────────────┘
       │                 │                   │
  SecurityBlocker   MCP Server         Google Cloud DLP
  (in-process)    server_mcp.py         (Cloud API)
                       │
                  SQLite Database
                   salaries.db
```

### Layer Responsibilities

| Layer | Components | Responsibility |
|-------|-----------|----------------|
| **Client** | `query_MCP_ADK_A2A.py`, `a2a_client.py` | Request orchestration, input sanitization, Model Armor integration |
| **A2A Protocol** | `a2a_servers.py`, `task_manager.py` | Standardized JSON-RPC 2.0 agent communication, task lifecycle management |
| **ADK Agents** | `agent.py`, `mcp_agent.py` | Natural language understanding, tool invocation, sequential pipeline execution |
| **Tools** | `server_mcp.py`, SecurityBlocker, Google Cloud DLP | SQL execution, threat detection, PII masking |

---

## Agent Pipeline

Every user query passes through three specialized agents in sequence.

> **Which pipeline halts.** `clients/query_MCP_ADK_A2A.analyze_salary_data_async`
> calls the three agents over A2A and returns early on a `BLOCKED` verdict — that
> path halts. The `SequentialAgent` in `agents/agent.py` (used by `adk run`) does
> **not**: ADK runs every sub-agent unconditionally, so a `BLOCKED` from the Judge
> simply becomes the SQL agent's input. The SQL tools are independently restricted
> to read-only `SELECT`s (see below), so a pass-through cannot damage the database.

```
User Query
    │
    ▼
[Input Sanitization]
  • Character whitelist (alphanumeric + basic punctuation)
  • 300-character length limit
  • Model Armor API scan
    │
    ▼
[Judge Agent]  ──────────────────────────────────────────────┐
  Model: gemini-3.7-flash                                    │
  Tool:  SecurityBlocker                                      │ BLOCKED
  • 60+ SQL/XSS/command injection patterns                    │ → Return error
  • 50+ obfuscation patterns (leetspeak, encoding, etc.)      │
  • Returns: PASS or BLOCKED                                  │
    │ PASS                                                    │
    ▼                                                         │
[SQL Agent]                                                   │
  Model: gemini-3.7-flash                                    │
  Tool:  MCP Server (query_data, execute_sql_query, etc.)    │
  • Translates natural language → SQL                        │
  • Executes against salaries.db (SQLite)                    │
  • Returns structured query results                         │
    │                                                         │
    ▼                                                         │
[Mask Agent]                                                  │
  Model: gemini-3.7-flash                                    │
  Tool:  Google Cloud DLP                                    │
  • Scans results for 16 PII info types                      │
  • Replaces sensitive values with asterisks                 │
  • Returns safe, masked output                              │
    │                                                         │
    ▼                                                         │
Final Response ◄─────────────────────────────────────────────┘
```

### Agent Definitions

**Judge Agent (`security_judge`)**
- Evaluates every input before any database interaction
- Invokes the `SecurityBlocker` tool, which applies 100+ regex patterns covering SQL injection, XSS, command injection, path traversal, and obfuscated variants
- Outputs a clear `PASS` or `BLOCKED` verdict

**SQL Agent (`sql_assistant`)**
- Accepts natural-language queries about salary data
- Uses MCP tools to inspect the schema, generate valid SQL, and execute it
- Works with columns: `work_year`, `experience_level`, `employment_type`, `job_title`, `salary`, `salary_currency`, `salary_in_usd`, `employee_residence`, `remote_ratio`, `company_location`, `company_size`, `fictitious_name`, `fictitious_surname`

**Mask Agent (`data_masker`)**
- Post-processes all SQL results using Google Cloud DLP
- Detects and masks: `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD_NUMBER`, `US_SOCIAL_SECURITY_NUMBER`, `PERSON_NAME`, `IP_ADDRESS`, `DATE_OF_BIRTH`, `STREET_ADDRESS`, `PASSWORD`, `URL`, `AGE`, `VEHICLE_IDENTIFICATION_NUMBER`, `IBAN_CODE`, `MAC_ADDRESS`, and more (16 types total)

---

## Security Model

The system implements a **five-layer security model**:

### 1. Input Sanitization (Client-Side)
- Whitelists alphanumeric characters and safe punctuation
- Enforces a 300-character hard limit
- Integrates with **Google Model Armor API** for additional LLM-specific threat scanning

### 2. Threat Detection (Judge Agent + SecurityBlocker)
Pattern categories covered:

| Category | Examples |
|----------|---------|
| Database destruction | `DROP TABLE`, `TRUNCATE`, `ALTER` |
| Authentication bypass | `OR 1=1`, `' OR 'a'='a` |
| Comment injection | `--`, `#`, `/* */` |
| UNION-based injection | `UNION SELECT`, `UNION ALL SELECT` |
| Blind/time-based injection | `AND IF`, `SLEEP()`, `WAITFOR DELAY` |
| Database-specific attacks | `xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE` |
| Stacked queries | Semicolon-chained commands |
| NoSQL injection | `$ne`, `$gt`, `$where` |
| XSS | `<script>`, `javascript:`, event handlers |
| Command injection | `sudo`, `rm`, `wget`, `curl` |
| Path traversal | `../`, sensitive file paths |
| Obfuscation (50+ patterns) | Leetspeak, URL encoding, Unicode fullwidth, embedded comments, case variants, MySQL version comments |

### 3. Query Validation (MCP Server)
- **`assert_read_only()`** rejects anything that is not a single `SELECT`/`WITH`
  statement, *before* it reaches SQLite: write keywords, stacked queries
  (`SELECT 1; DROP TABLE ...`), comment-smuggled statements, `ATTACH`, `PRAGMA`.
  Keywords inside string literals are not flagged, so legitimate queries still run.
- The connection is opened `mode=ro`, so SQLite itself refuses any write even if
  the guard were bypassed.
- **`QuerySQLCheckerTool`** asks the LLM to repair SQL *syntax*. It is a
  convenience, **not** a security control — its output is re-checked by
  `assert_read_only()` before execution.
- **No per-caller authentication.** See the note below.

### 4. PII Masking (Mask Agent + Google Cloud DLP)
- Every response is scanned for personally identifiable information
- Detected PII is replaced with masked output before reaching the client

### 5. LLM Safety Settings
- Gemini safety filters enabled for all agents
- Blocks: dangerous content, hate speech, harassment, sexually explicit material, and violence

---

## MCP Integration

The **Model Context Protocol (MCP)** server (`servers/server_mcp.py`) exposes database tools to the SQL agent using the `FastMCP` framework.

### Authentication — what it does and does not do

> **The MCP tools are not access-controlled.** `DatabaseAuthenticator` exists and
> hashes passwords correctly, but no tool consults it. `setup_database` previously
> set `username = "admin"` / `password = "admin123"` in code — with the
> interactive prompts commented out — and then verified those credentials against
> itself, so the check could never fail. That credential theatre has been removed
> rather than left to imply a control that isn't there; see `MCP_AUTH_NOTE` in
> `servers/server_mcp.py`.
>
> The server talks stdio to whatever process spawns it. Real access control needs
> transport-level authentication between the ADK client and this server.

```python
class DatabaseAuthenticator:
    # Retained because this README documents it; it gates nothing.
    # admin / admin123 · analyst / data456 · reader / read789
```

### Exposed Tools

| Tool | Signature | Description |
|------|-----------|-------------|
| `query_data` | `query_data(sql: str)` | Raw SQL execution on the salaries database |
| `execute_sql_query` | `execute_sql_query(sql: str)` | SQL execution with pre-validation |
| `get_table_info` | `get_table_info(tables: str)` | Returns schema and sample data for given tables |
| `list_database_tables` | `list_database_tables()` | Lists all tables in the database |

### ADK ↔ MCP Connection

```python
# mcp_agent.py — connecting ADK agent to MCP server
tools, exit_stack = await MCPToolset.from_server(
    connection_params=StdioServerParameters(
        command='python',
        args=["servers/server_mcp.py"],
    )
)

agent = LlmAgent(
    model='gemini-3.7-flash',
    name='sql_assistant',
    instruction="Analyze salary data. Use available tools to query the database...",
    tools=tools,
)
```

---

## A2A Protocol

The system uses the **Agent-to-Agent (A2A) protocol** for standardized, interoperable agent communication. Each agent runs as an independent HTTP service exposing a JSON-RPC 2.0 API.

### Server Ports

| Agent | Port | Responsibility |
|-------|------|---------------|
| Judge Server | 10002 | Security threat evaluation |
| Mask Server | 10003 | PII masking |
| SQL Server | 10004 | Data analysis |

### API Endpoints

Each server exposes:

- `GET /.well-known/agent.json` — Agent card (metadata, skills, capabilities)
- `POST /rpc` — JSON-RPC 2.0 endpoint

### Supported RPC Methods

| Method | Description |
|--------|-------------|
| `tasks/send` | Send a task synchronously |
| `tasks/sendSubscribe` | Send a task with streaming response |
| `tasks/get` | Retrieve task status and results |
| `tasks/cancel` | Cancel an in-progress task |
| `tasks/pushNotification/set` | Configure push notifications |
| `tasks/pushNotification/get` | Retrieve notification configuration |

### Task Lifecycle

```
tasks/send
    → SUBMITTED  (task created in memory)
    → WORKING    (agent processing)
    → COMPLETED  (results available as artifacts)
         or
    → FAILED / CANCELED
```

---

## Project Structure

```
Multi_Agent_System_With_MCP/
├── agents/
│   ├── agent.py                    # Judge, SQL, and Mask agent definitions
│   ├── mcp_agent.py                # ADK ↔ MCP integration
│   ├── __init__.py                 # Exports root_agent
│   └── .env                        # Environment variables
│
├── servers/
│   ├── server_mcp.py               # FastMCP server with database tools
│   ├── a2a_servers.py              # A2A protocol server (3 instances)
│   ├── task_manager.py             # Task lifecycle managers (Judge, Mask, SQL)
│   └── run_servers.py              # Server orchestration & startup
│
├── clients/
│   ├── query_MCP_ADK_A2A.py        # Main pipeline (SecurityBlocker, orchestration)
│   └── a2a_client.py               # Async A2A HTTP client
│
├── utilities/
│   ├── types2.py                   # Pydantic models for A2A / JSON-RPC
│   └── utils.py                    # Shared helper functions
│
├── evaluation/
│   ├── simple_evaluator.py         # Evaluation harness
│   ├── test_scenarios.json         # 100 test cases (60 malicious + 40 legitimate)
│   ├── test_config.json            # Evaluator configuration
│   └── security_test_results.json  # Stored results
│
├── data/
│   └── Updated_Salaries_Data.csv   # Source salary dataset
│
├── main.py                         # Entry point
├── requirements.txt                # Python dependencies
├── salaries.db                     # Auto-generated SQLite database
└── readme.md
```

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Agent framework | Google ADK | 0.1.0 |
| Protocol | MCP (FastMCP) | 1.6.0 |
| LLM | Google Generative AI / Vertex AI | gemini-3.7-flash |
| Web framework | FastAPI | ≥ 0.95.0 |
| ASGI server | Uvicorn | latest |
| Database | SQLite3 | built-in |
| Query validation | LangChain + SQLDatabaseToolkit | 0.3.19 |
| Data processing | Pandas | 2.2.3 |
| PII detection | Google Cloud DLP | 3.28.0 |
| Secrets | Google Cloud Secret Manager | 2.23.2 |
| Async HTTP | aiohttp | latest |
| Logging | loguru | latest |

---

## Setup & Installation

### Prerequisites

- Python 3.8+
- A Google Cloud project with the following APIs enabled:
  - Vertex AI API (for Gemini models)
  - Cloud DLP API
  - Cloud Secret Manager API (optional)
  - Model Armor API (optional)

### 1. Clone & Install

```bash
git clone <repository-url>
cd Multi_Agent_System_With_MCP
pip install -r requirements.txt
```

### 2. Configure Environment

Create or edit `agents/.env`:

```env
GOOGLE_GENAI_USE_VERTEXAI=TRUE
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
GOOGLE_CLOUD_LOCATION=us-central1
```

Or set environment variables directly:

```bash
export GOOGLE_CLOUD_PROJECT=your-gcp-project-id
export GOOGLE_CLOUD_LOCATION=us-central1
export GOOGLE_GENAI_USE_VERTEXAI=True
```

> **Note:** If you prefer API key authentication instead of Vertex AI, set `GOOGLE_API_KEY=your-api-key` and remove `GOOGLE_GENAI_USE_VERTEXAI`.

### 3. Authenticate with Google Cloud

```bash
gcloud auth application-default login
gcloud config set project your-gcp-project-id
```

### 4. Verify Database

The SQLite database (`salaries.db`) is auto-generated from `data/Updated_Salaries_Data.csv` when the MCP server starts. No manual setup is required.

---

## Usage

### Option 1: ADK Web Interface (Recommended)

```bash
adk web
```

This launches the ADK chat UI and automatically starts:
- Judge Server (port 10002)
- Mask Server (port 10003)
- SQL Server (port 10004)
- MCP Server

Open your browser and interact with the agent directly through the chat interface.

### Option 2: Run Servers Manually

```bash
# Terminal 1 — start all A2A servers
python servers/run_servers.py

# Terminal 2 — send queries through the pipeline
python clients/query_MCP_ADK_A2A.py
```

### Example Queries

```
"What is the average salary for Machine Learning Engineers in small companies?"
"Show me the top 10 highest-paid roles in 2024"
"How does salary differ between remote and on-site positions?"
"Which countries have the highest average salaries in USD?"
"Compare salaries by experience level for Data Scientists"
```

### Example Blocked Queries

The following will be caught by the Judge Agent:

```
"SELECT * FROM users WHERE 1=1--"          # SQL injection
"DR0P T4BL3 salaries"                      # Leetspeak obfuscation
"%53%45%4c%45%43%54 * FROM salaries"       # URL-encoded SELECT
"<script>alert('xss')</script>"            # XSS
"sudo rm -rf /"                             # Command injection
```

---

## Evaluation & Testing

The project includes an evaluation framework with 100 test scenarios.

### Run the Evaluator

```bash
python evaluation/simple_evaluator.py
```

### Test Coverage

| Category | Count | Expected Outcome |
|----------|-------|-----------------|
| SQL injection variants | 20 | BLOCKED |
| Obfuscated attacks | 15 | BLOCKED |
| XSS / command injection | 10 | BLOCKED |
| Prompt injection | 10 | BLOCKED |
| Other malicious inputs | 5 | BLOCKED |
| Legitimate salary queries | 40 | PASSED |

### Metrics Reported

- Total scenarios run
- **Pipeline errors, counted separately and excluded from the pass rate**
- Pass / fail rate over *valid* results only
- An explicit list of malicious scenarios that were **not** blocked
- Results persisted to `evaluation/security_test_results.json`

> **Why errors are separated.** `analyze_salary_data_async` returns a plain string
> for every outcome, including its own failures (`"Privacy masking error: ..."`,
> `"SQL execution error: ..."`). The evaluator used to classify anything that did
> not contain `"blocked"` as `PASSED`, so an infrastructure failure on a benign
> scenario counted as a **successful security test**. The recorded run in
> `security_test_results.json` contains exactly that: `legitimate_salary_range_by_title`
> returned `"Privacy masking error: 500 Internal error encountered."` and was
> scored `passed: true`. A harness that reports green while the system is broken
> is worse than no harness.

### Reading the recorded results

The shipped `security_test_results.json` reports 82/99. Re-scored with errors
excluded it is 81/98 — the headline barely moves, but the corrected summary now
surfaces what the JSON always contained: **17 malicious scenarios were not
blocked**, including NoSQL, LDAP, XPath, template-injection, file-inclusion and
path-traversal payloads. `malicious_nosql_injection` returned `3755`, the full row
count of the salaries table, meaning the query executed.

Those 17 are the actual findings of this evaluation. They are gaps in the
`SecurityBlocker` pattern set, which covers SQL/XSS/command-injection shapes well
and non-SQL injection families poorly.

---

## Unit tests

```bash
pip install pytest pytest-asyncio
pytest -q
```

53 tests, no credentials or network required — `tests/conftest.py` mocks ADK,
Vertex AI, DLP, Secret Manager and the SQL toolkit before importing anything.
Coverage is focused on the security controls: the read-only SQL guard (including
stacked queries and comment smuggling), the Model Armor verdict being read, the
Judge instruction not inviting an override, and the evaluator's outcome
classification.

---

## Deployment

### Local Testing with Docker

```bash
docker build -t adk-multi-agent .
docker run -p 8000:8000 \
  -e GOOGLE_API_KEY=your_api_key \
  adk-multi-agent adk web
```

### Production: Google Cloud Run

```bash
export GOOGLE_CLOUD_PROJECT=your-project-id
export GOOGLE_CLOUD_LOCATION=us-central1
export GOOGLE_GENAI_USE_VERTEXAI=True
export AGENT_PATH="."
export SERVICE_NAME="adk-agent-service"
export APP_NAME="agents"

adk deploy cloud_run \
  --project=$GOOGLE_CLOUD_PROJECT \
  --region=$GOOGLE_CLOUD_LOCATION \
  --service_name=$SERVICE_NAME \
  --app_name=$APP_NAME \
  --with_ui \
  $AGENT_PATH
```

This command builds the container, pushes it to Artifact Registry, and deploys it as a Cloud Run service with the ADK web UI enabled.

---

## Secrets hygiene

`agents/.env` is **tracked in git** (committed in `519982c`). `.gitignore`
previously contained only `**/__pycache__/`, so nothing prevented it. The
committed version holds a GCP project id and no credentials, but the file being
tracked means the next real key written there is committed too.

To untrack it without deleting your local copy:

```bash
git rm --cached agents/.env
git commit -m "stop tracking agents/.env"
```

`.gitignore` now ignores `.env` and `**/.env` while keeping `.env.example`.

---

## Known limitations

- **The SecurityBlocker pattern set is SQL/XSS-shaped.** The recorded evaluation
  shows 17 non-SQL injection families getting through (NoSQL, LDAP, XPath,
  template, file inclusion, path traversal, CSRF, HTML injection). Closing those
  is the substantive outstanding work.
- **No per-caller authentication on the MCP tools** — see the Authentication note.
- **`sanitize_input` strips disallowed characters silently** rather than rejecting
  the input, so `DROP TABLE users;` becomes `DROP TABLE users` and is passed on to
  the Judge rather than refused outright. The whitelist is also stricter than the
  charset check that follows it, so that check can never fire.
- **The Judge is a rewriting step in the trust chain.** `analyze_salary_data_async`
  interpolates the Judge's *output* into the SQL agent's prompt, so whatever the
  Judge emits becomes the SQL agent's instruction. The block test is
  `if "BLOCK" in judge_output.upper()` — a substring match on free model text.
- **Block detection is substring-based**, so a legitimate query containing the
  word "block" would be refused. No such job title exists in the bundled dataset
  (93 distinct titles checked), but a different dataset could trip it.
- **`salaries.db` is rebuilt from `SALARIES_CSV_PATH` on every server start**
  (`if_exists='replace'`), discarding any state. If that variable is unset the
  committed `salaries.db` is used as-is.
- **Sessions are in-memory**, so conversation history does not survive a restart
  and is not shared across processes.

---

## Documentation

- [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/)
- [Agent-to-Agent (A2A) Protocol](https://google.github.io/A2A/#/documentation)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction)
- [Google Cloud DLP](https://cloud.google.com/dlp/docs)
- [Google Model Armor](https://cloud.google.com/security/products/model-armor)
- [LangChain SQL Toolkit](https://python.langchain.com/docs/integrations/toolkits/sql_database)

---

*This project demonstrates a production-grade integration of A2A, MCP, and Google ADK to build a secure, multi-agent architecture for data analysis with enterprise-level threat detection and privacy protection.*
