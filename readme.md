[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/rubenszimbres-a2a-adk-mcp-badge.png)](https://mseep.ai/app/rubenszimbres-a2a-adk-mcp)

# Agent-to-Agent (A2A) Security Pipeline with MCP Integration

This project implements a security-focused data processing pipeline using the Agent-to-Agent (A2A) protocol combined with Model Context Protocol (MCP) integration. The system provides secure database queries through a multi-agent architecture.

## System Architecture

The system utilizes a layered architecture:

1. **A2A Protocol Layer**: Provides standardized communication between clients and agent services
2. **ADK Framework Layer**: Manages agent behavior and tool integration
3. **MCP Server Layer**: Provides specialized SQL and data processing tools

### Components

- **A2A Servers**: Handle client requests and agent communication
- **ADK Agents**: Process natural language requests using specialized tools
- **MCP Server**: Provides SQL query and database interaction tools
- **Task Managers**: Coordinate task execution across agents

## Agent Pipeline

The system implements a security pipeline with three specialized agents:

1. **Judge Agent**: Evaluates input for security threats (SQL injection, XSS, etc.)
2. **SQL Agent**: Performs database queries and analysis using MCP tools
3. **Mask Agent**: Applies privacy protection to sensitive data in results

## Flow Diagram

```
Client Request → A2A Server → Judge Agent → SQL Agent → Mask Agent → Client Response
```

## Key Features

- **Security Threat Detection**: Identifies and blocks malicious inputs via tool and Model Armor
- **SQL Query Analysis**: Processes database queries using natural language
- **PII Data Protection**: Masks personally identifiable information in results using DLP
- **A2A Protocol Compliance**: Implements standardized agent communication
- **MCP Integration**: Leverages Model Context Protocol tools for enhanced capabilities

## Installation

### Prerequisites

- Python 3.8+
- aiohttp
- FastAPI
- Google ADK
- Google Generative AI packages
- uvicorn

### Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure API keys in environment variables (even better, use secret manager)
4. Have fun

## Usage

### Starting the Servers

Run the `adk web` script to run the chat interface:

```bash
adk web
```

This will start:
- Judge Server (port 10002)
- Mask Server (port 10003)
- SQL Server (port 10004)
- MCP Server


### Making Requests

Run the `query_MCP_ADK_A2A.py` script to query the multi-agent system:

```bash
python ./clients/query_MCP_ADK_A2A.py
```

This will use the `a2a_client.py` module to make requests to the pipeline:


## Core Files

- `a2a_client.py`: Client for A2A communication
- `a2a_servers.py`: Server implementations for A2A protocol
- `query_MCP_ADK_A2A.py`: Main pipeline implementation
- `run_servers.py`: Server startup and coordination
- `server_mcp.py`: MCP server implementation
- `task_manager.py`: Task coordination for agent communication
- `mcp_agent.py`: Integration between ADK and MCP

## MCP Integration

The system integrates with Model Context Protocol (MCP) for enhanced SQL capabilities:

```python
# Connect to MCP server
tools, exit_stack = await MCPToolset.from_server(
    connection_params=StdioServerParameters(
        command='python',
        args=["server_mcp.py"],
    )
)

# Create ADK agent with MCP tools
agent = LlmAgent(
    model='gemini-2.5-pro-preview-03-25',
    name='sql_assistant',
    instruction="...",
    tools=tools,
)
```

## Security Features

- Pattern-based security threat detection
- PII identification and masking (emails, names, addresses, etc.)
- Input sanitation with whitelist approach
- Model Armor API integration for additional protection


## Deployment

Testing:

```
docker build -t adk-multi-agent .
docker run -p 8000:8000 -e GOOGLE_API_KEY=your_api_key adk-multi-agent adk web
```

Production:

```
export GOOGLE_CLOUD_PROJECT=next-project25
export GOOGLE_CLOUD_LOCATION=us-central1
export GOOGLE_GENAI_USE_VERTEXAI=True
export AGENT_PATH="."
export SERVICE_NAME="adk-agent-service"
export APP_NAME="agents"
```

```
adk deploy cloud_run \
--project=$GOOGLE_CLOUD_PROJECT \
--region=$GOOGLE_CLOUD_LOCATION \
--service_name=$SERVICE_NAME \
--app_name=$APP_NAME \
--with_ui \
$AGENT_PATH
```


## Documentation

[Agent Development Kit Documentation](https://google.github.io/adk-docs/)

[A2A Protocol Documentation](https://google.github.io/A2A/#/documentation)

[MCP Server Documentation](https://modelcontextprotocol.io/introduction)


## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with comprehensive description


*This project demonstrates integration between A2A protocol and MCP server capabilities, creating a secure and flexible agent architecture for data processing.*
