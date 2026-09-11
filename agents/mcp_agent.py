import logging
import uuid
from google.genai import types
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def get_tools_async():
    """Gets tools from the MCP Server."""
    logger.info("Connecting to MCP security-hub server...")

    try:
        # Connect to your existing MCP server
        tools, exit_stack = await MCPToolset.from_server(
            connection_params=StdioServerParameters(
                command='python',
                args=[
                    "./servers/server_mcp.py"
                ],
            )
        )

        logger.info(f"MCP Toolset created successfully with {len(tools)} tools")
        return tools, exit_stack
    except Exception as e:
        logger.error(f"Failed to connect to MCP server: {e}")
        raise

async def get_agent_async():
    """Creates an ADK Agent equipped with tools from the MCP Server."""
    try:
        tools, exit_stack = await get_tools_async()

        # Create the agent with MCP tools
        root_agent = LlmAgent(
            model='gemini-3.7-flash',
            name='sql_analysis_assistant',
            instruction="""
            You are an expert SQL analyst working with a salary database.
            Follow these steps:
            1. Understand the user's question about salary data
            2. Use the available MCP tools to query and analyze the salary database
            3. Format results in a clear, readable way
            4. Be particularly careful with sensitive information in the results
            """,
            tools=tools,
        )

        return root_agent, exit_stack
    except Exception as e:
        logger.error(f"Failed to create agent: {e}")
        raise

async def run_mcp_agent(query):
    """Run the MCP agent with a given query and return the response."""
    session_service = InMemorySessionService()
    artifacts_service = InMemoryArtifactService()
    exit_stack = None

    try:
        # Create a unique session with a UUID
        session_id = f"session_{uuid.uuid4()}"
        session = session_service.create_session(
            state={},
            app_name='mcp_sql_analysis_app',
            user_id='user_1',
            session_id=session_id
        )

        logger.info(f"User Query: '{query}'")
        content = types.Content(role='user', parts=[types.Part(text=query)])

        # Get the agent with MCP tools
        root_agent, exit_stack = await get_agent_async()

        # Create runner
        runner = Runner(
            app_name='mcp_sql_analysis_app',
            agent=root_agent,
            artifact_service=artifacts_service,
            session_service=session_service,
        )

        logger.info("Running agent...")
        result_text = ""

        # Process the query
        events_async = runner.run_async(
            session_id=session.id,
            user_id=session.user_id,
            new_message=content
        )

        async for event in events_async:
            logger.debug(f"Event type: {type(event)}")
            if event.is_final_response() and event.content and event.content.parts:
                result_text = event.content.parts[0].text

        return result_text
    except Exception as e:
        logger.error(f"Error running MCP agent: {e}")
        return f"Error: {str(e)}"
    finally:
        if exit_stack:
            logger.info("Closing MCP server connection...")
            try:
                await exit_stack.aclose()
            except Exception as e:
                logger.error(f"Error closing MCP connection: {e}")
