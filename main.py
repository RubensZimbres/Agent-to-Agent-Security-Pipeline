"""Entry point for running the pipeline through the ADK CLI.

`create_runner` is kept as a helper for programmatic use. It is now async: ADK's
`session_service.create_session` is a coroutine, and the previous synchronous
version never awaited it -- the call returned an un-awaited coroutine and the
session was never created. main() also built a runner and then discarded it
before handing control to the CLI, so none of that work had any effect.
"""
import os

from dotenv import load_dotenv
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService

from agents import judge_agent, mask_agent, sql_agent, root_agent  # noqa: F401

# Load environment variables
load_dotenv()

USER_ID = os.getenv("ADK_USER_ID", "user_1")


async def create_runner(agent, app_name, session_id=None):
    """Create a Runner with a live session. Returns (runner, session_id)."""
    session_service = InMemorySessionService()
    artifact_service = InMemoryArtifactService()

    session_id = session_id or f"{app_name}_{agent.name}"
    await session_service.create_session(
        app_name=app_name,
        user_id=USER_ID,
        session_id=session_id,
    )

    runner = Runner(
        agent=agent,
        app_name=app_name,
        artifact_service=artifact_service,
        session_service=session_service,
    )
    return runner, session_id


def main():
    """Hand control to the ADK CLI.

    Run the full pipeline with:  adk run agents
    """
    from google.adk.cli import app
    app.run()


if __name__ == "__main__":
    main()
