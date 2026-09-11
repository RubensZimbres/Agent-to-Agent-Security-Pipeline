# run_servers.py
import asyncio
import logging
import threading
import uvicorn

import os
import sys

# Add the project root to the path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import your agent calling functions
from clients.query_MCP_ADK_A2A import call_judge_agent, call_mask_agent, call_sql_agent

# Import A2A server creation functions
from servers.a2a_servers import create_judge_server, create_mask_server, create_sql_server

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

USER_ID = "user_1"

def run_server(server):
    """Run an A2A server in a separate thread."""
    host = server.host
    port = server.port
    app = server.app

    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)

def main():
    """Start all A2A servers."""
    # Create servers
    judge_server = create_judge_server(host="localhost", port=10002, call_judge_agent=call_judge_agent)
    mask_server = create_mask_server(host="localhost", port=10003, call_mask_agent=call_mask_agent)
    sql_server = create_sql_server(host="localhost", port=10004, call_sql_agent=call_sql_agent)

    # Start servers in separate threads
    judge_thread = threading.Thread(target=run_server, args=(judge_server,))
    mask_thread = threading.Thread(target=run_server, args=(mask_server,))
    sql_thread = threading.Thread(target=run_server, args=(sql_server,))

    judge_thread.start()
    mask_thread.start()
    sql_thread.start()

    logger.info("All servers started. Press Ctrl+C to stop.")

    # Keep the main thread alive
    try:
        while True:
            asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down servers...")

if __name__ == "__main__":
    main()