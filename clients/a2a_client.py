# a2a_client.py
import uuid
import json
import aiohttp
import logging

logger = logging.getLogger(__name__)

async def call_a2a_agent(query, host, port, stream=False):
    """Call an agent via A2A protocol."""
    url = f"http://{host}:{port}/rpc"
    task_id = f"task-{uuid.uuid4()}"
    session_id = f"session-{uuid.uuid4()}"

    if stream:
        return await _call_a2a_agent_stream(query, url, task_id, session_id)
    else:
        return await _call_a2a_agent_sync(query, url, task_id, session_id)

async def _call_a2a_agent_sync(query, url, task_id, session_id):
    """Call an agent via A2A synchronously."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/send",
        "params": {
            "id": task_id,
            "sessionId": session_id,
            "message": {
                "role": "user",
                "parts": [{
                    "type": "text",
                    "text": query
                }]
            }
        }
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                logger.error(f"Error calling agent: {error_text}")
                raise Exception(f"Error calling agent: {error_text}")

            result = await response.json()

            # Check for errors
            if "error" in result:
                logger.error(f"Agent returned error: {result['error']}")
                raise Exception(f"Agent error: {result['error']['message']}")

            # Extract the text response from the artifact
            task_result = result.get("result", {})
            artifacts = task_result.get("artifacts", [])

            if artifacts:
                for part in artifacts[0].get("parts", []):
                    if part.get("type") == "text":
                        return part.get("text", "")

            # If no text found in artifacts, check the status message
            status = task_result.get("status", {})
            message = status.get("message", {})

            for part in message.get("parts", []):
                if part.get("type") == "text":
                    return part.get("text", "")

            return ""

async def _call_a2a_agent_stream(query, url, task_id, session_id):
    """Call an agent via A2A with streaming."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/sendSubscribe",
        "params": {
            "id": task_id,
            "sessionId": session_id,
            "message": {
                "role": "user",
                "parts": [{
                    "type": "text",
                    "text": query
                }]
            }
        }
    }

    result_text = ""

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                logger.error(f"Error calling agent: {error_text}")
                raise Exception(f"Error calling agent: {error_text}")

            # Process the SSE response
            async for line in response.content:
                line = line.decode('utf-8').strip()

                if line.startswith('data: '):
                    data = json.loads(line[6:])

                    # Check for artifact updates
                    if "result" in data and "artifact" in data["result"]:
                        artifact = data["result"]["artifact"]

                        for part in artifact.get("parts", []):
                            if part.get("type") == "text":
                                result_text = part.get("text", "")

    return result_text