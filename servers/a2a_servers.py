# common/a2a_servers.py
from fastapi import FastAPI, Request
from task_manager import JudgeTaskManager
from task_manager import MaskTaskManager
from task_manager import SqlTaskManager
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import logging
from utilities.types2 import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    GetTaskRequest,
    GetTaskResponse,
    JSONRPCResponse,
    SendTaskRequest,
    SendTaskStreamingRequest,
)

logger = logging.getLogger(__name__)

class A2AServer:
    def __init__(self, agent_card: AgentCard, task_manager, host="localhost", port=8000):
        self.agent_card = agent_card
        self.task_manager = task_manager
        self.host = host
        self.port = port
        self.app = FastAPI()

        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self.setup_routes()

    def setup_routes(self):
        @self.app.get("/.well-known/agent.json")
        async def get_agent_card():
            return self.agent_card.dict(exclude_none=True)

        @self.app.post("/rpc")
        async def handle_rpc(request: Request):
            try:
                body = await request.json()

                method = body.get("method")
                if not method:
                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32600, "message": "Invalid request: no method"}}
                    )

                # Process based on method
                if method == "tasks/send":
                    request_obj = SendTaskRequest(**body)
                    response = await self.task_manager.on_send_task(request_obj)
                    return JSONResponse(response.dict(exclude_none=True))

                elif method == "tasks/sendSubscribe":
                    request_obj = SendTaskStreamingRequest(**body)
                    result = await self.task_manager.on_send_task_subscribe(request_obj)

                    # If result is an error response, return it
                    if isinstance(result, JSONRPCResponse):
                        return JSONResponse(result.dict(exclude_none=True))

                    # Otherwise, it's a streaming response
                    async def stream_generator():
                        async for response in result:
                            yield f"data: {json.dumps(response.dict(exclude_none=True))}\n\n"

                    return StreamingResponse(
                        stream_generator(),
                        media_type="text/event-stream"
                    )

                elif method == "tasks/get":
                    request_obj = GetTaskRequest(**body)
                    task_id = request_obj.params.get("id")
                    history_length = request_obj.params.get("historyLength", 0)

                    task = await self.task_manager.get_task(task_id, history_length)
                    if not task:
                        return JSONResponse(
                            {"jsonrpc": "2.0", "id": request_obj.id, "error": {"code": -32000, "message": f"Task {task_id} not found"}}
                        )

                    response = GetTaskResponse(id=request_obj.id, result=task)
                    return JSONResponse(response.dict(exclude_none=True))

                elif method == "tasks/cancel":
                    task_id = body.get("params", {}).get("id")
                    if not task_id:
                        return JSONResponse(
                            {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32602, "message": "Invalid params: missing id"}}
                        )

                    task = await self.task_manager.cancel_task(task_id)
                    if not task:
                        return JSONResponse(
                            {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32000, "message": f"Task {task_id} not found"}}
                        )

                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": body.get("id", 0), "result": task.dict(exclude_none=True)}
                    )

                elif method == "tasks/pushNotification/set":
                    task_id = body.get("params", {}).get("id")
                    config = body.get("params", {}).get("pushNotificationConfig")

                    if not task_id or not config:
                        return JSONResponse(
                            {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32602, "message": "Invalid params: missing id or pushNotificationConfig"}}
                        )

                    result = await self.task_manager.set_push_notification(task_id, config)
                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": body.get("id", 0), "result": result}
                    )

                elif method == "tasks/pushNotification/get":
                    task_id = body.get("params", {}).get("id")

                    if not task_id:
                        return JSONResponse(
                            {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32602, "message": "Invalid params: missing id"}}
                        )

                    result = await self.task_manager.get_push_notification(task_id)
                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": body.get("id", 0), "result": result}
                    )

                else:
                    return JSONResponse(
                        {"jsonrpc": "2.0", "id": body.get("id", 0), "error": {"code": -32601, "message": f"Method not found: {method}"}}
                    )

            except Exception as e:
                logger.error(f"Error handling request: {e}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": body.get("id", 0) if 'body' in locals() else 0, "error": {"code": -32603, "message": f"Internal error: {str(e)}"}}
                )

    def start(self):
        import uvicorn
        logger.info(f"Starting A2A Server on {self.host}:{self.port}")
        uvicorn.run(self.app, host=self.host, port=self.port)

def create_judge_server(host="localhost", port=10002, call_judge_agent=None):
    """Create and return an A2A server for the security judge agent."""
    if not call_judge_agent:
        raise ValueError("Judge agent callback function is required")

    # Configure capabilities
    capabilities = AgentCapabilities(
        streaming=True,
        pushNotifications=False,
        stateTransitionHistory=True
    )

    # Configure skills
    skill = AgentSkill(
        id="security_evaluation",
        name="Security Threat Evaluation",
        description="Evaluates input for security threats like SQL injection and XSS",
        tags=["security", "threat-detection", "input-validation"],
        examples=["Evaluate this input for security threats"]
    )

    # Create agent card
    agent_card = AgentCard(
        name="Security Judge Agent",
        description="An agent that evaluates input for security threats",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        authentication=None,  # No authentication for simplicity
        defaultInputModes=["text", "text/plain"],
        defaultOutputModes=["text", "text/plain"],
        capabilities=capabilities,
        skills=[skill]
    )

    # Create task manager
    task_manager = JudgeTaskManager(judge_agent_call=call_judge_agent)

    # Create A2A server
    server = A2AServer(
        agent_card=agent_card,
        task_manager=task_manager,
        host=host,
        port=port
    )

    return server

def create_mask_server(host="localhost", port=10003, call_mask_agent=None):
    """Create and return an A2A server for the masking agent."""
    if not call_mask_agent:
        raise ValueError("Mask agent callback function is required")

    # Configure capabilities
    capabilities = AgentCapabilities(
        streaming=True,
        pushNotifications=False,
        stateTransitionHistory=True
    )

    # Configure skills
    skill = AgentSkill(
        id="data_masking",
        name="PII Data Masking",
        description="Masks personally identifiable information (PII) in text",
        tags=["privacy", "data-protection", "pii"],
        examples=["Mask the PII in this text"]
    )

    # Create agent card
    agent_card = AgentCard(
        name="Data Masking Agent",
        description="An agent that masks sensitive data in text",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        authentication=None,  # No authentication for simplicity
        defaultInputModes=["text", "text/plain"],
        defaultOutputModes=["text", "text/plain"],
        capabilities=capabilities,
        skills=[skill]
    )

    # Create task manager
    task_manager = MaskTaskManager(mask_agent_call=call_mask_agent)

    # Create A2A server
    server = A2AServer(
        agent_card=agent_card,
        task_manager=task_manager,
        host=host,
        port=port
    )

    return server

def create_sql_server(host="localhost", port=10004, call_sql_agent=None):
    """Create and return an A2A server for the SQL agent."""
    if not call_sql_agent:
        raise ValueError("SQL agent callback function is required")

    # Configure capabilities
    capabilities = AgentCapabilities(
        streaming=True,
        pushNotifications=False,
        stateTransitionHistory=True
    )

    # Configure skills
    skill = AgentSkill(
        id="sql_analysis",
        name="SQL Data Analysis",
        description="Analyzes salary data using SQL queries",
        tags=["sql", "data-analysis", "salary-data"],
        examples=["What's the average salary for Machine Learning Engineers?"]
    )

    # Create agent card
    agent_card = AgentCard(
        name="SQL Analysis Agent",
        description="An agent that analyzes salary data using SQL queries",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        authentication=None,  # No authentication for simplicity
        defaultInputModes=["text", "text/plain"],
        defaultOutputModes=["text", "text/plain"],
        capabilities=capabilities,
        skills=[skill]
    )

    # Create task manager
    task_manager = SqlTaskManager(sql_agent_call=call_sql_agent)

    # Create A2A server
    server = A2AServer(
        agent_card=agent_card,
        task_manager=task_manager,
        host=host,
        port=port
    )

    return server