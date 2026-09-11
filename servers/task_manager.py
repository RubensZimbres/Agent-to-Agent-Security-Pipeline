# Add the project root to the path
import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.modules.pop("servers", None)  # Clear any failed import attempts
    sys.path.insert(0, project_root)

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional, AsyncIterable, Any, Union
from utilities.types2 import (
    SendTaskRequest, TaskSendParams, Message, TaskStatus, Artifact,
    TaskStatusUpdateEvent, TaskArtifactUpdateEvent, TextPart,
    Task, SendTaskResponse, InternalError, JSONRPCResponse,
    SendTaskStreamingRequest, SendTaskStreamingResponse,
    TaskState
)
import logging
from utilities.utils import are_modalities_compatible, new_incompatible_types_error

logger = logging.getLogger(__name__)

class InMemoryTaskManager:
    """Base task manager with in-memory storage for tasks."""

    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_messages: Dict[str, List[Message]] = {}
        self.push_notifications: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()

    async def upsert_task(self, params: TaskSendParams) -> Task:
        """Create or update a task in the store."""
        async with self.lock:
            task_id = params.id
            session_id = params.sessionId or str(uuid.uuid4())

            # Create new task if it doesn't exist
            if task_id not in self.tasks:
                task = Task(
                    id=task_id,
                    sessionId=session_id,
                    status=TaskStatus(
                        state=TaskState.SUBMITTED,
                        timestamp=datetime.utcnow().isoformat()
                    ),
                    history=[],
                    artifacts=[]
                )
                self.tasks[task_id] = task
                self.task_messages[task_id] = []

            # Update existing task
            else:
                task = self.tasks[task_id]

            # Add message to history
            message = params.message
            self.task_messages[task_id].append(message)
            task.history = self.task_messages[task_id][-params.historyLength:] if params.historyLength else self.task_messages[task_id]

            # Update task status to working
            task.status = TaskStatus(
                state=TaskState.WORKING,
                timestamp=datetime.utcnow().isoformat()
            )

            return task

    async def get_task(self, task_id: str, history_length: int = 0) -> Optional[Task]:
        """Get a task by ID."""
        async with self.lock:
            if task_id not in self.tasks:
                return None

            task = self.tasks[task_id]

            # Update history based on requested length
            if history_length > 0 and task_id in self.task_messages:
                task.history = self.task_messages[task_id][-history_length:]
            else:
                task.history = self.task_messages.get(task_id, [])

            return task

    async def cancel_task(self, task_id: str) -> Optional[Task]:
        """Cancel a task."""
        async with self.lock:
            if task_id not in self.tasks:
                return None

            task = self.tasks[task_id]
            task.status = TaskStatus(
                state=TaskState.CANCELED,
                timestamp=datetime.utcnow().isoformat()
            )

            return task

    async def set_push_notification(self, task_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Set push notification config for a task."""
        self.push_notifications[task_id] = config
        return {"id": task_id, "pushNotificationConfig": config}

    async def get_push_notification(self, task_id: str) -> Dict[str, Any]:
        """Get push notification config for a task."""
        config = self.push_notifications.get(task_id)
        return {"id": task_id, "pushNotificationConfig": config}

    # The following methods should be implemented by subclasses

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        """Handle send task request."""
        raise NotImplementedError()

    async def on_send_task_subscribe(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        """Handle send task with streaming request."""
        raise NotImplementedError()


class JudgeTaskManager(InMemoryTaskManager):
    def __init__(self, judge_agent_call):
        super().__init__()
        self.call_agent = judge_agent_call

    def _validate_request(
        self, request: Union[SendTaskRequest, SendTaskStreamingRequest]
    ) -> None:
        # Check if the requested output modes are compatible
        task_send_params: TaskSendParams = request.params
        if not are_modalities_compatible(
            task_send_params.acceptedOutputModes, ["text", "text/plain"]
        ):
            logger.warning(
                "Unsupported output mode. Received %s, Support %s",
                task_send_params.acceptedOutputModes,
                ["text", "text/plain"],
            )
            return new_incompatible_types_error(request.id)
        return None

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return await self._invoke(request)

    async def on_send_task_subscribe(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return self._stream_generator(request)

    async def _stream_generator(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            # First, send the "working" status
            task_status = TaskStatus(state=TaskState.WORKING)
            task_update_event = TaskStatusUpdateEvent(
                id=task_send_params.id,
                status=task_status,
                final=False,
            )
            yield SendTaskStreamingResponse(id=request.id, result=task_update_event)

            # Call the judge agent
            result = await self.call_agent(query)

            # Prepare response
            parts = [{"type": "text", "text": result}]
            task_state = TaskState.COMPLETED
            message = Message(role="agent", parts=parts)
            task_status = TaskStatus(state=task_state, message=message)

            # Update the task
            artifacts = [Artifact(parts=parts, index=0, lastChunk=True)]
            await self._update_store(task_send_params.id, task_status, artifacts)

            # Send artifact
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskArtifactUpdateEvent(
                    id=task_send_params.id,
                    artifact=artifacts[0],
                )
            )

            # Send final status
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskStatusUpdateEvent(
                    id=task_send_params.id,
                    status=task_status,
                    final=True
                )
            )
        except Exception as e:
            logger.error(f"An error occurred while streaming the response: {e}")
            yield JSONRPCResponse(
                id=request.id,
                error=InternalError(
                    message=f"An error occurred while streaming the response: {str(e)}"
                ),
            )

    async def _update_store(
        self, task_id: str, status: TaskStatus, artifacts: list[Artifact]
    ) -> Task:
        async with self.lock:
            try:
                task = self.tasks[task_id]
            except KeyError:
                logger.error(f"Task {task_id} not found for updating the task")
                raise ValueError(f"Task {task_id} not found")

            task.status = status
            if artifacts is not None:
                if task.artifacts is None:
                    task.artifacts = []
                task.artifacts.extend(artifacts)

            return task

    async def _invoke(self, request: SendTaskRequest) -> SendTaskResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            result = await self.call_agent(query)
        except Exception as e:
            logger.error(f"Error invoking agent: {e}")
            raise ValueError(f"Error invoking agent: {e}")

        parts = [{"type": "text", "text": result}]
        task_state = TaskState.COMPLETED

        task = await self._update_store(
            task_send_params.id,
            TaskStatus(
                state=task_state,
                message=Message(role="agent", parts=parts)
            ),
            [Artifact(parts=parts, index=0)],
        )

        return SendTaskResponse(id=request.id, result=task)

    def _get_user_query(self, task_send_params: TaskSendParams) -> str:
        for part in task_send_params.message.parts:
            if isinstance(part, TextPart) or (isinstance(part, dict) and part.get("type") == "text"):
                return part.text if hasattr(part, "text") else part.get("text", "")

        raise ValueError("Only text parts are supported")

class MaskTaskManager(InMemoryTaskManager):
    def __init__(self, mask_agent_call):
        super().__init__()
        self.call_agent = mask_agent_call

    def _validate_request(
        self, request: Union[SendTaskRequest, SendTaskStreamingRequest]
    ) -> None:
        # Check if the requested output modes are compatible
        task_send_params: TaskSendParams = request.params
        if not are_modalities_compatible(
            task_send_params.acceptedOutputModes, ["text", "text/plain"]
        ):
            logger.warning(
                "Unsupported output mode. Received %s, Support %s",
                task_send_params.acceptedOutputModes,
                ["text", "text/plain"],
            )
            return new_incompatible_types_error(request.id)
        return None

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return await self._invoke(request)

    async def on_send_task_subscribe(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return self._stream_generator(request)

    async def _stream_generator(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            # First, send the "working" status
            task_status = TaskStatus(state=TaskState.WORKING)
            task_update_event = TaskStatusUpdateEvent(
                id=task_send_params.id,
                status=task_status,
                final=False,
            )
            yield SendTaskStreamingResponse(id=request.id, result=task_update_event)

            # Call the judge agent
            result = await self.call_agent(query)

            # Prepare response
            parts = [{"type": "text", "text": result}]
            task_state = TaskState.COMPLETED
            message = Message(role="agent", parts=parts)
            task_status = TaskStatus(state=task_state, message=message)

            # Update the task
            artifacts = [Artifact(parts=parts, index=0, lastChunk=True)]
            await self._update_store(task_send_params.id, task_status, artifacts)

            # Send artifact
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskArtifactUpdateEvent(
                    id=task_send_params.id,
                    artifact=artifacts[0],
                )
            )

            # Send final status
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskStatusUpdateEvent(
                    id=task_send_params.id,
                    status=task_status,
                    final=True
                )
            )
        except Exception as e:
            logger.error(f"An error occurred while streaming the response: {e}")
            yield JSONRPCResponse(
                id=request.id,
                error=InternalError(
                    message=f"An error occurred while streaming the response: {str(e)}"
                ),
            )

    async def _update_store(
        self, task_id: str, status: TaskStatus, artifacts: list[Artifact]
    ) -> Task:
        async with self.lock:
            try:
                task = self.tasks[task_id]
            except KeyError:
                logger.error(f"Task {task_id} not found for updating the task")
                raise ValueError(f"Task {task_id} not found")

            task.status = status
            if artifacts is not None:
                if task.artifacts is None:
                    task.artifacts = []
                task.artifacts.extend(artifacts)

            return task

    async def _invoke(self, request: SendTaskRequest) -> SendTaskResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            result = await self.call_agent(query)
        except Exception as e:
            logger.error(f"Error invoking agent: {e}")
            raise ValueError(f"Error invoking agent: {e}")

        parts = [{"type": "text", "text": result}]
        task_state = TaskState.COMPLETED

        task = await self._update_store(
            task_send_params.id,
            TaskStatus(
                state=task_state,
                message=Message(role="agent", parts=parts)
            ),
            [Artifact(parts=parts, index=0)],
        )

        return SendTaskResponse(id=request.id, result=task)

    def _get_user_query(self, task_send_params: TaskSendParams) -> str:
        for part in task_send_params.message.parts:
            if isinstance(part, TextPart) or (isinstance(part, dict) and part.get("type") == "text"):
                return part.text if hasattr(part, "text") else part.get("text", "")

        raise ValueError("Only text parts are supported")

class SqlTaskManager(InMemoryTaskManager):
    def __init__(self, sql_agent_call):
        super().__init__()
        self.call_agent = sql_agent_call

    def _validate_request(
        self, request: Union[SendTaskRequest, SendTaskStreamingRequest]
    ) -> None:
        # Check if the requested output modes are compatible
        task_send_params: TaskSendParams = request.params
        if not are_modalities_compatible(
            task_send_params.acceptedOutputModes, ["text", "text/plain"]
        ):
            logger.warning(
                "Unsupported output mode. Received %s, Support %s",
                task_send_params.acceptedOutputModes,
                ["text", "text/plain"],
            )
            return new_incompatible_types_error(request.id)
        return None

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return await self._invoke(request)

    async def on_send_task_subscribe(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        error = self._validate_request(request)
        if error:
            return error

        await self.upsert_task(request.params)
        return self._stream_generator(request)

    async def _stream_generator(
        self, request: SendTaskStreamingRequest
    ) -> AsyncIterable[SendTaskStreamingResponse] | JSONRPCResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            # First, send the "working" status
            task_status = TaskStatus(state=TaskState.WORKING)
            task_update_event = TaskStatusUpdateEvent(
                id=task_send_params.id,
                status=task_status,
                final=False,
            )
            yield SendTaskStreamingResponse(id=request.id, result=task_update_event)

            # Call the judge agent
            result = await self.call_agent(query)

            # Prepare response
            parts = [{"type": "text", "text": result}]
            task_state = TaskState.COMPLETED
            message = Message(role="agent", parts=parts)
            task_status = TaskStatus(state=task_state, message=message)

            # Update the task
            artifacts = [Artifact(parts=parts, index=0, lastChunk=True)]
            await self._update_store(task_send_params.id, task_status, artifacts)

            # Send artifact
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskArtifactUpdateEvent(
                    id=task_send_params.id,
                    artifact=artifacts[0],
                )
            )

            # Send final status
            yield SendTaskStreamingResponse(
                id=request.id,
                result=TaskStatusUpdateEvent(
                    id=task_send_params.id,
                    status=task_status,
                    final=True
                )
            )
        except Exception as e:
            logger.error(f"An error occurred while streaming the response: {e}")
            yield JSONRPCResponse(
                id=request.id,
                error=InternalError(
                    message=f"An error occurred while streaming the response: {str(e)}"
                ),
            )

    async def _update_store(
        self, task_id: str, status: TaskStatus, artifacts: list[Artifact]
    ) -> Task:
        async with self.lock:
            try:
                task = self.tasks[task_id]
            except KeyError:
                logger.error(f"Task {task_id} not found for updating the task")
                raise ValueError(f"Task {task_id} not found")

            task.status = status
            if artifacts is not None:
                if task.artifacts is None:
                    task.artifacts = []
                task.artifacts.extend(artifacts)

            return task

    async def _invoke(self, request: SendTaskRequest) -> SendTaskResponse:
        task_send_params: TaskSendParams = request.params
        query = self._get_user_query(task_send_params)

        try:
            result = await self.call_agent(query)
        except Exception as e:
            logger.error(f"Error invoking agent: {e}")
            raise ValueError(f"Error invoking agent: {e}")

        parts = [{"type": "text", "text": result}]
        task_state = TaskState.COMPLETED

        task = await self._update_store(
            task_send_params.id,
            TaskStatus(
                state=task_state,
                message=Message(role="agent", parts=parts)
            ),
            [Artifact(parts=parts, index=0)],
        )

        return SendTaskResponse(id=request.id, result=task)

    def _get_user_query(self, task_send_params: TaskSendParams) -> str:
        for part in task_send_params.message.parts:
            if isinstance(part, TextPart) or (isinstance(part, dict) and part.get("type") == "text"):
                return part.text if hasattr(part, "text") else part.get("text", "")

        raise ValueError("Only text parts are supported")