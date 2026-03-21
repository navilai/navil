"""A2A Task Dispatch — inter-agent task management.

Implements the A2A task lifecycle:
    sendMessage → Task (pending)
    getTask → Task (with current state)
    cancelTask → Task (canceled)

Tasks flow through Navil's governance layer:
    Agent A → sendMessage → Navil Proxy (auth + policy check) → Agent B
    Agent B → response → Navil Proxy (telemetry) → Agent A
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskState(Enum):
    """A2A task lifecycle states."""

    PENDING = "pending"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class TaskMessage:
    """A message within an A2A task conversation."""

    role: str  # "user" or "agent"
    content: str
    content_type: str = "text/plain"
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "parts": [{"type": self.content_type, "text": self.content}],
            "timestamp": self.timestamp,
        }


@dataclass
class TaskArtifact:
    """An output artifact produced by the agent."""

    name: str
    content: str
    content_type: str = "text/plain"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "parts": [{"type": self.content_type, "text": self.content}],
        }


@dataclass
class Task:
    """An A2A task — the unit of work between agents."""

    id: str = ""
    state: TaskState = TaskState.PENDING
    messages: list[TaskMessage] = field(default_factory=list)
    artifacts: list[TaskArtifact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    # Navil governance metadata
    source_agent: str = ""
    target_agent: str = ""
    navil_scope: str = ""  # X-Navil-Scope for tool visibility

    def __post_init__(self) -> None:
        if not self.id:
            self.id = f"task-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state.value,
            "messages": [m.to_dict() for m in self.messages],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "metadata": {
                **self.metadata,
                "navil": {
                    "source_agent": self.source_agent,
                    "target_agent": self.target_agent,
                    "scope": self.navil_scope,
                },
            },
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }


class TaskStore:
    """In-memory task store for A2A task management.

    Production deployments should back this with Redis or a database.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def create(self, task: Task) -> Task:
        """Store a new task."""
        self._tasks[task.id] = task
        logger.info(f"A2A task created: {task.id} ({task.source_agent} → {task.target_agent})")
        return task

    def get(self, task_id: str) -> Task | None:
        """Retrieve a task by ID."""
        return self._tasks.get(task_id)

    def update_state(self, task_id: str, state: TaskState) -> Task | None:
        """Update a task's state."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.state = state
        task.updated_at = datetime.now(timezone.utc).isoformat()
        return task

    def add_message(self, task_id: str, message: TaskMessage) -> Task | None:
        """Add a message to a task's conversation."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.messages.append(message)
        task.updated_at = datetime.now(timezone.utc).isoformat()
        return task

    def add_artifact(self, task_id: str, artifact: TaskArtifact) -> Task | None:
        """Add an artifact to a task."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.artifacts.append(artifact)
        task.updated_at = datetime.now(timezone.utc).isoformat()
        return task

    def cancel(self, task_id: str) -> Task | None:
        """Cancel a task."""
        return self.update_state(task_id, TaskState.CANCELED)

    def list_tasks(
        self,
        source_agent: str | None = None,
        target_agent: str | None = None,
        state: TaskState | None = None,
        limit: int = 50,
    ) -> list[Task]:
        """List tasks with optional filters."""
        tasks = list(self._tasks.values())

        if source_agent:
            tasks = [t for t in tasks if t.source_agent == source_agent]
        if target_agent:
            tasks = [t for t in tasks if t.target_agent == target_agent]
        if state:
            tasks = [t for t in tasks if t.state == state]

        # Most recent first
        tasks.sort(key=lambda t: t.created_at, reverse=True)
        return tasks[:limit]
