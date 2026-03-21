"""Tests for A2A (Agent-to-Agent) protocol support.

Tests cover:
- AgentCard serialization to A2A-compliant JSON
- build_navil_agent_card() defaults and env overrides
- Task lifecycle (create, state transitions, messages, artifacts)
- TaskStore CRUD operations
- Task filtering and listing
"""

from __future__ import annotations

import os
from unittest.mock import patch

from navil.a2a.agent_card import (
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    SecurityScheme,
    build_navil_agent_card,
)
from navil.a2a.tasks import Task, TaskArtifact, TaskMessage, TaskState, TaskStore


class TestAgentCard:
    """Test AgentCard model and serialization."""

    def test_agent_card_to_dict_required_fields(self) -> None:
        card = AgentCard(
            name="test-agent",
            description="A test agent",
            provider=AgentProvider(organization="TestOrg"),
            interfaces=[AgentInterface(protocol="jsonrpc", url="http://localhost:8080/a2a")],
        )
        d = card.to_dict()

        assert d["name"] == "test-agent"
        assert d["description"] == "A test agent"
        assert d["provider"]["organization"] == "TestOrg"
        assert d["version"] == "1.0.0"
        assert d["capabilities"]["streaming"] is False
        assert len(d["interfaces"]) == 1
        assert d["interfaces"][0]["protocol"] == "jsonrpc"

    def test_agent_card_with_skills(self) -> None:
        card = AgentCard(
            name="skilled-agent",
            description="Agent with skills",
            provider=AgentProvider(organization="Org"),
            skills=[
                AgentSkill(id="s1", name="Skill 1", description="Does thing 1", tags=["tag1"]),
                AgentSkill(id="s2", name="Skill 2", description="Does thing 2"),
            ],
            interfaces=[],
        )
        d = card.to_dict()

        assert len(d["skills"]) == 2
        assert d["skills"][0]["id"] == "s1"
        assert d["skills"][0]["tags"] == ["tag1"]

    def test_agent_card_with_security(self) -> None:
        card = AgentCard(
            name="secure-agent",
            description="Secured",
            provider=AgentProvider(organization="Org"),
            security_schemes={
                "jwt": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
            },
            security=[{"jwt": []}],
            interfaces=[],
        )
        d = card.to_dict()

        assert "securitySchemes" in d
        assert d["securitySchemes"]["jwt"]["type"] == "http"
        assert d["securitySchemes"]["jwt"]["bearerFormat"] == "JWT"
        assert d["security"] == [{"jwt": []}]

    def test_agent_card_with_extensions(self) -> None:
        card = AgentCard(
            name="ext-agent",
            description="With extensions",
            provider=AgentProvider(organization="Org"),
            extensions=[{"name": "navil-governance", "version": "1.0.0"}],
            interfaces=[],
        )
        d = card.to_dict()

        assert len(d["extensions"]) == 1
        assert d["extensions"][0]["name"] == "navil-governance"


class TestBuildNavilAgentCard:
    """Test build_navil_agent_card() factory."""

    def test_defaults(self) -> None:
        card = build_navil_agent_card()
        d = card.to_dict()

        assert d["name"] == "navil-agent"
        assert "navil_jwt" in d["securitySchemes"]
        assert d["security"] == [{"navil_jwt": []}]
        assert len(d["interfaces"]) == 1
        assert d["interfaces"][0]["protocol"] == "jsonrpc"
        assert len(d["extensions"]) == 1
        assert d["extensions"][0]["name"] == "navil-governance"

    def test_custom_values(self) -> None:
        card = build_navil_agent_card(
            agent_name="my-agent",
            agent_description="My custom agent",
            base_url="https://api.example.com",
            provider_org="ExampleCorp",
        )
        d = card.to_dict()

        assert d["name"] == "my-agent"
        assert d["description"] == "My custom agent"
        assert d["provider"]["organization"] == "ExampleCorp"
        assert "https://api.example.com/a2a" in d["interfaces"][0]["url"]

    def test_env_overrides(self) -> None:
        env = {
            "NAVIL_AGENT_NAME": "env-agent",
            "NAVIL_BASE_URL": "https://env.example.com",
            "NAVIL_PROVIDER_ORG": "EnvOrg",
        }
        with patch.dict(os.environ, env):
            card = build_navil_agent_card()
            d = card.to_dict()

        assert d["name"] == "env-agent"
        assert d["provider"]["organization"] == "EnvOrg"

    def test_custom_skills(self) -> None:
        skills = [
            AgentSkill(id="code-review", name="Code Review", description="Reviews PRs"),
        ]
        card = build_navil_agent_card(skills=skills)
        d = card.to_dict()

        assert len(d["skills"]) == 1
        assert d["skills"][0]["id"] == "code-review"


class TestTask:
    """Test A2A Task model."""

    def test_task_auto_id(self) -> None:
        task = Task()
        assert task.id.startswith("task-")
        assert len(task.id) > 10

    def test_task_to_dict(self) -> None:
        task = Task(
            source_agent="agent-a",
            target_agent="agent-b",
            navil_scope="github-pr-review",
        )
        d = task.to_dict()

        assert d["state"] == "pending"
        assert d["metadata"]["navil"]["source_agent"] == "agent-a"
        assert d["metadata"]["navil"]["target_agent"] == "agent-b"
        assert d["metadata"]["navil"]["scope"] == "github-pr-review"

    def test_task_with_messages(self) -> None:
        task = Task(
            messages=[
                TaskMessage(role="user", content="Review this PR"),
                TaskMessage(role="agent", content="Looking at the changes..."),
            ]
        )
        d = task.to_dict()

        assert len(d["messages"]) == 2
        assert d["messages"][0]["role"] == "user"
        assert d["messages"][0]["parts"][0]["text"] == "Review this PR"


class TestTaskStore:
    """Test TaskStore CRUD operations."""

    def test_create_and_get(self) -> None:
        store = TaskStore()
        task = Task(source_agent="a", target_agent="b")
        store.create(task)

        retrieved = store.get(task.id)
        assert retrieved is not None
        assert retrieved.id == task.id
        assert retrieved.source_agent == "a"

    def test_get_nonexistent(self) -> None:
        store = TaskStore()
        assert store.get("nonexistent") is None

    def test_update_state(self) -> None:
        store = TaskStore()
        task = Task()
        store.create(task)

        updated = store.update_state(task.id, TaskState.WORKING)
        assert updated is not None
        assert updated.state == TaskState.WORKING

    def test_add_message(self) -> None:
        store = TaskStore()
        task = Task()
        store.create(task)

        msg = TaskMessage(role="user", content="Hello")
        updated = store.add_message(task.id, msg)
        assert updated is not None
        assert len(updated.messages) == 1

    def test_add_artifact(self) -> None:
        store = TaskStore()
        task = Task()
        store.create(task)

        artifact = TaskArtifact(name="result.json", content='{"ok": true}')
        updated = store.add_artifact(task.id, artifact)
        assert updated is not None
        assert len(updated.artifacts) == 1

    def test_cancel(self) -> None:
        store = TaskStore()
        task = Task()
        store.create(task)

        canceled = store.cancel(task.id)
        assert canceled is not None
        assert canceled.state == TaskState.CANCELED

    def test_list_with_filters(self) -> None:
        store = TaskStore()
        store.create(Task(source_agent="a", target_agent="b"))
        store.create(Task(source_agent="a", target_agent="c"))
        store.create(Task(source_agent="x", target_agent="b"))

        # Filter by source
        results = store.list_tasks(source_agent="a")
        assert len(results) == 2

        # Filter by target
        results = store.list_tasks(target_agent="b")
        assert len(results) == 2

        # Filter by both
        results = store.list_tasks(source_agent="a", target_agent="b")
        assert len(results) == 1

    def test_list_by_state(self) -> None:
        store = TaskStore()
        t1 = Task()
        t2 = Task()
        store.create(t1)
        store.create(t2)
        store.update_state(t1.id, TaskState.COMPLETED)

        pending = store.list_tasks(state=TaskState.PENDING)
        assert len(pending) == 1

        completed = store.list_tasks(state=TaskState.COMPLETED)
        assert len(completed) == 1
