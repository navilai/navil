"""Tests for the Contribution API — client-side and server-side.

Validates:
  - Client: sanitization, submission, privacy guarantees
  - Server: validation, deduplication, queuing for aggregation pipeline
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from navil.cloud.contribution_api import (
    CONTRIBUTION_ALLOWED_FIELDS,
    CONTRIBUTION_BANNED_FIELDS,
    ContributionClient,
    ContributionReceiver,
    ValidationError,
    sanitize_batch,
    sanitize_record,
    validate_batch,
    validate_contribution,
)

# ── Sanitization (Client-Side) ─────────────────────────────────


class TestSanitizeRecord:
    """Tests for client-side record sanitization."""

    def test_strips_source_ip(self):
        record = {
            "tool_name": "read_file",
            "source_ip": "192.168.1.1",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "source_ip" not in sanitized

    def test_strips_arguments(self):
        record = {
            "tool_name": "exec_command",
            "arguments": {"cmd": "rm -rf /"},
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "arguments" not in sanitized

    def test_strips_request_headers(self):
        record = {
            "tool_name": "test",
            "request_headers": {"Authorization": "Bearer secret-token"},
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "request_headers" not in sanitized

    def test_strips_raw_body(self):
        record = {
            "tool_name": "test",
            "raw_body": '{"jsonrpc":"2.0","params":{"sensitive":"data"}}',
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "raw_body" not in sanitized

    def test_strips_tool_name(self):
        """Individual tool names could reveal infrastructure topology."""
        record = {
            "tool_name": "internal_admin_panel_v3",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "tool_name" not in sanitized
        # But tool_sequence_hash should be present
        assert "tool_sequence_hash" in sanitized

    def test_produces_sha256_hash(self):
        record = {
            "tool_name": "read_file",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert len(sanitized["tool_sequence_hash"]) == 64  # SHA-256 hex

    def test_copies_allowed_metadata(self):
        record = {
            "tool_name": "test",
            "anomaly_type": "RECONNAISSANCE",
            "severity": "HIGH",
            "confidence": 0.87,
            "source_type": "canary",
            "profile_name": "dev_tools",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert sanitized["anomaly_type"] == "RECONNAISSANCE"
        assert sanitized["severity"] == "HIGH"
        assert sanitized["confidence"] == 0.87
        assert sanitized["source_type"] == "canary"
        assert sanitized["profile_name"] == "dev_tools"

    def test_integer_aggregates(self):
        record = {
            "tool_name": "test",
            "tool_count": 42,
            "unique_tool_count": 5,
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert sanitized["tool_count"] == 42
        assert sanitized["unique_tool_count"] == 5

    def test_contribution_uuid_generated(self):
        record = {
            "tool_name": "test",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "contribution_uuid" in sanitized
        # Should be a valid UUID
        uuid.UUID(sanitized["contribution_uuid"])

    def test_contribution_uuid_deterministic(self):
        record = {"tool_name": "test", "timestamp": "2026-03-01T12:00:00Z"}
        s1 = sanitize_record(record)
        s2 = sanitize_record(record)
        assert s1["contribution_uuid"] == s2["contribution_uuid"]

    def test_output_only_contains_allowed_fields(self):
        """Every key in output must be in CONTRIBUTION_ALLOWED_FIELDS."""
        record = {
            "tool_name": "test",
            "source_ip": "10.0.0.1",
            "arguments": {"key": "value"},
            "request_headers": {"X-Custom": "header"},
            "raw_body": "raw",
            "anomaly_type": "RATE_SPIKE",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "timestamp": "2026-03-01T00:00:00Z",
            "extra_unknown_field": "should be dropped",
        }
        sanitized = sanitize_record(record)
        for key in sanitized:
            assert key in CONTRIBUTION_ALLOWED_FIELDS, f"{key} not in allowlist"

    def test_exhaustive_banned_field_injection(self):
        """Inject every banned field and verify none appear in output."""
        for banned in CONTRIBUTION_BANNED_FIELDS:
            record = {
                banned: "injected_value",
                "timestamp": "2026-03-01T00:00:00Z",
            }
            sanitized = sanitize_record(record)
            assert banned not in sanitized, f"Banned field {banned} leaked through"


class TestSanitizeBatch:
    """Tests for batch sanitization."""

    def test_valid_batch(self):
        records = [
            {"tool_name": "t1", "timestamp": "2026-03-01T00:00:00Z"},
            {"tool_name": "t2", "timestamp": "2026-03-01T00:01:00Z"},
        ]
        results = sanitize_batch(records)
        assert len(results) == 2

    def test_skips_invalid(self):
        records = [
            {"tool_name": "ok", "timestamp": "2026-03-01T00:00:00Z"},
            None,  # type: ignore[list-item]
            {"tool_name": "also_ok", "timestamp": "2026-03-01T00:01:00Z"},
        ]
        results = sanitize_batch(records)  # type: ignore[arg-type]
        assert len(results) == 2

    def test_empty_batch(self):
        results = sanitize_batch([])
        assert results == []


# ── ContributionClient ──────────────────────────────────────────


class TestContributionClient:
    """Tests for the HTTP submission client."""

    @pytest.mark.asyncio
    async def test_submit_empty(self):
        client = ContributionClient(api_key="test")
        result = await client.submit_detections([])
        assert result["submitted"] == 0
        assert result["status"] == "no_data"

    @pytest.mark.asyncio
    async def test_submit_success(self):
        client = ContributionClient(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._http_client = mock_client

        records = [
            {"tool_name": "read_file", "timestamp": "2026-03-01T00:00:00Z"},
        ]
        result = await client.submit_detections(records, source_type="canary")
        assert result["submitted"] == 1
        assert result["status"] == "ok"

        # Verify POST payload is sanitized
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        for c in payload["contributions"]:
            assert "tool_name" not in c
            assert "source_ip" not in c

    @pytest.mark.asyncio
    async def test_submit_with_metadata(self):
        client = ContributionClient(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._http_client = mock_client

        records = [{"tool_name": "test", "timestamp": "2026-03-01T00:00:00Z"}]
        result = await client.submit_detections(
            records,
            source_type="honeypot",
            profile_name="cloud_creds",
        )
        assert result["submitted"] == 1

        # Check that source metadata was included
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        entry = payload["contributions"][0]
        assert entry.get("source_type") == "honeypot"
        assert entry.get("profile_name") == "cloud_creds"

    @pytest.mark.asyncio
    async def test_submit_http_error(self):
        client = ContributionClient(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 503
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._http_client = mock_client

        records = [{"tool_name": "test", "timestamp": "2026-03-01T00:00:00Z"}]
        result = await client.submit_detections(records)
        assert result["submitted"] == 0
        assert "error" in result["status"]

    @pytest.mark.asyncio
    async def test_close(self):
        client = ContributionClient()
        mock = AsyncMock()
        client._http_client = mock
        await client.close()
        mock.aclose.assert_called_once()
        assert client._http_client is None


# ── Validation (Server-Side) ───────────────────────────────────


class TestValidateContribution:
    """Tests for server-side contribution validation."""

    def test_valid_entry(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "tool_sequence_hash": "a" * 64,
            "anomaly_type": "RATE_SPIKE",
            "severity": "HIGH",
            "confidence": 0.85,
            "source_type": "canary",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        validated = validate_contribution(entry)
        assert validated == entry

    def test_missing_contribution_uuid(self):
        entry = {"tool_sequence_hash": "abc", "severity": "HIGH"}
        with pytest.raises(ValidationError, match="contribution_uuid"):
            validate_contribution(entry)

    def test_banned_field_rejected(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "source_ip": "192.168.1.1",  # banned
        }
        with pytest.raises(ValidationError, match="banned"):
            validate_contribution(entry)

    def test_unknown_field_rejected(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "unknown_custom_field": "value",
        }
        with pytest.raises(ValidationError, match="Unknown"):
            validate_contribution(entry)

    def test_invalid_severity(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "severity": "SUPER_CRITICAL",
        }
        with pytest.raises(ValidationError, match="severity"):
            validate_contribution(entry)

    def test_valid_severities(self):
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            entry = {
                "contribution_uuid": str(uuid.uuid4()),
                "severity": severity,
            }
            validated = validate_contribution(entry)
            assert validated["severity"] == severity

    def test_invalid_confidence_range(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "confidence": 1.5,
        }
        with pytest.raises(ValidationError, match="Confidence"):
            validate_contribution(entry)

    def test_invalid_confidence_negative(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "confidence": -0.1,
        }
        with pytest.raises(ValidationError, match="Confidence"):
            validate_contribution(entry)

    def test_valid_confidence_bounds(self):
        for conf in (0.0, 0.5, 1.0):
            entry = {
                "contribution_uuid": str(uuid.uuid4()),
                "confidence": conf,
            }
            validated = validate_contribution(entry)
            assert validated["confidence"] == conf

    def test_invalid_source_type(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "source_type": "unknown_source",
        }
        with pytest.raises(ValidationError, match="source_type"):
            validate_contribution(entry)

    def test_valid_source_types(self):
        for src in ("canary", "honeypot", "detector"):
            entry = {
                "contribution_uuid": str(uuid.uuid4()),
                "source_type": src,
            }
            validated = validate_contribution(entry)
            assert validated["source_type"] == src

    def test_negative_tool_count(self):
        entry = {
            "contribution_uuid": str(uuid.uuid4()),
            "tool_count": -1,
        }
        with pytest.raises(ValidationError, match="tool_count"):
            validate_contribution(entry)

    def test_not_a_dict(self):
        with pytest.raises(ValidationError, match="must be a dict"):
            validate_contribution("not a dict")  # type: ignore[arg-type]

    def test_oversized_uuid(self):
        entry = {
            "contribution_uuid": "x" * 300,
        }
        with pytest.raises(ValidationError, match="contribution_uuid"):
            validate_contribution(entry)


class TestValidateBatch:
    """Tests for batch validation."""

    def test_valid_batch(self):
        entries = [
            {"contribution_uuid": str(uuid.uuid4())},
            {"contribution_uuid": str(uuid.uuid4())},
        ]
        valid, errors = validate_batch(entries)
        assert len(valid) == 2
        assert len(errors) == 0

    def test_mixed_batch(self):
        entries = [
            {"contribution_uuid": str(uuid.uuid4())},
            {"source_ip": "bad"},  # banned field
            {"contribution_uuid": str(uuid.uuid4()), "severity": "INVALID"},
        ]
        valid, errors = validate_batch(entries)
        assert len(valid) == 1
        assert len(errors) == 2

    def test_oversized_batch(self):
        entries = [{"contribution_uuid": str(uuid.uuid4())} for _ in range(600)]
        valid, errors = validate_batch(entries)
        assert len(valid) == 0
        assert len(errors) == 1
        assert "too large" in errors[0]["error"].lower()

    def test_empty_batch(self):
        valid, errors = validate_batch([])
        assert valid == []
        assert errors == []


# ── ContributionReceiver ────────────────────────────────────────


class TestContributionReceiver:
    """Tests for server-side contribution receiving, dedup, and queuing."""

    def test_receive_valid_contributions(self):
        receiver = ContributionReceiver()
        contributions = [
            {"contribution_uuid": str(uuid.uuid4()), "severity": "HIGH"},
            {"contribution_uuid": str(uuid.uuid4()), "severity": "LOW"},
        ]
        result = receiver.receive(contributions)
        assert result["accepted"] == 2
        assert result["duplicates"] == 0
        assert result["rejected"] == 0
        assert receiver.queue_size == 2

    def test_deduplication(self):
        receiver = ContributionReceiver()
        shared_uuid = str(uuid.uuid4())
        contributions = [
            {"contribution_uuid": shared_uuid, "severity": "HIGH"},
        ]

        result1 = receiver.receive(contributions)
        assert result1["accepted"] == 1

        result2 = receiver.receive(contributions)
        assert result2["accepted"] == 0
        assert result2["duplicates"] == 1

        # Queue should only have one entry
        assert receiver.queue_size == 1

    def test_validation_rejects_invalid(self):
        receiver = ContributionReceiver()
        contributions = [
            {"contribution_uuid": str(uuid.uuid4())},  # valid
            {"source_ip": "192.168.1.1"},  # banned field
        ]
        result = receiver.receive(contributions)
        assert result["accepted"] == 1
        assert result["rejected"] == 1
        assert len(result["errors"]) == 1

    def test_drain_queue(self):
        receiver = ContributionReceiver()
        for _ in range(5):
            receiver.receive([{"contribution_uuid": str(uuid.uuid4())}])

        assert receiver.queue_size == 5
        drained = receiver.drain_queue()
        assert len(drained) == 5
        assert receiver.queue_size == 0

    def test_drain_queue_partial(self):
        receiver = ContributionReceiver()
        for _ in range(5):
            receiver.receive([{"contribution_uuid": str(uuid.uuid4())}])

        drained = receiver.drain_queue(max_items=3)
        assert len(drained) == 3
        assert receiver.queue_size == 2

    def test_drain_queue_empty(self):
        receiver = ContributionReceiver()
        drained = receiver.drain_queue()
        assert drained == []

    def test_stats(self):
        receiver = ContributionReceiver()
        shared_uuid = str(uuid.uuid4())

        receiver.receive([
            {"contribution_uuid": str(uuid.uuid4())},
            {"contribution_uuid": shared_uuid},
        ])
        receiver.receive([
            {"contribution_uuid": shared_uuid},  # duplicate
            {"source_ip": "bad"},  # rejected
        ])

        stats = receiver.stats
        assert stats["total_received"] == 4
        assert stats["total_accepted"] == 2
        assert stats["total_duplicates"] == 1
        assert stats["total_rejected"] == 1

    def test_clear_seen(self):
        receiver = ContributionReceiver()
        test_uuid = str(uuid.uuid4())
        receiver.receive([{"contribution_uuid": test_uuid}])

        cleared = receiver.clear_seen()
        assert cleared == 1

        # Should be able to re-submit after clearing
        result = receiver.receive([{"contribution_uuid": test_uuid}])
        assert result["accepted"] == 1

    def test_max_queue_size(self):
        receiver = ContributionReceiver(max_queue_size=5)
        for _ in range(10):
            receiver.receive([{"contribution_uuid": str(uuid.uuid4())}])
        # Ring buffer should cap at 5
        assert receiver.queue_size == 5

    def test_received_at_timestamp_added(self):
        receiver = ContributionReceiver()
        receiver.receive([{"contribution_uuid": str(uuid.uuid4())}])
        drained = receiver.drain_queue()
        assert "_received_at" in drained[0]
