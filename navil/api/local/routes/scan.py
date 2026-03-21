# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Scanner and pentest endpoints."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from navil.api.local.state import AppState

from ._helpers import PentestRequest, ScanRequest

router = APIRouter()


@router.post("/scan")
def scan_config(req: ScanRequest) -> dict[str, Any]:
    s = AppState.get()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(req.config, f)
        tmp_path = f.name
    try:
        result = s.scanner.scan(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return result


@router.post("/pentest")
def run_pentest(req: PentestRequest) -> dict[str, Any]:
    """Run SAFE-MCP attack simulations against the anomaly detectors."""
    from navil.pentest import PentestEngine

    s = AppState.get()
    engine = PentestEngine(s.anomaly_detector, s.policy_engine)

    if req.scenario:
        result = engine.run_scenario(req.scenario)
        return {
            "status": "completed",
            "total_scenarios": 1,
            "passed": 1 if result.verdict == "PASS" else 0,
            "failed": 1 if result.verdict == "FAIL" else 0,
            "partial": 1 if result.verdict == "PARTIAL" else 0,
            "detection_rate": (
                100.0 if result.verdict == "PASS" else 50.0 if result.verdict == "PARTIAL" else 0.0
            ),
            "results": [result.to_dict()],
        }
    return engine.run_all()
