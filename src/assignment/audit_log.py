"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from time import monotonic
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[float, dict]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and start time for the request."""
        self._open[request_id or user_id] = (
            monotonic(),
            {"user_id": user_id, "request_id": request_id, "input": text, "timestamp": utc_now_iso()},
        )

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the audit entry with the response, decision and latency."""
        started = self._open.pop(request_id or user_id, None)
        start, entry = started if started else (
            None, {"user_id": user_id, "request_id": request_id, "timestamp": utc_now_iso()},
        )
        entry.update(
            output=text, blocked=blocked, layer=layer,
            latency_ms=(monotonic() - start) * 1000 if start is not None else None,
        )
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
