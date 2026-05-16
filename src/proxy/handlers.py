"""Request handlers for the Agent Firewall proxy."""

from __future__ import annotations

import logging
from typing import Any

from src.detection.inspector import (
    ActionRequest,
    ActionType,
    ContentInspector,
)
from src.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class ActionHandler:
    """Handles and validates agent tool requests."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        inspector: ContentInspector,
    ) -> None:
        self._policy = policy_engine
        self._inspector = inspector

    async def handle(self, request_data: dict[str, Any]) -> dict[str, Any]:
        action = request_data.get("action")
        target = request_data.get("target", "")
        method = request_data.get("method")
        content = request_data.get("content")
        session_id = request_data.get("session_id")

        action_request = ActionRequest(
            action=ActionType(action),
            target=target,
            method=method,
            content=content,
            session_id=session_id,
            metadata=request_data.get("metadata"),
        )

        results = self._inspector.inspect_action(action_request)

        most_severe = None
        for result in results:
            if result.is_blocked:
                logger.warning(
                    "BLOCKED action=%s target=%s reason=%s severity=%s",
                    action,
                    target[:200],
                    result.reason,
                    result.severity,
                )
                most_severe = result
                break
            if result.is_flagged:
                if most_severe is None or result.severity.value > most_severe.severity.value:
                    most_severe = result

        if most_severe is None:
            return {
                "status": "allowed",
                "action": action,
                "target": target,
                "session_id": session_id,
            }

        if most_severe.is_blocked:
            return {
                "status": "blocked",
                "action": action,
                "target": target[:200],
                "reason": most_severe.reason,
                "severity": most_severe.severity.value,
                "findings": most_severe.findings,
                "session_id": session_id,
            }

        return {
            "status": "flagged",
            "action": action,
            "target": target[:200],
            "reason": most_severe.reason,
            "severity": most_severe.severity.value,
            "findings": most_severe.findings,
            "session_id": session_id,
        }


class PassthroughHandler:
    """Handles passthrough requests that should be forwarded to real endpoints."""

    async def handle(
        self,
        request_data: dict[str, Any],
        inspector: ContentInspector,
    ) -> dict[str, Any]:
        import aiohttp

        action = request_data.get("action")
        target = request_data.get("target", "")
        method = request_data.get("method", "GET")
        content = request_data.get("content")
        headers = request_data.get("headers", {})

        action_request = ActionRequest(
            action=ActionType(action),
            target=target,
            method=method,
            content=content,
            session_id=request_data.get("session_id"),
            metadata=request_data.get("metadata"),
        )

        results = inspector.inspect_action(action_request)

        for result in results:
            if result.is_blocked:
                return {
                    "status": "blocked",
                    "action": action,
                    "target": target[:200],
                    "reason": result.reason,
                    "severity": result.severity.value,
                    "findings": result.findings,
                    "passthrough": False,
                }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=target,
                    data=content,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.text()

                    if method.upper() in ("POST", "PUT", "PATCH"):
                        pass
                    else:
                        fetch_check = ActionRequest(
                            action=ActionType.WEB_FETCH,
                            target=target,
                            content=body,
                            session_id=request_data.get("session_id"),
                        )
                        fetch_results = inspector.inspect_action(fetch_check)
                        for fr in fetch_results:
                            if fr.is_flagged:
                                return {
                                    "status": "allowed_with_warning",
                                    "action": action,
                                    "target": target[:200],
                                    "reason": fr.reason,
                                    "severity": fr.severity.value,
                                    "findings": fr.findings,
                                    "passthrough": True,
                                    "response_status": resp.status,
                                    "response_body_length": len(body),
                                    "injection_warning": True,
                                }

                    return {
                        "status": "allowed",
                        "action": action,
                        "target": target[:200],
                        "passthrough": True,
                        "response_status": resp.status,
                        "response_body_length": len(body),
                        "response_body": body[:10000],
                    }
        except Exception as e:
            return {
                "status": "error",
                "action": action,
                "target": target[:200],
                "error": str(e),
                "passthrough": False,
            }
