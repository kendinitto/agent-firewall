"""Agent Firewall Proxy Server."""

from __future__ import annotations

import argparse
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.detection.inspector import ContentInspector
from src.policy.engine import PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agent_firewall")

_policy_engine: PolicyEngine | None = None
_inspector: ContentInspector | None = None
_handler: object | None = None
_passthrough_handler: object | None = None


def _initialize(config_path: str | Path | None = None) -> None:
    global _policy_engine, _inspector, _handler, _passthrough_handler
    from src.proxy.handlers import ActionHandler, PassthroughHandler

    if config_path is None:
        config_path = Path("configs/policy.yaml")
    config_path = Path(config_path)
    if not config_path.exists():
        config_path = Path(__file__).parent.parent.parent / "configs" / "policy.yaml"

    logger.info("Loading policy from %s", config_path)
    _policy_engine = PolicyEngine.from_yaml(str(config_path))
    _inspector = ContentInspector(_policy_engine)
    _handler = ActionHandler(_policy_engine, _inspector)
    _passthrough_handler = PassthroughHandler()


def get_handler() -> object:
    if _handler is None:
        _initialize()
    return _handler


def get_inspector() -> ContentInspector:
    if _inspector is None:
        _initialize()
    return _inspector


def get_passthrough_handler() -> object:
    if _passthrough_handler is None:
        _initialize()
    return _passthrough_handler


@asynccontextmanager
async def lifespan(application: FastAPI) -> None:
    _initialize()
    yield


app = FastAPI(title="Agent Firewall", version="0.1.0", lifespan=lifespan)


class ActionRequest(BaseModel):
    action: str
    target: str
    method: str | None = None
    content: str | None = None
    session_id: str | None = None
    metadata: dict | None = None
    headers: dict | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    policies_loaded: bool


@app.get("/health")
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok" if _policy_engine else "not_initialized",
        version="0.1.0",
        policies_loaded=_policy_engine is not None,
    )


@app.post("/action/check")
async def check_action(request: ActionRequest) -> JSONResponse:
    handler = get_handler()
    result = await handler.handle(request.model_dump())
    status_code = 200
    if result.get("status") == "blocked":
        status_code = 403
    return JSONResponse(content=result, status_code=status_code)


@app.post("/action/passthrough")
async def passthrough_action(request: ActionRequest) -> JSONResponse:
    pt_handler = get_passthrough_handler()
    inspector = get_inspector()
    result = await pt_handler.handle(request.model_dump(), inspector)
    status_code = 200
    if result.get("status") == "blocked":
        status_code = 403
    elif result.get("status") == "error":
        status_code = 502
    return JSONResponse(content=result, status_code=status_code)


@app.post("/action/batch")
async def batch_check(requests: list[ActionRequest]) -> JSONResponse:
    handler = get_handler()
    results = []
    has_blocked = False
    for req in requests:
        result = await handler.handle(req.model_dump())
        results.append(result)
        if result.get("status") == "blocked":
            has_blocked = True

    return JSONResponse(
        content={"results": results, "summary": {"total": len(results), "blocked": has_blocked}},
        status_code=403 if has_blocked else 200,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Firewall Proxy Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument(
        "--config",
        default="configs/policy.yaml",
        help="Path to policy YAML file",
    )
    parser.add_argument("--log-level", default="info", help="Log level")
    args = parser.parse_args()

    logger.info("Starting Agent Firewall on %s:%d", args.host, args.port)
    logger.info("Config: %s", args.config)

    uvicorn.run(
        "src.proxy.server:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
