"""FastAPI app: redact -> leak-check -> forward to Anthropic -> restore."""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .. import audit
from ..config import Settings, validate_vault_name
from ..engine import Engine, build_engine
from ..leakguard import LeakDetected
from .anthropic import (
    Blocked,
    RequestRedactor,
    SSERewriter,
    ThinkingCache,
    rehydrate_response,
)

log = logging.getLogger("bestie.proxy")

_FORWARD_REQUEST_HEADERS = ("anthropic-version", "anthropic-beta", "content-type", "user-agent")
_FORWARD_RESPONSE_HEADERS = ("request-id", "retry-after", "x-should-retry")


def _error(status: int, message: str, kind: str = "invalid_request_error") -> JSONResponse:
    return JSONResponse(
        {"type": "error", "error": {"type": kind, "message": f"[Bestie] {message}"}},
        status_code=status,
    )


def create_app(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    dump_upstream: bool = False,
) -> FastAPI:
    engines: dict[str, Engine] = {}
    lock = threading.RLock()
    thinking = ThinkingCache()
    client = httpx.AsyncClient(
        base_url=settings.upstream_url.rstrip("/"),
        transport=transport,
        timeout=httpx.Timeout(600.0, connect=15.0),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await client.aclose()

    app = FastAPI(
        title="Bestie", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )

    def engine_for(request: Request) -> Engine:
        name = validate_vault_name(request.headers.get("x-bestie-vault") or settings.default_vault)
        with lock:
            if name not in engines:
                engines[name] = build_engine(settings, name)
            return engines[name]

    def upstream_headers(request: Request) -> dict[str, str]:
        headers = {k: v for k in _FORWARD_REQUEST_HEADERS if (v := request.headers.get(k))}
        headers.setdefault("anthropic-version", "2023-06-01")
        if settings.api_key:
            headers["x-api-key"] = settings.api_key
        else:
            # No key configured on the proxy: pass the client's own credentials.
            for k in ("x-api-key", "authorization"):
                if v := request.headers.get(k):
                    headers[k] = v
        return headers

    def response_headers(resp: httpx.Response) -> dict[str, str]:
        out = {k: v for k in _FORWARD_RESPONSE_HEADERS if (v := resp.headers.get(k))}
        out.update({k: v for k, v in resp.headers.items() if k.startswith("anthropic-")})
        return out

    async def handle(request: Request, path: str, *, rehydrate: bool) -> Response:
        request_id = uuid.uuid4().hex[:12]
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "request body is not valid JSON")
        if not isinstance(body, dict):
            return _error(400, "request body must be a JSON object")
        try:
            engine = engine_for(request)
        except ValueError as e:
            return _error(400, str(e))

        with lock:
            try:
                redactor = RequestRedactor(
                    engine.redactor, thinking, allow_binary=settings.allow_binary
                )
                result = redactor.redact(body)
                engine.guard.check(result.outgoing)
                engine.guard.check(result.passthrough, deep=False)
            except (Blocked, LeakDetected) as e:
                engine.save()
                audit.record(
                    settings.audit_path,
                    "blocked",
                    request_id=request_id,
                    vault=engine.vault.name,
                    path=path,
                    reason=str(e),
                )
                log.warning("blocked request %s: %s", request_id, e)
                return _error(400, f"request blocked, nothing was sent: {e}")
            except Exception:
                log.exception("redaction failed")
                audit.record(
                    settings.audit_path,
                    "blocked",
                    request_id=request_id,
                    vault=engine.vault.name,
                    path=path,
                    reason="internal error",
                )
                return _error(500, "redaction failed, nothing was sent", "api_error")
            engine.save()

        audit.record(
            settings.audit_path,
            "forwarded",
            request_id=request_id,
            vault=engine.vault.name,
            path=path,
            redacted=result.stats,
        )
        if dump_upstream:
            print(f"--- upstream {path} [{request_id}] ---", file=sys.stderr)
            print(json.dumps(result.body, indent=2, ensure_ascii=False), file=sys.stderr)

        headers = upstream_headers(request)
        r = engine.redactor
        if rehydrate and result.body.get("stream"):
            req = client.build_request(
                "POST", path, json=result.body, headers=headers, params=request.query_params
            )
            upstream = await client.send(req, stream=True)
            if upstream.status_code != 200:
                content = await upstream.aread()
                await upstream.aclose()
                return Response(
                    content,
                    upstream.status_code,
                    headers=response_headers(upstream),
                    media_type=upstream.headers.get("content-type"),
                )

            async def events():
                rewriter = SSERewriter(r, thinking)
                try:
                    async for chunk in upstream.aiter_bytes():
                        for out in rewriter.feed(chunk):
                            yield out
                    for out in rewriter.close():
                        yield out
                finally:
                    await upstream.aclose()

            return StreamingResponse(
                events(), media_type="text/event-stream", headers=response_headers(upstream)
            )

        upstream = await client.post(
            path, json=result.body, headers=headers, params=request.query_params
        )
        try:
            data = upstream.json()
        except ValueError:
            return Response(
                upstream.content,
                upstream.status_code,
                headers=response_headers(upstream),
                media_type=upstream.headers.get("content-type"),
            )
        if rehydrate and isinstance(data, dict):
            data = rehydrate_response(r, data, thinking)
        return JSONResponse(data, upstream.status_code, headers=response_headers(upstream))

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        return await handle(request, "/v1/messages", rehydrate=True)

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> Response:
        return await handle(request, "/v1/messages/count_tokens", rehydrate=False)

    @app.get("/v1/models")
    @app.get("/v1/models/{model_id}")
    async def models(request: Request, model_id: str | None = None) -> Response:
        path = "/v1/models" + (f"/{model_id}" if model_id else "")
        upstream = await client.get(
            path, headers=upstream_headers(request), params=dict(request.query_params)
        )
        return Response(
            upstream.content, upstream.status_code, media_type=upstream.headers.get("content-type")
        )

    @app.get("/bestie/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "vault": settings.default_vault,
            "api_key_configured": bool(settings.api_key),
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def unsupported(path: str) -> Response:
        return _error(
            404,
            f"/{path} is not supported by Bestie (only /v1/messages); nothing was sent",
            "not_found_error",
        )

    return app
