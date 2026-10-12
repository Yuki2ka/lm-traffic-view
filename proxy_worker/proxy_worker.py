"""
Standalone proxy worker process.
Run by proxy.py (management) as a subprocess.

Usage: python proxy_worker.py <port> <target>
Example: python proxy_worker.py 1235 http://127.0.0.1:1234
"""

import asyncio
import json
import sys
import time
from typing import Any

import httpx
from fastapi import Request
from fastapi.responses import Response, StreamingResponse
import uvicorn
from fastapi import FastAPI

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1235
TARGET = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:1234"
TARGET = TARGET.rstrip("/")
MGMT_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 19999

CAPTURE_RESPONSE_BYTES = 262144

app = FastAPI()
client = httpx.AsyncClient(timeout=None)

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def now_ms() -> int:
    return int(time.time() * 1000)

def safe_json_loads(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None

def truncate(s: str, n: int = 300) -> str:
    if s is None:
        return ""
    return s if len(s) <= n else s[:n] + f" … [{len(s)} chars]"

def summarize_chat_request(obj: Any) -> str:
    if not isinstance(obj, dict):
        return "raw request"
    parts = []
    model = obj.get("model")
    if model:
        parts.append(f"model={model}")
    if "stream" in obj:
        parts.append(f"stream={obj.get('stream')}")
    messages = obj.get("messages")
    if isinstance(messages, list):
        roles = []
        for m in messages:
            if isinstance(m, dict):
                role = m.get("role", "?")
                content = m.get("content")
                roles.append(f"{role}:{len(content)}c" if isinstance(content, str) else role)
        parts.append("messages=" + " > ".join(roles))
    tools = obj.get("tools")
    if isinstance(tools, list):
        names = []
        for t in tools:
            if isinstance(t, dict):
                fn = t.get("function") or {}
                if isinstance(fn, dict) and fn.get("name"):
                    names.append(fn["name"])
        if names:
            parts.append("tools=" + ", ".join(names))
    return " | ".join(parts) if parts else "json request"

def summarize_sse_json(obj: Any) -> str:
    if not isinstance(obj, dict):
        return "sse json"
    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        ch = choices[0]
        if isinstance(ch, dict):
            delta = ch.get("delta") or {}
            finish_reason = ch.get("finish_reason")
            bits = []
            if isinstance(delta, dict):
                if delta.get("role"):
                    bits.append(f"role={delta['role']}")
                content = delta.get("content")
                if content:
                    bits.append(f"content +{len(content)}c")
                reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                if reasoning:
                    bits.append(f"reasoning +{len(reasoning)}c")
                tool_calls = delta.get("tool_calls")
                if isinstance(tool_calls, list):
                    tc_bits = []
                    for tc in tool_calls:
                        if not isinstance(tc, dict):
                            continue
                        fn = tc.get("function") or {}
                        if isinstance(fn, dict):
                            name = fn.get("name")
                            args = fn.get("arguments")
                            tc_bits.append(f"{name}()" if name else f"args +{len(args)}c" if args else "")
                    tc_bits = [b for b in tc_bits if b]
                    if tc_bits:
                        bits.append("tool_call " + ", ".join(tc_bits))
            if finish_reason:
                bits.append(f"finish={finish_reason}")
            return " | ".join(bits) if bits else "choice delta"
    if obj.get("object"):
        return str(obj.get("object"))
    return "json"

def compact_for_ui(x: Any, max_string: int = 2000) -> Any:
    if isinstance(x, str):
        if len(x) > max_string:
            return {"__big_string__": True, "chars": len(x), "preview": x[:max_string]}
        return x
    if isinstance(x, list):
        return [compact_for_ui(v, max_string) for v in x]
    if isinstance(x, dict):
        return {k: compact_for_ui(v, max_string) for k, v in x.items()}
    return x


# ── forward events to management server ──
_event_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
_seq = 0

async def publish(event: dict):
    global _seq
    _seq += 1
    event["seq"] = _seq
    event["ts"] = now_ms()
    try:
        _event_queue.put_nowait(event)
    except asyncio.QueueFull:
        pass
    # fire-and-forget POST to management server
    try:
        await client.post(
            f"http://127.0.0.1:{MGMT_PORT}/api/event",
            json=event,
        )
    except Exception:
        pass


@app.on_event("startup")
async def start_event_drain():
    """Background task: keep event queue drained so it doesn't fill."""
    async def drain():
        while True:
            await asyncio.sleep(0.1)
            while not _event_queue.empty():
                try:
                    _event_queue.get_nowait()
                except Exception:
                    break
    asyncio.create_task(drain())


@app.get("/health")
async def health():
    return {"ok": True, "port": PORT, "target": TARGET}


@app.api_route(
    "/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)
async def proxy(path: str, request: Request):
    url = f"{TARGET}/{path}"
    if request.url.query:
        url += "?" + request.url.query

    body = await request.body()

    req_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS
    }

    parsed_body = safe_json_loads(body)
    await publish(
        {
            "dir": "agent → server",
            "kind": "request",
            "method": request.method,
            "path": "/" + path,
            "summary": summarize_chat_request(parsed_body)
            if parsed_body is not None
            else f"{len(body)} bytes",
            "json": compact_for_ui(parsed_body) if parsed_body is not None else None,
            "text": None
            if parsed_body is not None
            else body[:20000].decode("utf-8", errors="replace"),
        }
    )

    try:
        upstream_req = client.build_request(
            request.method, url, headers=req_headers, content=body,
        )
        upstream_resp = await client.send(upstream_req, stream=True)
    except Exception as e:
        await publish({"dir": "proxy", "kind": "error", "summary": repr(e)})
        return Response(str(e), status_code=502)

    resp_headers = {
        k: v for k, v in upstream_resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS
    }
    content_type = upstream_resp.headers.get("content-type", "")
    is_sse = "text/event-stream" in content_type.lower()

    async def stream_response():
        captured = bytearray()
        sse_buffer = ""

        try:
            async for chunk in upstream_resp.aiter_bytes():
                if len(captured) < CAPTURE_RESPONSE_BYTES:
                    remaining = CAPTURE_RESPONSE_BYTES - len(captured)
                    captured.extend(chunk[:remaining])

                if is_sse:
                    try:
                        sse_buffer += chunk.decode("utf-8", errors="replace")
                        while "\n\n" in sse_buffer:
                            raw_event, sse_buffer = sse_buffer.split("\n\n", 1)
                            await handle_sse_event(raw_event)
                    except Exception as e:
                        await publish({"dir": "proxy", "kind": "sse-parse-error", "summary": repr(e)})

                yield chunk

        finally:
            if is_sse and sse_buffer.strip():
                await handle_sse_event(sse_buffer)
            if not is_sse:
                parsed = safe_json_loads(bytes(captured))
                await publish(
                    {
                        "dir": "server → agent",
                        "kind": "response",
                        "status": upstream_resp.status_code,
                        "summary": summarize_sse_json(parsed)
                        if parsed is not None
                        else f"{len(captured)} captured bytes",
                        "json": compact_for_ui(parsed) if parsed is not None else None,
                        "text": None
                        if parsed is not None
                        else bytes(captured).decode("utf-8", errors="replace"),
                    }
                )
            await upstream_resp.aclose()

    return StreamingResponse(
        stream_response(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=content_type or None,
    )


async def handle_sse_event(raw_event: str):
    lines = raw_event.splitlines()
    data_lines = []
    for line in lines:
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if not data_lines:
        return
    data = "\n".join(data_lines)
    if data.strip() == "[DONE]":
        await publish({"dir": "server → agent", "kind": "sse", "summary": "[DONE]", "text": "[DONE]"})
        return
    try:
        obj = json.loads(data)
        await publish({"dir": "server → agent", "kind": "sse", "summary": summarize_sse_json(obj), "json": compact_for_ui(obj)})
    except Exception:
        await publish({"dir": "server → agent", "kind": "sse", "summary": truncate(data, 200), "text": truncate(data, 5000)})


if __name__ == "__main__":
    print(f"[proxy_worker] listening on 127.0.0.1:{PORT}, target={TARGET}, mgmt={MGMT_PORT}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
