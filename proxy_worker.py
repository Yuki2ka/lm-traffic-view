"""
HTTP reverse proxy worker. Started by app.py as a subprocess.

Usage: python proxy_worker.py <listen_port> <target>
Example: python proxy_worker.py 1235 http://127.0.0.1:1234
"""

import sys

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from common import (CAPTURE_BYTES, MGMT_PORT, EventSender, SseParser,
                    request_event, response_event)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1235
TARGET = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:1234").rstrip("/")

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    # ask upstream for identity encoding: we must read the body and forward it unchanged
    "accept-encoding",
}

app = FastAPI()
client = httpx.AsyncClient(timeout=None)
sender = EventSender(MGMT_PORT)
publish = sender.publish


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    url = f"{TARGET}/{path}"
    if request.url.query:
        url += "?" + request.url.query

    body = await request.body()
    req_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    publish(request_event(request.method, "/" + path, body))

    try:
        upstream_req = client.build_request(request.method, url, headers=req_headers, content=body)
        upstream_resp = await client.send(upstream_req, stream=True)
    except Exception as e:
        publish({"dir": "proxy", "kind": "error", "summary": f"upstream {TARGET} unreachable: {e!r}"})
        return Response(str(e), status_code=502)

    resp_headers = {k: v for k, v in upstream_resp.headers.items()
                    if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "content-encoding"}
    content_type = upstream_resp.headers.get("content-type", "")
    is_sse = "text/event-stream" in content_type.lower()

    async def stream_response():
        captured = bytearray()
        total = 0
        sse = SseParser(publish) if is_sse else None
        try:
            async for chunk in upstream_resp.aiter_bytes():
                total += len(chunk)
                if sse:
                    try:
                        sse.feed(chunk)
                    except Exception as e:
                        publish({"dir": "proxy", "kind": "sse-parse-error", "summary": repr(e)})
                elif len(captured) < CAPTURE_BYTES:
                    captured.extend(chunk[:CAPTURE_BYTES - len(captured)])
                yield chunk
        finally:
            if sse:
                sse.close()
            else:
                publish(response_event(upstream_resp.status_code, bytes(captured), total))
            await upstream_resp.aclose()

    return StreamingResponse(
        stream_response(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=content_type or None,
    )


if __name__ == "__main__":
    print(f"[proxy_worker] 127.0.0.1:{PORT} -> {TARGET}  (mgmt :{MGMT_PORT})", file=sys.stderr)
    publish({"dir": "proxy", "kind": "info", "summary": f"HTTP proxy 127.0.0.1:{PORT} → {TARGET}"})
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
