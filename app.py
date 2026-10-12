"""
Management server: web UI + WebSocket event hub + worker process control.

Run:  python app.py            (UI at http://127.0.0.1:19999/)
Env:  MGMT_PORT=19999  HISTORY_MAX=2000  WS_QUEUE_MAX=5000
"""

import asyncio
import os
import socket
import subprocess
import sys
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

HERE = Path(__file__).parent
MANAGEMENT_PORT = int(os.getenv("MGMT_PORT", "19999"))
HISTORY_MAX = int(os.getenv("HISTORY_MAX", "2000"))
WS_QUEUE_MAX = int(os.getenv("WS_QUEUE_MAX", "5000"))
UI_HTML_PATH = HERE / "index.html"
BOOT_ID = uuid.uuid4().hex[:8]

# Known local LLM servers: name, default port, probe endpoint, download page
SERVERS = [
    ("LM Studio",             1234,  "v1/models", "https://lmstudio.ai/download"),
    ("Ollama",                11434, "api/tags",  "https://ollama.com/download"),
    ("llama.cpp",             8080,  "v1/models", "https://github.com/ggml-org/llama.cpp/releases"),
    ("ik_llama.cpp",          8080,  "v1/models", "https://github.com/ikawrakow/ik_llama.cpp"),
    ("LocalAI",               8080,  "v1/models", "https://github.com/mudler/LocalAI/releases"),
    ("Jan",                   1337,  "v1/models", "https://github.com/janhq/jan/releases"),
    ("KoboldCpp",             5001,  "v1/models", "https://github.com/LostRuins/koboldcpp/releases"),
    ("Text Generation WebUI", 5000,  "v1/models", "https://github.com/oobabooga/text-generation-webui"),
    ("vLLM",                  8000,  "v1/models", "https://docs.vllm.ai/en/latest/getting_started/installation.html"),
]

# ── state ──
state = {"target": "", "listenPort": 0, "mode": "", "configured": False, "error": ""}
worker: subprocess.Popen | None = None


# ═══════════════════════ event hub ═══════════════════════

class Hub:
    def __init__(self):
        self.seq = 0
        self.history: deque = deque(maxlen=HISTORY_MAX)
        self.clients: set[asyncio.Queue] = set()

    def publish(self, event: dict):
        self.seq += 1
        event["seq"] = self.seq
        event.setdefault("ts", int(time.time() * 1000))
        self.history.append(event)
        for q in list(self.clients):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)

    def register(self, since: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=WS_QUEUE_MAX)
        for item in self.history:
            if item["seq"] > since and not q.full():
                q.put_nowait(item)
        self.clients.add(q)
        return q


hub = Hub()


def info(summary: str, kind: str = "info", text: str | None = None):
    hub.publish({"dir": "proxy", "kind": kind, "summary": summary, "text": text})


# ═══════════════════════ worker processes ═══════════════════════

def worker_alive() -> bool:
    return worker is not None and worker.poll() is None


def stop_worker():
    global worker
    if worker_alive():
        worker.terminate()
        try:
            worker.wait(timeout=3)
        except subprocess.TimeoutExpired:
            worker.kill()
    worker = None


def start_worker(script: str, *args):
    global worker
    stop_worker()
    env = {**os.environ, "MGMT_PORT": str(MANAGEMENT_PORT)}
    worker = subprocess.Popen([sys.executable, str(HERE / script), *map(str, args)], env=env, cwd=str(HERE))


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


async def check_port(port: int, timeout: float = 0.3) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
        w.close()
        return True
    except Exception:
        return False


async def watchdog():
    """Report unexpected worker exits to the UI."""
    seen = None
    while True:
        await asyncio.sleep(1)
        w = worker
        if w is not None and w.poll() is not None and seen is not w:
            seen = w
            info(f"Worker exited (code {w.returncode}). Click the mode badge to reconfigure.", "error")


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(watchdog())
    yield
    task.cancel()
    stop_worker()


app = FastAPI(lifespan=lifespan)


# ═══════════════════════ API ═══════════════════════

def config_view():
    return {**state, "proxyRunning": worker_alive()}


@app.get("/api/config")
async def get_config():
    return config_view()


@app.post("/api/config")
async def set_config(request: Request):
    body = await request.json()
    target = (body.get("target") or "").rstrip("/")
    mode = body.get("mode") or "proxy"
    listen = int(body.get("proxyPort") or 0)
    u = urlparse(target if "://" in target else "http://" + target)
    host, tport = u.hostname or "127.0.0.1", u.port or 80

    def fail(msg):
        state["error"] = msg
        return {**config_view(), "ok": False, "error": msg}

    if not target:
        return fail("target is required")
    stop_worker()
    if mode == "sniff":
        start_worker("sniffer_worker.py", tport, host)
        listen = tport
    else:
        if not listen:
            return fail("proxyPort is required")
        if listen == tport and host in ("127.0.0.1", "localhost"):
            return fail(f"Proxy port :{listen} equals server port – use sniff mode for same-port capture")
        if not port_free(listen):
            return fail(f"Port :{listen} is already in use (server or other app). Choose another port or sniff mode.")
        start_worker("proxy_worker.py", listen, f"http://{host}:{tport}")

    state.update(target=f"http://{host}:{tport}", listenPort=listen, mode=mode, configured=True, error="")
    # let the worker fail fast on import/bind/permission errors (scapy import is slow)
    for _ in range(20 if mode == "sniff" else 8):
        await asyncio.sleep(0.1)
        if not worker_alive():
            break
    if not worker_alive():
        return fail(f"Worker failed to start (exit code {worker.returncode if worker else '?'}) – see console / log")
    return {**config_view(), "ok": True}


@app.get("/api/scan")
async def scan_servers():
    """Probe default ports and port+1 (user may have moved the server) in parallel."""
    ports: dict[int, dict] = {}
    for name, port, ep, url in SERVERS:
        for p, parent in ((port, None), (port + 1, port)):
            if p in ports:
                if parent is None and name not in ports[p]["name"]:
                    ports[p]["name"] += " / " + name
                continue
            ports[p] = {"name": name, "port": p, "endpoint": ep, "url": url,
                        "nonStandard": parent is not None, "parentPort": parent}
    own = {MANAGEMENT_PORT}
    if worker_alive() and state["mode"] != "sniff":
        own.add(state["listenPort"])
    plist = [p for p in ports if p not in own]
    opened = await asyncio.gather(*(check_port(p) for p in plist))
    servers = [{**ports[p], "open": o} for p, o in zip(plist, opened)]
    return {"servers": servers, "managementPort": MANAGEMENT_PORT, "proxyPort": state["listenPort"]}


@app.post("/api/event")
async def ingest_event(request: Request):
    """Events from workers: a single dict or a list (batched)."""
    data = await request.json()
    for ev in data if isinstance(data, list) else [data]:
        if isinstance(ev, dict):
            hub.publish(ev)
    return {"ok": True}


# ═══════════════════════ UI ═══════════════════════

@app.get("/")
@app.get("/_ui")
async def ui():
    return HTMLResponse(UI_HTML_PATH.read_text(encoding="utf-8"))


@app.get("/_ui-mtime")
async def ui_mtime():
    return {"mtime": UI_HTML_PATH.stat().st_mtime}


@app.websocket("/_ws")
async def ws_endpoint(ws: WebSocket):
    """?since=<last seq seen>&boot=<boot id> – resume without duplicates after reconnect."""
    await ws.accept()
    since = int(ws.query_params.get("since") or 0)
    reset = ws.query_params.get("boot") != BOOT_ID
    if reset:
        since = 0
    await ws.send_json({"type": "hello", "boot": BOOT_ID, "reset": reset})
    q = hub.register(since)
    try:
        while True:
            await ws.send_json(await q.get())
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        hub.clients.discard(q)


if __name__ == "__main__":
    import uvicorn
    print(f"\n  LM Traffic View  →  http://127.0.0.1:{MANAGEMENT_PORT}/\n", flush=True)
    uvicorn.run(app, host=os.getenv("MGMT_HOST", "127.0.0.1"), port=MANAGEMENT_PORT, log_level="warning")
