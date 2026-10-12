import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response, StreamingResponse

MANAGEMENT_PORT = int(os.getenv("MGMT_PORT", "19999"))
HISTORY_MAX = int(os.getenv("HISTORY_MAX", "2000"))
WS_QUEUE_MAX = int(os.getenv("WS_QUEUE_MAX", "1000"))
CAPTURE_RESPONSE_BYTES = int(os.getenv("CAPTURE_RESPONSE_BYTES", "262144"))

app = FastAPI()

client = httpx.AsyncClient(timeout=None)

UI_HTML_PATH = Path(__file__).parent / "index.html"

# ── proxy state ──
TARGET = ""
PROXY_PORT = 0
PROXY_MODE = ""
CONFIGURED = False
worker_process = None  # subprocess.Popen - can be proxy_worker or sniffer_worker

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

# ── known servers ──
SERVERS = [
    {"name": "Jan.ai",                "port": 1337,  "endpoint": "v1/models"},
    {"name": "LM Studio",             "port": 1234,  "endpoint": "v1/chat/completions"},
    {"name": "llama.cpp",             "port": 8080,  "endpoint": "v1/chat/completions"},
    {"name": "ik_llama.cpp",          "port": 8080,  "endpoint": "v1/chat/completions"},
    {"name": "KoboldCPP",             "port": 5001,  "endpoint": "api/v1/generate"},
    {"name": "Ollama",                "port": 11434, "endpoint": "api/tags"},
    {"name": "vLLM",                  "port": 8000,  "endpoint": "v1/chat/completions"},
    {"name": "LocalAI",               "port": 8080,  "endpoint": "v1/models"},
    {"name": "Text Generation WebUI", "port": 7860,  "endpoint": "v1/chat/completions"},
]


def check_port_open(port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


async def async_check_port(port: int, timeout: float = 0.25) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
        return False


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


class Hub:
    def __init__(self):
        self.seq = 0
        self.history = deque(maxlen=HISTORY_MAX)
        self.clients: set[asyncio.Queue] = set()
        self.lock = asyncio.Lock()

    async def publish(self, event: dict):
        async with self.lock:
            self.seq += 1
            event["seq"] = self.seq
            event["ts"] = now_ms()
            self.history.append(event)
            dead = []
            for q in self.clients:
                try:
                    if q.full():
                        try:
                            q.get_nowait()
                        except Exception:
                            pass
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
            for q in dead:
                self.clients.discard(q)

    async def register(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=WS_QUEUE_MAX)
        async with self.lock:
            self.clients.add(q)
            for item in self.history:
                if not q.full():
                    q.put_nowait(item)
        return q

    async def unregister(self, q: asyncio.Queue):
        async with self.lock:
            self.clients.discard(q)


hub = Hub()


# ═══════════════════════════════════════════════════════════
#  WORKER SUBPROCESS MANAGEMENT
# ═══════════════════════════════════════════════════════════

def start_proxy_process(port: int, target: str):
    """Start the actual HTTP proxy as a subprocess on the given port."""
    global worker_process

    # kill old worker if running
    stop_worker_process()

    env = os.environ.copy()
    env["PROXY_PORT"] = str(port)
    env["PROXY_TARGET"] = target
    env["MGMT_PORT"] = str(MANAGEMENT_PORT)

    worker_process = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / "proxy_worker.py"), str(port), target],
        env=env,
    )


def start_sniffer_process(target_port: int, target_host: str = "127.0.0.1"):
    """Start the passive packet sniffer (scapy) as a subprocess.
    This captures traffic on target_host:target_port without rebinding the port,
    so agent and LM Studio can both stay on 127.0.0.1:1234 unchanged.
    """
    global worker_process

    stop_worker_process()

    env = os.environ.copy()
    env["SNIFF_PORT"] = str(target_port)
    env["SNIFF_HOST"] = target_host
    env["MGMT_PORT"] = str(MANAGEMENT_PORT)

    worker_process = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / "sniffer_worker.py"), str(target_port), target_host],
        env=env,
    )


def stop_worker_process():
    global worker_process
    if worker_process and worker_process.poll() is None:
        worker_process.terminate()
        try:
            worker_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            worker_process.kill()
    worker_process = None


# ═══════════════════════════════════════════════════════════
#  MANAGEMENT API
# ═══════════════════════════════════════════════════════════

@app.get("/api/config")
async def get_config():
    return {
        "listenPort": PROXY_PORT or None,
        "target": TARGET,
        "mode": PROXY_MODE,
        "configured": CONFIGURED,
        "proxyRunning": worker_process is not None and worker_process.poll() is None,
    }


@app.post("/api/config")
async def set_config(request: Request):
    global TARGET, PROXY_MODE, PROXY_PORT, CONFIGURED
    body = await request.json()

    new_target = body.get("target", "").rstrip("/")
    new_mode = body.get("mode", "")
    new_port = body.get("proxyPort")

    if new_target:
        TARGET = new_target
    if new_mode:
        PROXY_MODE = new_mode
    if new_port:
        PROXY_PORT = int(new_port)

    CONFIGURED = True

    # (re)start the worker subprocess
    if TARGET and PROXY_PORT:
        # parse target host/port
        # TARGET is like http://127.0.0.1:1234
        target_host = "127.0.0.1"
        target_port = PROXY_PORT
        if "://" in TARGET:
            hostport = TARGET.split("://", 1)[1]
        else:
            hostport = TARGET
        if ":" in hostport.split("/")[0]:
            hp = hostport.split("/")[0]
            target_host, port_s = hp.rsplit(":", 1)
            try:
                target_port = int(port_s)
            except ValueError:
                pass

        if PROXY_MODE == "sniff":
            # Passive tap – no port rebinding. Agent and server stay on the same address.
            start_sniffer_process(target_port, target_host)
            await hub.publish({
                "dir": "proxy",
                "kind": "info",
                "summary": f"Sniffer started on {target_host}:{target_port} – zero-config, read-only",
                "text": "Agent and LM Studio both stay on the same port. Traffic is passively captured via Scapy/Npcap.\nIf you see no traffic: install Npcap with 'loopback support' on Windows, or run as root on Linux/macOS."
            })
        else:
            # Classic HTTP reverse proxy
            start_proxy_process(PROXY_PORT, TARGET)

    return {
        "listenPort": PROXY_PORT,
        "target": TARGET,
        "mode": PROXY_MODE,
        "configured": CONFIGURED,
        "proxyRunning": worker_process is not None and worker_process.poll() is None,
        "ok": True,
    }


@app.get("/api/scan")
async def scan_servers():
    """Scan default ports + port+1, all in parallel. Excludes own ports."""
    ports_to_scan = {}
    for s in SERVERS:
        p = s["port"]
        if p not in ports_to_scan:
            ports_to_scan[p] = {"name": s["name"], "endpoint": s["endpoint"], "parentPort": None}
        p1 = s["port"] + 1
        if p1 not in ports_to_scan:
            ports_to_scan[p1] = {"name": s["name"], "endpoint": s["endpoint"], "parentPort": s["port"]}

    # exclude our own ports
    own_ports = {MANAGEMENT_PORT}
    if PROXY_PORT and PROXY_MODE != "sniff":
        own_ports.add(PROXY_PORT)

    port_list = [p for p in ports_to_scan if p not in own_ports]
    checks = await asyncio.gather(*(async_check_port(p) for p in port_list))

    results = []
    for port, is_open in zip(port_list, checks):
        info = ports_to_scan[port]
        results.append({
            "name": info["name"],
            "port": port,
            "endpoint": info["endpoint"],
            "open": is_open,
            "nonStandard": info["parentPort"] is not None,
            "parentPort": info["parentPort"],
        })

    return {"servers": results, "managementPort": MANAGEMENT_PORT, "proxyPort": PROXY_PORT}


# ═══════════════════════════════════════════════════════════
#  UI
# ═══════════════════════════════════════════════════════════

@app.get("/")
async def ui_root():
    return HTMLResponse(UI_HTML_PATH.read_text(encoding="utf-8"))

@app.get("/_ui")
async def ui():
    return HTMLResponse(UI_HTML_PATH.read_text(encoding="utf-8"))

@app.get("/_ui-mtime")
async def ui_mtime():
    return {"mtime": UI_HTML_PATH.stat().st_mtime}


# ═══════════════════════════════════════════════════════════
#  EVENT INGEST (from proxy/sniffer worker subprocess)
# ═══════════════════════════════════════════════════════════

@app.post("/api/event")
async def ingest_event(request: Request):
    """Receive event from proxy_worker / sniffer_worker and broadcast to all UI clients."""
    event = await request.json()
    await hub.publish(event)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════
#  WEBSOCKET (event stream to browsers)
# ═══════════════════════════════════════════════════════════

@app.websocket("/_ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    q = await hub.register()
    try:
        while True:
            event = await q.get()
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await hub.unregister(q)