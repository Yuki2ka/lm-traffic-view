"""Shared code for workers: summarizers, UI event builders, SSE parser, event sender."""

import codecs
import json
import os
import queue
import threading
import time
from typing import Any, Callable, Optional

import httpx

MGMT_PORT = int(os.getenv("MGMT_PORT", "19999"))
CAPTURE_BYTES = int(os.getenv("CAPTURE_RESPONSE_BYTES", "262144"))

AGENT_TO_SERVER = "agent → server"
SERVER_TO_AGENT = "server → agent"


def now_ms() -> int:
    return int(time.time() * 1000)


def safe_json_loads(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


def truncate(s: Optional[str], n: int = 300) -> str:
    if s is None:
        return ""
    return s if len(s) <= n else s[:n] + f" … [{len(s)} chars]"


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


def summarize_chat_request(obj: Any) -> str:
    if not isinstance(obj, dict):
        return "raw request"
    parts = []
    if obj.get("model"):
        parts.append(f"model={obj['model']}")
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
            delta = ch.get("delta") or ch.get("message") or {}
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


# ── UI event builders (same shape for proxy and sniffer) ──

def request_event(method: str, path: str, body: bytes) -> dict:
    parsed = safe_json_loads(body) if body else None
    return {
        "dir": AGENT_TO_SERVER,
        "kind": "request",
        "method": method,
        "path": path,
        "summary": f"{method} {path} " + (summarize_chat_request(parsed) if parsed is not None else f"{len(body)} bytes"),
        "json": compact_for_ui(parsed) if parsed is not None else None,
        "text": None if parsed is not None else body[:20000].decode("utf-8", errors="replace"),
    }


def response_event(status: int, body: bytes, total_len: Optional[int] = None) -> dict:
    parsed = safe_json_loads(body) if body else None
    n = total_len if total_len is not None else len(body)
    return {
        "dir": SERVER_TO_AGENT,
        "kind": "response" if status < 400 else "error",
        "status": status,
        "summary": f"{status} " + (summarize_sse_json(parsed) if parsed is not None else f"{n} bytes"),
        "json": compact_for_ui(parsed) if parsed is not None else None,
        "text": None if parsed is not None else body[:20000].decode("utf-8", errors="replace"),
    }


def sse_event(raw_event: str) -> Optional[dict]:
    data_lines = [ln[5:].lstrip() for ln in raw_event.splitlines() if ln.startswith("data:")]
    if not data_lines:
        return None
    data = "\n".join(data_lines)
    if data.strip() == "[DONE]":
        return {"dir": SERVER_TO_AGENT, "kind": "sse", "summary": "[DONE]", "text": "[DONE]"}
    try:
        obj = json.loads(data)
        return {"dir": SERVER_TO_AGENT, "kind": "sse", "summary": summarize_sse_json(obj), "json": compact_for_ui(obj)}
    except Exception:
        return {"dir": SERVER_TO_AGENT, "kind": "sse", "summary": truncate(data, 200), "text": truncate(data, 5000)}


class SseParser:
    """Incremental SSE parser. Safe with UTF-8 split across chunks and with \\r\\n line endings."""

    def __init__(self, emit: Callable[[dict], None]):
        self.emit = emit
        self.dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.buf = ""

    def feed(self, data: bytes):
        self.buf += self.dec.decode(data)
        if "\r" in self.buf:
            self.buf = self.buf.replace("\r\n", "\n")
        while "\n\n" in self.buf:
            raw, self.buf = self.buf.split("\n\n", 1)
            ev = sse_event(raw)
            if ev:
                self.emit(ev)

    def close(self):
        self.buf += self.dec.decode(b"", final=True)
        if self.buf.strip():
            ev = sse_event(self.buf)
            if ev:
                self.emit(ev)
        self.buf = ""


class EventSender:
    """Non-blocking event publisher: queues events, a background thread POSTs them
    to the management server in batches. Never slows down the proxied stream."""

    def __init__(self, mgmt_port: int = MGMT_PORT):
        self.url = f"http://127.0.0.1:{mgmt_port}/api/event"
        self.q: "queue.Queue[dict]" = queue.Queue(maxsize=20000)
        threading.Thread(target=self._run, daemon=True).start()

    def publish(self, event: dict):
        event.setdefault("ts", now_ms())
        try:
            self.q.put_nowait(event)
        except queue.Full:
            pass  # UI too slow – drop rather than block traffic

    def _run(self):
        with httpx.Client(timeout=5.0) as client:
            while True:
                batch = [self.q.get()]
                try:
                    while len(batch) < 500:
                        batch.append(self.q.get_nowait())
                except queue.Empty:
                    pass
                try:
                    client.post(self.url, json=batch)
                except Exception:
                    pass  # management server down – drop

    def flush(self, timeout: float = 2.0):
        end = time.time() + timeout
        while not self.q.empty() and time.time() < end:
            time.sleep(0.05)
        time.sleep(0.1)
