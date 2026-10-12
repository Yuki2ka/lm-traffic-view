"""
Passive LM Studio traffic sniffer.
Run by proxy.py (management) as a subprocess.

Usage: python sniffer_worker.py <port> <host>
Example: python sniffer_worker.py 1234 127.0.0.1

Captures TCP traffic on host:port without rebinding the port.
Agent and LM Studio both stay on 127.0.0.1:1234 unchanged.

Requires:
  pip install scapy httpx

OS notes:
  Windows: Install Npcap with "Loopback support" checked.
           Run this script as Administrator.
           Interface will auto-detect "Npcap Loopback Adapter".
  Linux:   Run as root, or: sudo setcap cap_net_raw=eip $(which python)
           Interface defaults to "lo", falls back to any.
  macOS:   Run as root (sudo). Interface defaults to "lo0".
"""

import asyncio
import json
import sys
import time
import threading
from collections import defaultdict
from typing import Any, Dict, Tuple

import httpx

# --- Scapy import (lazy, with friendly error) ---
try:
    from scapy.all import sniff, TCP, Raw, IP, IPv6, conf, get_if_list
    SCAPY_OK = True
except Exception as e:
    print(f"[sniffer] Scapy import failed: {e}", file=sys.stderr)
    print("[sniffer] pip install scapy", file=sys.stderr)
    sys.exit(1)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
MGMT_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 19999

MGMT_URL = f"http://127.0.0.1:{MGMT_PORT}/api/event"

client = httpx.Client(timeout=2.0)

# ── same summarizers as proxy_worker.py ──
def safe_json_loads(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None

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

def truncate(s: str, n: int = 300) -> str:
    if s is None:
        return ""
    return s if len(s) <= n else s[:n] + f" … [{len(s)} chars]"


def publish(event: dict):
    """POST event to management server, fire-and-forget."""
    try:
        client.post(MGMT_URL, json=event, timeout=0.5)
    except Exception:
        pass  # UI not running / mgmt down – ignore


# ── TCP stream reassembler ──

class Flow:
    """One TCP connection: client ↔ server (server_port == PORT)"""
    __slots__ = ("key", "c2s_buf", "s2c_buf",
                 "c2s_next_seq", "s2c_next_seq",
                 "c2s_pending", "s2c_pending",
                 "s2c_sse_left",
                 "req_header", "resp_header",
                 "last_seen")

    def __init__(self, key):
        self.key = key
        self.c2s_buf = bytearray()
        self.s2c_buf = bytearray()
        self.c2s_next_seq = None
        self.s2c_next_seq = None
        self.c2s_pending: Dict[int, bytes] = {}
        self.s2c_pending: Dict[int, bytes] = {}
        self.s2c_sse_left = ""
        self.req_header = None
        self.resp_header = None
        self.last_seen = time.time()

    def feed(self, payload: bytes, seq: int, to_server: bool):
        self.last_seen = time.time()
        if to_server:
            self._feed_dir(payload, seq, True)
            self._try_parse_requests()
        else:
            self._feed_dir(payload, seq, False)
            self._try_parse_responses()

    def _feed_dir(self, payload: bytes, seq: int, to_server: bool):
        if not payload:
            return
        if to_server:
            nxt = self.c2s_next_seq
            buf = self.c2s_buf
            pending = self.c2s_pending
        else:
            nxt = self.s2c_next_seq
            buf = self.s2c_buf
            pending = self.s2c_pending

        if nxt is None:
            nxt = seq
            buf.extend(payload)
            nxt = seq + len(payload)
        elif seq == nxt:
            buf.extend(payload)
            nxt += len(payload)
            # drain pending in-order
            while nxt in pending:
                p = pending.pop(nxt)
                buf.extend(p)
                nxt += len(p)
        elif seq > nxt:
            # out of order, stash
            pending[seq] = payload
            return
        else:  # seq < nxt, overlap / retransmit
            overlap = nxt - seq
            if overlap < len(payload):
                buf.extend(payload[overlap:])
                nxt = seq + len(payload)
            # else fully duplicate, drop
        if to_server:
            self.c2s_next_seq = nxt
        else:
            self.s2c_next_seq = nxt

    # ----- HTTP parsing -----
    def _try_parse_requests(self):
        buf = self.c2s_buf
        while True:
            if self.req_header is None:
                idx = buf.find(b"\r\n\r\n")
                if idx == -1:
                    return
                header_bytes = bytes(buf[:idx])
                try:
                    head_text = header_bytes.decode("latin-1")
                except Exception:
                    head_text = ""
                lines = head_text.split("\r\n")
                req_line = lines[0] if lines else ""
                parts = req_line.split()
                method = parts[0] if len(parts) > 0 else "?"
                path = parts[1] if len(parts) > 1 else "/"
                hdr = {}
                for ln in lines[1:]:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        hdr[k.strip().lower()] = v.strip()
                clen = int(hdr.get("content-length", "0") or "0")
                self.req_header = {
                    "method": method,
                    "path": path,
                    "headers": hdr,
                    "header_len": idx + 4,
                    "content_length": clen,
                }
            h = self.req_header
            total_needed = h["header_len"] + h["content_length"]
            if len(buf) < total_needed:
                return  # wait for body
            body = bytes(buf[h["header_len"]:total_needed])
            # emit
            parsed = safe_json_loads(body)
            publish({
                "dir": "agent → server",
                "kind": "request",
                "method": h["method"],
                "path": h["path"],
                "summary": summarize_chat_request(parsed) if parsed is not None else f"{len(body)} bytes",
                "json": compact_for_ui(parsed) if parsed is not None else None,
                "text": None if parsed is not None else body[:20000].decode("utf-8", errors="replace"),
            })
            # pop consumed
            del buf[:total_needed]
            self.req_header = None
            # loop, there may be pipelined requests

    def _try_parse_responses(self):
        buf = self.s2c_buf
        while True:
            if self.resp_header is None:
                idx = buf.find(b"\r\n\r\n")
                if idx == -1:
                    return
                header_bytes = bytes(buf[:idx])
                try:
                    head_text = header_bytes.decode("latin-1")
                except Exception:
                    head_text = ""
                lines = head_text.split("\r\n")
                hdr = {}
                for ln in lines[1:]:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        hdr[k.strip().lower()] = v.strip()
                is_sse = "text/event-stream" in hdr.get("content-type", "")
                clen = hdr.get("content-length")
                try:
                    clen = int(clen) if clen else None
                except Exception:
                    clen = None
                self.resp_header = {
                    "headers": hdr,
                    "header_len": idx + 4,
                    "content_length": clen,
                    "is_sse": is_sse,
                    "status": lines[0] if lines else "",
                }
                # strip header from buf
                del buf[:idx+4]
                self.s2c_sse_left = ""
                if is_sse:
                    # SSE: stream-parse as data comes in, don't wait
                    pass
                continue

            h = self.resp_header
            if h["is_sse"]:
                # Parse SSE events incrementally
                if not buf:
                    return
                try:
                    chunk_text = buf.decode("utf-8", errors="replace")
                except Exception:
                    chunk_text = ""
                buf.clear()
                data = self.s2c_sse_left + chunk_text
                # SSE events are separated by \n\n
                while "\n\n" in data:
                    raw_event, data = data.split("\n\n", 1)
                    self._handle_sse_event(raw_event)
                self.s2c_sse_left = data
                return  # wait for more
            else:
                # ordinary response
                clen = h["content_length"]
                if clen is None:
                    # no content-length – can't know end, wait a bit or give up
                    # For LM Studio non-streaming, Content-Length is present.
                    # Give up after 1 MB to avoid infinite buffer.
                    if len(buf) > 1_000_000:
                        clen = len(buf)
                    else:
                        return
                if len(buf) < clen:
                    return
                body = bytes(buf[:clen])
                parsed = safe_json_loads(body)
                publish({
                    "dir": "server → agent",
                    "kind": "response",
                    "status": 200,
                    "summary": summarize_sse_json(parsed) if parsed is not None else f"{len(body)} bytes",
                    "json": compact_for_ui(parsed) if parsed is not None else None,
                    "text": None if parsed is not None else body.decode("utf-8", errors="replace")[:20000],
                })
                del buf[:clen]
                self.resp_header = None
                continue

    def _handle_sse_event(self, raw_event: str):
        lines = raw_event.splitlines()
        data_lines = []
        for line in lines:
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        if not data_lines:
            return
        data = "\n".join(data_lines)
        if data.strip() == "[DONE]":
            publish({"dir": "server → agent", "kind": "sse", "summary": "[DONE]", "text": "[DONE]"})
            return
        try:
            obj = json.loads(data)
            publish({"dir": "server → agent", "kind": "sse",
                     "summary": summarize_sse_json(obj),
                     "json": compact_for_ui(obj)})
        except Exception:
            publish({"dir": "server → agent", "kind": "sse",
                     "summary": truncate(data, 200),
                     "text": truncate(data, 5000)})


flows: Dict[Tuple, Flow] = {}

def get_flow(client_ip, client_port, server_ip, server_port):
    key = (client_ip, client_port, server_ip, server_port)
    f = flows.get(key)
    if f is None:
        f = Flow(key)
        flows[key] = f
    return f

def flow_gc():
    while True:
        time.sleep(30)
        now = time.time()
        dead = [k for k, f in flows.items() if now - f.last_seen > 120]
        for k in dead:
            flows.pop(k, None)

# ── Scapy packet callback ──

def packet_cb(pkt):
    if not pkt.haslayer(TCP):
        return
    tcp = pkt[TCP]
    if tcp.sport != PORT and tcp.dport != PORT:
        return
    payload = bytes(tcp.payload)
    if not payload and not tcp.flags.S and not tcp.flags.F:
        return  # pure ACK, ignore

    ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
    if ip_layer is None:
        return
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    to_server = (tcp.dport == PORT)
    if to_server:
        client_ip, client_port = src_ip, tcp.sport
        server_ip, server_port = dst_ip, tcp.dport
    else:
        client_ip, client_port = dst_ip, tcp.dport
        server_ip, server_port = src_ip, tcp.sport

    flow = get_flow(client_ip, client_port, server_ip, server_port)
    flow.feed(payload, int(tcp.seq), to_server)

    # RST/FIN: close flow after a short delay
    if tcp.flags.R or tcp.flags.F:
        # flush any remaining SSE buffer
        if flow.s2c_sse_left.strip():
            flow._handle_sse_event(flow.s2c_sse_left)
            flow.s2c_sse_left = ""


def pick_iface():
    """Pick a loopback-capable interface for Windows/Linux/macOS."""
    ifs = get_if_list()
    # Windows Npcap Loopback
    for n in ifs:
        low = n.lower()
        if "loopback" in low or "npcap" in low and "loopback" in low:
            return n
    # Linux / macOS
    for cand in ("lo", "lo0"):
        if cand in ifs:
            return cand
    # fall back: let scapy choose
    return None

def main():
    iface = pick_iface()
    print(f"[sniffer] listening for TCP port {PORT} on {HOST}, iface={iface or 'default'}", file=sys.stderr)
    print(f"[sniffer] mgmt -> {MGMT_URL}", file=sys.stderr)

    publish({
        "dir": "proxy",
        "kind": "info",
        "summary": f"Sniffer started on {HOST}:{PORT}  iface={iface or 'auto'}",
        "text": f"Scapy sniffing TCP port {PORT}.\n"
                f"Windows: requires Npcap with 'Loopback support' + Admin.\n"
                f"Linux/macOS: requires root / CAP_NET_RAW.\n"
                f"If you see no events, check interface / permissions."
    })

    threading.Thread(target=flow_gc, daemon=True).start()

    bpf = f"tcp port {PORT}"
    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=packet_cb,
            store=False,
        )
    except PermissionError:
        print("[sniffer] Permission denied – run as Administrator/root, or grant CAP_NET_RAW", file=sys.stderr)
        publish({"dir": "proxy", "kind": "error", "summary": "Sniffer permission denied – run as Administrator / root"})
        sys.exit(2)
    except Exception as e:
        print(f"[sniffer] sniff error: {e}", file=sys.stderr)
        publish({"dir": "proxy", "kind": "error", "summary": f"Sniff error: {e}"})
        sys.exit(1)

if __name__ == "__main__":
    main()
