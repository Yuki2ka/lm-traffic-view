"""
Passive traffic sniffer worker. Started by app.py as a subprocess.

Usage: python sniffer_worker.py <port> [host]
Example: python sniffer_worker.py 1234 127.0.0.1

Captures TCP traffic on <port> without binding it, so agent and server
both stay on 127.0.0.1:1234 unchanged. Read-only.

Requires scapy and capture rights:
  Windows: Npcap with "Support loopback traffic" + run as Administrator.
  Linux:   root, or: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
  macOS:   root.
"""

import re
import sys
import threading
import time
from typing import Dict, Tuple

from common import (CAPTURE_BYTES, MGMT_PORT, EventSender, SseParser,
                    request_event, response_event)

try:
    from scapy.all import IP, TCP, IPv6, Raw, get_if_list, sniff
except Exception as e:
    print(f"[sniffer] scapy import failed: {e}\n[sniffer] pip install scapy", file=sys.stderr)
    EventSender(MGMT_PORT).publish({"dir": "proxy", "kind": "error", "summary": f"Sniffer: scapy import failed: {e}"})
    time.sleep(1)
    sys.exit(1)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

sender = EventSender(MGMT_PORT)
publish = sender.publish

REQ_START = re.compile(rb"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD) \S+ HTTP/1\.[01]\r\n")
RESP_START = re.compile(rb"HTTP/1\.[01] \d{3}")
MAX_HEAD = 64 * 1024


class HttpStream:
    """Incremental HTTP/1.x parser for one direction of a TCP connection.
    Handles Content-Length, chunked encoding, read-until-close and SSE streaming.
    Resyncs if capture started in the middle of a connection."""

    def __init__(self, is_request: bool):
        self.is_request = is_request
        self.buf = bytearray()
        self._reset()

    def _reset(self):
        self.head = None          # dict once headers parsed
        self.mode = None          # "len" | "chunked" | "eof"
        self.remaining = 0
        self.chunk_state = "size"
        self.body = bytearray()
        self.total = 0
        self.sse = None

    # ── input ──
    def feed(self, data: bytes):
        self.buf.extend(data)
        while self._step():
            pass

    def close(self):
        if self.head is not None and (self.mode == "eof" or self.sse):
            self._finish()

    # ── state machine ──
    def _step(self) -> bool:
        if self.head is None:
            return self._parse_head()
        if self.mode == "len":
            n = min(self.remaining, len(self.buf))
            if n:
                self._body(bytes(self.buf[:n]))
                del self.buf[:n]
                self.remaining -= n
            if self.remaining == 0:
                self._finish()
                return True
            return False
        if self.mode == "eof":
            if self.buf:
                self._body(bytes(self.buf))
                self.buf.clear()
            return False
        # chunked
        if self.chunk_state == "size":
            i = self.buf.find(b"\r\n")
            if i == -1:
                return False
            try:
                size = int(bytes(self.buf[:i]).split(b";")[0].strip() or b"0", 16)
            except ValueError:
                size = 0
            del self.buf[:i + 2]
            if size == 0:
                self.chunk_state = "trailer"
            else:
                self.remaining, self.chunk_state = size, "data"
            return True
        if self.chunk_state == "data":
            n = min(self.remaining, len(self.buf))
            if n == 0:
                return False
            self._body(bytes(self.buf[:n]))
            del self.buf[:n]
            self.remaining -= n
            if self.remaining == 0:
                self.chunk_state = "crlf"
            return True
        if self.chunk_state == "crlf":
            if len(self.buf) < 2:
                return False
            del self.buf[:2]
            self.chunk_state = "size"
            return True
        if self.chunk_state == "trailer":
            if self.buf.startswith(b"\r\n"):
                del self.buf[:2]
            else:
                i = self.buf.find(b"\r\n\r\n")
                if i == -1:
                    return False
                del self.buf[:i + 4]
            self._finish()
            return True
        return False

    def _parse_head(self) -> bool:
        m = (REQ_START if self.is_request else RESP_START).search(self.buf)
        if not m:
            if len(self.buf) > 64:
                del self.buf[:-64]  # garbage (capture started mid-stream) – drop
            return False
        if m.start():
            del self.buf[:m.start()]
        i = self.buf.find(b"\r\n\r\n")
        if i == -1:
            if len(self.buf) > MAX_HEAD:
                del self.buf[:1]
                return True
            return False
        lines = bytes(self.buf[:i]).decode("latin-1").split("\r\n")
        del self.buf[:i + 4]
        hdr = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        first = lines[0].split()
        head = {"headers": hdr}
        if self.is_request:
            head["method"], head["path"] = first[0], first[1] if len(first) > 1 else "/"
        else:
            try:
                head["status"] = int(first[1])
            except (IndexError, ValueError):
                head["status"] = 0
        self.head = head

        te = hdr.get("transfer-encoding", "").lower()
        clen = hdr.get("content-length")
        status = head.get("status", 200)
        if "chunked" in te:
            self.mode = "chunked"
        elif clen is not None and clen.isdigit():
            self.mode, self.remaining = "len", int(clen)
        elif self.is_request or status in (204, 304) or 100 <= status < 200:
            self.mode, self.remaining = "len", 0
        else:
            self.mode = "eof"
        if not self.is_request and "text/event-stream" in hdr.get("content-type", "").lower():
            self.sse = SseParser(publish)
        return True

    def _body(self, data: bytes):
        self.total += len(data)
        if self.sse:
            self.sse.feed(data)
        elif len(self.body) < CAPTURE_BYTES:
            self.body.extend(data[:CAPTURE_BYTES - len(self.body)])

    def _finish(self):
        h = self.head
        if self.sse:
            self.sse.close()
        elif self.is_request:
            publish(request_event(h["method"], h["path"], bytes(self.body)))
        else:
            publish(response_event(h["status"], bytes(self.body), self.total))
        self._reset()


class Flow:
    """One TCP connection; reorders segments by seq for each direction."""

    def __init__(self):
        self.streams = {True: HttpStream(True), False: HttpStream(False)}
        self.next_seq: Dict[bool, int] = {}
        self.pending: Dict[bool, Dict[int, bytes]] = {True: {}, False: {}}
        self.last_seen = time.time()

    def feed(self, payload: bytes, seq: int, to_server: bool):
        self.last_seen = time.time()
        nxt = self.next_seq.get(to_server)
        pending = self.pending[to_server]
        out = bytearray()
        if nxt is None or seq == nxt:
            out += payload
            nxt = seq + len(payload)
            while nxt in pending:
                p = pending.pop(nxt)
                out += p
                nxt += len(p)
        elif seq > nxt:
            if len(pending) < 10000:
                pending[seq] = payload  # out of order – stash
            return
        else:  # retransmit / overlap
            overlap = nxt - seq
            if overlap >= len(payload):
                return
            out += payload[overlap:]
            nxt = seq + len(payload)
        self.next_seq[to_server] = nxt
        self.streams[to_server].feed(bytes(out))

    def close(self):
        for s in self.streams.values():
            s.close()


flows: Dict[Tuple, Flow] = {}
flows_lock = threading.Lock()


def flow_gc():
    while True:
        time.sleep(30)
        now = time.time()
        with flows_lock:
            for k in [k for k, f in flows.items() if now - f.last_seen > 300]:
                flows.pop(k).close()


def packet_cb(pkt):
    if not pkt.haslayer(TCP):
        return
    tcp = pkt[TCP]
    if PORT not in (tcp.sport, tcp.dport):
        return
    ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
    if ip is None:
        return
    to_server = tcp.dport == PORT
    key = (ip.src, tcp.sport, ip.dst, tcp.dport) if to_server else (ip.dst, tcp.dport, ip.src, tcp.sport)
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""  # Raw excludes ethernet padding
    flags = int(tcp.flags)
    with flows_lock:
        flow = flows.get(key)
        if flow is None:
            if not payload:
                return
            flow = flows[key] = Flow()
        if payload:
            flow.feed(payload, int(tcp.seq), to_server)
        if flags & 0x04:  # RST
            flow.close()
            flows.pop(key, None)
        elif flags & 0x01:  # FIN: this direction is done
            flow.streams[to_server].close()


def pick_iface():
    """Loopback interface for Windows (Npcap) / Linux / macOS, or None = scapy default."""
    try:
        ifs = get_if_list()
    except Exception:
        return None
    for cand in ("lo", "lo0"):
        if cand in ifs:
            return cand
    for n in ifs:
        if "loopback" in n.lower():
            return n
    return None


def main():
    iface = pick_iface()
    print(f"[sniffer] tcp port {PORT} on iface={iface or 'default'}  (mgmt :{MGMT_PORT})", file=sys.stderr)
    publish({
        "dir": "proxy", "kind": "info",
        "summary": f"Sniffer on {HOST}:{PORT} iface={iface or 'auto'} – read-only",
        "text": "Agent and server stay on the same port. Nothing to reconfigure.\n"
                "No events? Windows: Npcap with loopback support + run as Administrator. "
                "Linux/macOS: run as root (or setcap cap_net_raw).",
    })
    threading.Thread(target=flow_gc, daemon=True).start()

    kw = dict(iface=iface, prn=packet_cb, store=False)
    try:
        try:
            sniff(filter=f"tcp port {PORT}", **kw)
        except PermissionError:
            raise
        except Exception as e:  # BPF compile may fail without libpcap/tcpdump – filter in python
            print(f"[sniffer] BPF filter failed ({e}), using python filter", file=sys.stderr)
            sniff(lfilter=lambda p: p.haslayer(TCP) and PORT in (p[TCP].sport, p[TCP].dport), **kw)
    except PermissionError:
        msg = "Sniffer: permission denied – run as Administrator / root"
        print("[sniffer] " + msg, file=sys.stderr)
        publish({"dir": "proxy", "kind": "error", "summary": msg})
        sender.flush()
        sys.exit(2)
    except Exception as e:
        print(f"[sniffer] sniff error: {e}", file=sys.stderr)
        publish({"dir": "proxy", "kind": "error", "summary": f"Sniffer error: {e}",
                 "text": "Windows: install Npcap (https://npcap.com) with 'Support loopback traffic'."})
        sender.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
