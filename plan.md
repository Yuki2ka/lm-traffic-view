# Plan

Goal: debug agent tool calls by watching agent ⇄ local LLM server traffic live, preferably with zero config changes to the agent or the server.

## Done
- [x] HTTP proxy agent → server; stream of messages shown as a chat; collapse text to see only command/tool names
- [x] Fast with a big, fast stream (async batched event sender, one DOM flush per frame, lazy render of groups and JSON)
- [x] "Hide 0-byte" checkbox (css class `empty`, toggled without a redraw)
- [x] Live reload of the UI when `index.html` is edited (`/_ui-mtime`, polled every 2 s)
- [x] One install+run script that installs into a local `.venv` only when needed (`run.bat`, `run.sh`)
- [x] Detect running servers: modal with Name, Port, Endpoint, download link; working server preselected
- [x] Time shown as hh:mm:ss (24 h)
- [x] Port logic:
  - server on its standard port (e.g. 1234) → ① sniff on the same port or ② proxy on :1235 (agent moves to :1235)
  - server on a non-standard port (e.g. 1235) → proxy :1234 → :1235 (agent keeps its default)
- [x] Scan port+1 as well; manual port input
- [x] Bug: bind error 10048 on :1234 (UI moved to :19999; ports are checked before the proxy starts)
- [x] Bug: LM Studio on :1235 was not detected
- [x] Toolbar: New-on-top (on by default), Auto-scroll (off by default), clearer toggle states, reddish Clear
- [x] Fold sequential events of the same type (`content +3c`… → `content ×47 (1283 chars)`); tool calls with different names stay separate
- [x] Same in/out port without touching agent or server: passive sniff (scapy; Npcap on Windows, root on Linux)
- [x] Merged proxy_worker/ + sniffer_worker/ into one app, shared code in `common.py`

## Not done / possibilities
- [ ] Test sniff on Windows (Npcap loopback) and macOS (so far only Linux is tested)
- [ ] Transparent bridge (active interception on the same port: WinDivert/pydivert, iptables). Sniff already covers read-only needs
- [ ] Check that the server list is current; probe the real endpoint (now TCP connect only)
- [ ] Assemble a streamed reply into one message (full content plus tool-call arguments per response)
- [ ] Save/export a session (JSONL/HAR)
- [ ] Option to listen on 0.0.0.0 (agent in WSL/Docker)
- [ ] Run workers in-process instead of as subprocesses (drop the event HTTP hop)
