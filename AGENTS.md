# AGENTS.md

Python (FastAPI) + one static HTML page with no build step. Goal and task list: `plan.md`. User docs: `README.md`.

## Files
| file | role |
|---|---|
| `app.py` | Management server on :19999. Serves `index.html`, WebSocket `/_ws`, `/api/config` (start/stop worker), `/api/scan` (probe known LLM ports and port+1), `/api/event` (ingest from workers), event `Hub` with history. Known-server list `SERVERS` lives here only. |
| `proxy_worker.py` | Subprocess. HTTP reverse proxy `listen_port → target`, streams responses through and parses SSE. |
| `sniffer_worker.py` | Subprocess. Passive scapy capture on a TCP port. TCP reorder (`Flow`) → HTTP/1.1 parser (`HttpStream`: content-length / chunked / until-close / SSE, resyncs mid-stream). Needs root/Admin (+ Npcap on Windows). Falls back to a Python filter if BPF can't compile (no libpcap). |
| `common.py` | Shared: summarizers, UI event builders (`request_event`, `response_event`, `sse_event`), `SseParser` (UTF-8-safe incremental), `EventSender` (thread, batched POST to `/api/event`, never blocks traffic). |
| `index.html` | The whole UI (vanilla JS). Startup modal (scan → mode cards) and log (groups, filter, lazy render, rAF batching). |
| `run.bat`, `run.sh` | Create `.venv`, install `requirements.txt` if imports fail, run `app.py`. |
| `dev/fake_llm.py` | Fake OpenAI-compatible server (SSE with content/tool_call/[DONE]) for testing without LM Studio. |

## Data flow
```
agent ─▶ proxy_worker :1235 ─▶ server :1234        (proxy modes)
agent ─▶ server :1234   ·· sniffer_worker taps lo   (sniff mode)
worker ──POST /api/event (list)──▶ app.py Hub ──WS /_ws──▶ browser
```
Event: `{dir: "agent → server"|"server → agent"|"proxy", kind: request|response|sse|error|info, summary, json?, text?, method?, path?, status?}`. Hub adds `seq` and `ts`. The UI groups consecutive events with the same `dir|kind|summary` (`+Nc` suffix stripped). Keep this summary format if you change summarizers.

Modes from the UI: `sniff` (listen == target port) and anything else = proxy (`redirect`, `passthrough`, `proxy`; these names are only labels).

WS reconnect: `/_ws?since=<seq>&boot=<id>`. The first message is `{type:"hello", reset}`, and `reset` means the server restarted, so the UI clears the log.

## Dev / test
```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python dev/fake_llm.py 1234 &
.venv/bin/python app.py          # MGMT_HOST=0.0.0.0 to expose, MGMT_PORT to move
curl -XPOST localhost:19999/api/config -H 'content-type: application/json' \
     -d '{"target":"http://127.0.0.1:1234","mode":"proxy","proxyPort":1235}'
curl -N localhost:1235/v1/chat/completions -d '{"stream":true,"messages":[]}' -H 'content-type: application/json'
# sniff test without root app: sudo -E .venv/bin/python sniffer_worker.py 1234
```
There are no unit tests. For headless UI checks, jsdom works (polyfill `window.fetch` in `beforeParse`, use `pretendToBeVisual`).

## Gotchas
- Workers get `MGMT_PORT` from env, not argv.
- The proxy drops `accept-encoding` upstream and `content-encoding` downstream, because httpx decodes the body.
- Errors and worker exits show up in the UI log as `proxy` events. The sniffer's permission error arrives after ~1 s.
- `pkill -f sniffer_worker.py` inside a bash `-c` that contains the same string kills your own shell.
