# lm-traffic-view

See what your AI agent sends to a local LLM server (LM Studio, Ollama, llama.cpp…) and what the server answers: requests, streamed tokens, tool calls. Shown live in the browser.

## Start

- Windows: `run.bat` (to use sniff mode, run it as Administrator and install [Npcap](https://npcap.com/#download) with "Support loopback traffic")
- Linux/macOS: `./run.sh` (to use sniff mode: `sudo ./run.sh`)

The first run creates `.venv` and installs the dependencies. Then open http://127.0.0.1:19999/

## Use

Example: your agent talks to LM Studio at `http://127.0.0.1:1234`.

1. Start LM Studio's server, then start this tool. It finds LM Studio on :1234.
2. Choose a mode:
   - **Sniff**: change nothing. The agent and LM Studio both stay on :1234 and the tool only reads the traffic. Needs Admin/root.
   - **HTTP proxy :1235**: point the agent to `http://127.0.0.1:1235`. No admin needed.
   - If you moved LM Studio to :1235 yourself, the tool listens on :1234 instead and the agent needs no changes.
3. Run your agent. Each request and its streamed reply show up as folded groups. For example, `content ×47` is 47 token chunks. Tool calls show up as `tool_call read_file()`. Click a group to open it. Use the filter box to search.

Click the mode badge in the toolbar to switch server or mode.
