"""Fake OpenAI-compatible server for testing. Usage: python dev/fake_llm.py [port=1234]"""
import asyncio, json, sys
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn
app = FastAPI()
@app.get("/v1/models")
async def models(): return {"object":"list","data":[{"id":"qwen"}]}
@app.post("/v1/chat/completions")
async def chat(req: Request):
    body = await req.json()
    if not body.get("stream"):
        return JSONResponse({"object":"chat.completion","choices":[{"message":{"role":"assistant","content":"Привет мир"},"finish_reason":"stop"}]})
    async def gen():
        yield f"data: {json.dumps({'choices':[{'delta':{'role':'assistant'}}]})}\n\n"
        for w in ["Прив", "ет, ", "мир", "!"]:
            yield f"data: {json.dumps({'choices':[{'delta':{'content':w}}]}, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.02)
        yield f"data: {json.dumps({'choices':[{'delta':{'tool_calls':[{'function':{'name':'read_file','arguments':''}}]}}]})}\n\n"
        yield f"data: {json.dumps({'choices':[{'delta':{},'finish_reason':'tool_calls'}]})}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")
uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 1234, log_level="warning")
