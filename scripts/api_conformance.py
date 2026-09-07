#!/usr/bin/env python3
# scripts/api_conformance.py — 8.2 真实 SDK 对照（openai==3.5.0 anthropic==1.1.0）。
# 用原仓 .venv python 运行：/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/api_conformance.py
# 流程：cargo build → mock 上游（:0 随机端口）→ veil 二进制（固定 127.0.0.1:8877，
# 必填 env 用 dummy 值，LLM_UPSTREAM 指 mock）→ openai/anthropic 官方 SDK 经网关
# 消费三协议流式/非流式/tool call/阻断，断言 SDK 可解析且内容正确。
# 阻断触发说明：网关流式阻断由审计 hold 超限 fail-closed 触发（AUDIT_HOLD_MAX_BYTES=16
# 极小值 + 危险 tool args），阻断相以 AUDIT_MODE=block 运行；responses 协议无 tool
# 输出数组可供 hold 捕获，阻断相取空流截断合成 response.failed 路径。

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPENAI_PIN = "3.5.0"
ANTHROPIC_PIN = "1.1.0"

VEIL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEIL_BIN = os.path.join(VEIL_ROOT, "target", "debug", "veil")
GATEWAY = "http://127.0.0.1:8877"

CHAT = "chatcmpl-veil-1"


def chat_chunk(content=None, tool_delta=None, finish=None):
    delta = {}
    if content is not None:
        delta.update({"role": "assistant", "content": content})
    if tool_delta is not None:
        delta["tool_calls"] = [tool_delta]
    choice = {"index": 0, "delta": delta}
    if finish is not None:
        choice["finish_reason"] = finish
    return {"id": CHAT, "object": "chat.completion.chunk", "created": 1,
            "model": "m", "choices": [choice]}


def sse_data(payload):
    if isinstance(payload, dict):
        payload = json.dumps(payload, ensure_ascii=False)
    return ("data: " + payload + "\n\n").encode("utf-8")


def chat_stream_normal():
    return (sse_data(chat_chunk(content="hello ")) + sse_data(chat_chunk(content="veil"))
            + sse_data(chat_chunk(finish="stop")) + b"data: [DONE]\n\n")


def chat_tool_deltas(name, args, dangerous=False):
    if dangerous:
        args = '{"command":"rm -rf / --no-preserve-root /tmp/veil-danger"}'
    elif not args:
        args = '{"city":"Paris"}'
    half = len(args) // 2
    frames = [
        chat_chunk(tool_delta={"index": 0, "id": "call_1", "type": "function",
                               "function": {"name": name, "arguments": args[:half]}}),
        chat_chunk(tool_delta={"index": 0, "function": {"arguments": args[half:]}}),
        chat_chunk(finish="tool_calls"),
    ]
    return b"".join(sse_data(f) for f in frames) + b"data: [DONE]\n\n"


def chat_completion(content=None, tool=False, dangerous=False):
    if tool or dangerous:
        args = ('{"command":"rm -rf /"}' if dangerous else '{"city":"Paris"}')
        message = {"role": "assistant", "content": None,
                   "tool_calls": [{"id": "call_1", "type": "function",
                                   "function": {"name": "get_weather" if not dangerous else "exec",
                                                "arguments": args}}]}
        finish = "tool_calls"
    else:
        message = {"role": "assistant", "content": content or "hello veil"}
        finish = "stop"
    return {"id": CHAT, "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}}


ANTH_START = {"type": "message_start", "message": {"id": "msg_1", "type": "message",
              "role": "assistant", "model": "m", "content": [], "stop_reason": None,
              "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0}}}


def anth_frame(event, payload):
    if isinstance(payload, dict):
        payload = json.dumps(payload, ensure_ascii=False)
    return ("event: " + event + "\ndata: " + payload + "\n\n").encode("utf-8")


def anth_stream_normal():
    return (anth_frame("message_start", ANTH_START)
            + anth_frame("content_block_start", {"type": "content_block_start", "index": 0,
                                                 "content_block": {"type": "text", "text": ""}})
            + anth_frame("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                 "delta": {"type": "text_delta", "text": "hello veil"}})
            + anth_frame("content_block_stop", {"type": "content_block_stop", "index": 0})
            + anth_frame("message_delta", {"type": "message_delta",
                                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                           "usage": {"output_tokens": 2}})
            + anth_frame("message_stop", {"type": "message_stop"}))


def anth_stream_tool(dangerous=False):
    name = "exec" if dangerous else "get_weather"
    args = '{"command":"rm -rf /"}' if dangerous else '{"city":"Paris"}'
    half = len(args) // 2
    return (anth_frame("message_start", ANTH_START)
            + anth_frame("content_block_start", {"type": "content_block_start", "index": 0,
                                                 "content_block": {"type": "tool_use", "id": "toolu_1",
                                                                   "name": name, "input": {}}})
            + anth_frame("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                 "delta": {"type": "input_json_delta",
                                                           "partial_json": args[:half]}})
            + anth_frame("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                 "delta": {"type": "input_json_delta",
                                                           "partial_json": args[half:]}})
            + anth_frame("content_block_stop", {"type": "content_block_stop", "index": 0})
            + anth_frame("message_delta", {"type": "message_delta",
                                           "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                                           "usage": {"output_tokens": 2}})
            + anth_frame("message_stop", {"type": "message_stop"}))


def anth_message(tool=False):
    if tool:
        content = [{"type": "tool_use", "id": "toolu_1", "name": "get_weather",
                    "input": {"city": "Paris"}}]
        stop = "tool_use"
    else:
        content = [{"type": "text", "text": "hello veil"}]
        stop = "end_turn"
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": content, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 2}}


RESP_OUT_TEXT = {"type": "message", "id": "msg_1", "role": "assistant",
                 "content": [{"type": "output_text", "text": "hello veil", "annotations": []}]}


def resp_frame(event, payload, seq):
    payload = dict(payload)
    payload["sequence_number"] = seq
    return anth_frame(event, payload)


def resp_stream_normal():
    return (resp_frame("response.created", {"type": "response.created",
                                            "response": {"id": "resp_1", "status": "in_progress",
                                                         "output": []}}, 0)
            + resp_frame("response.output_item.added", {"type": "response.output_item.added",
                                                        "output_index": 0,
                                                        "item": {"id": "msg_1", "type": "message",
                                                                 "role": "assistant", "content": []}}, 1)
            + resp_frame("response.output_text.delta", {"type": "response.output_text.delta",
                                                        "item_id": "msg_1", "output_index": 0,
                                                        "content_index": 0, "delta": "hello veil"}, 2)
            + resp_frame("response.output_text.done", {"type": "response.output_text.done",
                                                       "item_id": "msg_1", "output_index": 0,
                                                       "content_index": 0, "text": "hello veil"}, 3)
            + resp_frame("response.output_item.done", {"type": "response.output_item.done",
                                                       "output_index": 0, "item": RESP_OUT_TEXT}, 4)
            + resp_frame("response.completed", {"type": "response.completed",
                                                "response": {"id": "resp_1", "status": "completed",
                                                             "output": [RESP_OUT_TEXT]}}, 5))


def resp_object(tool=False):
    if tool:
        output = [{"type": "function_call", "id": "fc_1", "call_id": "call_1",
                   "name": "get_weather", "arguments": '{"city":"Paris"}'}]
    else:
        output = [RESP_OUT_TEXT]
    return {"id": "resp_1", "object": "response", "created_at": 1, "model": "m",
            "status": "completed", "output": output,
            "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}}


class MockUpstream(BaseHTTPRequestHandler):
    server_version = "MockUpstream/8.2"

    def log_message(self, *a):
        pass

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8") or "{}"), raw.decode("utf-8", "replace")
        except Exception:
            return {}, raw.decode("utf-8", "replace")

    def _send(self, body, ctype):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body, text = self._read_json()
        stream = body.get("stream") is True
        dangerous = "DANGEROUS_TEST" in text
        tool = "TOOL_TEST" in text
        empty = "EMPTY_TEST" in text
        path = self.path.split("?")[0]
        if path.endswith("/chat/completions"):
            if stream:
                if dangerous:
                    self._send(chat_tool_deltas("exec", "", True), "text/event-stream")
                elif tool:
                    self._send(chat_tool_deltas("get_weather", ""), "text/event-stream")
                else:
                    self._send(chat_stream_normal(), "text/event-stream")
            else:
                self._send(chat_completion(tool=tool), "application/json")
        elif path.endswith("/v1/messages") or path.endswith("/messages"):
            if stream:
                self._send(anth_stream_tool(dangerous) if (tool or dangerous)
                           else anth_stream_normal(), "text/event-stream")
            else:
                self._send(anth_message(tool=tool), "application/json")
        elif path.endswith("/v1/responses") or path.endswith("/responses"):
            if empty:
                self._send(b"", "text/event-stream")
            elif stream:
                self._send(resp_stream_normal(), "text/event-stream")
            else:
                self._send(resp_object(tool=tool), "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


RESULTS = []


def check(name, fn):
    try:
        fn()
    except Exception as e:
        print("FAIL " + name + ": " + repr(e))
        RESULTS.append((name, False))
    else:
        print("PASS " + name)
        RESULTS.append((name, True))


def raw_post(path, payload):
    req = urllib.request.Request(GATEWAY + path,
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def wait_healthy():
    for _ in range(150):
        try:
            with urllib.request.urlopen(GATEWAY + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("veil 网关未就绪")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_veil(env_extra):
    env = dict(os.environ)
    env.update({
        "HOMESERVER": "https://matrix.example.com",
        "ROOM_ID": "!r:example.com",
        "MATRIX_ACCESS_TOKEN": "syt_dummy_veil_conformance",
        "OBSERVABILITY_ADMIN_TOKEN": "veil-conformance-admin-token-0123456789",
        "GET_BINARY_SECRET": "veil-conformance-secret",
        "DATA_DIR": tempfile.mkdtemp(prefix="veil-conformance-"),
    })
    env.update(env_extra)
    proc = subprocess.Popen([VEIL_BIN], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        wait_healthy()
    except Exception:
        proc.terminate()
        raise
    return proc


def run_normal_phase():
    import openai
    import anthropic
    assert openai.__version__ == OPENAI_PIN, openai.__version__
    assert anthropic.__version__ == ANTHROPIC_PIN, anthropic.__version__
    oai = openai.OpenAI(base_url=GATEWAY + "/v1", api_key="dummy", timeout=30.0)
    ant = anthropic.Anthropic(base_url=GATEWAY, api_key="dummy-key", timeout=30.0)

    def chat_nonstream():
        r = oai.chat.completions.create(model="m", messages=[{"role": "user",
                                                              "content": "hello veil"}])
        assert "hello veil" in (r.choices[0].message.content or ""), r

    def chat_stream():
        s = oai.chat.completions.create(model="m", messages=[{"role": "user",
                                                              "content": "hello veil"}],
                                        stream=True)
        text = "".join(c.choices[0].delta.content or "" for c in s if c.choices)
        assert "hello veil" in text, text
        raw = raw_post("/v1/chat/completions", {"model": "m", "messages": [{"role": "user",
                  "content": "hello veil"}], "stream": True})
        assert raw.count("data: [DONE]") + raw.count("data:[DONE]") == 1, raw

    def chat_tool_nonstream():
        r = oai.chat.completions.create(model="m", messages=[{"role": "user",
                                                              "content": "TOOL_TEST run"}])
        tc = r.choices[0].message.tool_calls
        assert tc and tc[0].function.name == "get_weather", r
        assert json.loads(tc[0].function.arguments) == {"city": "Paris"}

    def chat_tool_stream():
        s = oai.chat.completions.create(model="m", messages=[{"role": "user",
                                                              "content": "TOOL_TEST run"}],
                                        stream=True)
        names, args = [], []
        for c in s:
            for tc in (c.choices[0].delta.tool_calls or []):
                if tc.function and tc.function.name:
                    names.append(tc.function.name)
                if tc.function and tc.function.arguments:
                    args.append(tc.function.arguments)
        assert "get_weather" in names, names
        assert json.loads("".join(args)) == {"city": "Paris"}, args

    def anth_nonstream():
        m = ant.messages.create(model="m", max_tokens=64, messages=[{"role": "user",
                                                                     "content": "hello veil"}])
        texts = [b.text for b in m.content if getattr(b, "type", "") == "text"]
        assert any("hello veil" in t for t in texts), m

    def anth_stream():
        text = ""
        with ant.messages.stream(model="m", max_tokens=64, messages=[{"role": "user",
                                                                      "content": "hello veil"}]) as s:
            for _ in s.text_stream:
                pass
            text = s.get_final_message().content[0].text
        assert "hello veil" in text, text

    def anth_tool_nonstream():
        m = ant.messages.create(model="m", max_tokens=64, messages=[{"role": "user",
                                                                     "content": "TOOL_TEST run"}])
        tools = [b for b in m.content if getattr(b, "type", "") == "tool_use"]
        assert tools and tools[0].name == "get_weather", m
        assert tools[0].input == {"city": "Paris"}, tools[0].input

    def anth_tool_stream():
        names, parts = [], []
        s = ant.messages.create(model="m", max_tokens=64, messages=[{"role": "user",
                                                                     "content": "TOOL_TEST run"}],
                                stream=True)
        for e in s:
            t = getattr(e, "type", "")
            if t == "content_block_start":
                b = getattr(e, "content_block", None)
                if b is not None and getattr(b, "name", None):
                    names.append(b.name)
            elif t == "content_block_delta":
                d = getattr(e, "delta", None)
                pj = getattr(d, "partial_json", "") if d is not None else ""
                if pj:
                    parts.append(pj)
        assert "get_weather" in names, names
        assert json.loads("".join(parts)) == {"city": "Paris"}, parts

    def resp_nonstream():
        r = oai.responses.create(model="m", input="hello veil")
        assert "hello veil" in (r.output_text or ""), r

    def resp_stream():
        s = oai.responses.create(model="m", input="hello veil", stream=True)
        deltas, types = [], []
        for e in s:
            types.append(getattr(e, "type", ""))
            d = getattr(e, "delta", "")
            if isinstance(d, str) and d:
                deltas.append(d)
        assert "response.completed" in types, types
        try:
            final = s.get_final_response()
            assert "hello veil" in (final.output_text or ""), final
        except Exception:
            assert "hello veil" in "".join(deltas), deltas

    def resp_tool_nonstream():
        r = oai.responses.create(model="m", input="TOOL_TEST run")
        calls = [b for b in r.output or [] if getattr(b, "type", "") == "function_call"]
        assert calls and calls[0].name == "get_weather", r
        assert json.loads(calls[0].arguments) == {"city": "Paris"}

    for name, fn in [("chat 非流式", chat_nonstream), ("chat 流式", chat_stream),
                     ("chat tool 非流式", chat_tool_nonstream),
                     ("chat tool 流式", chat_tool_stream),
                     ("anthropic 非流式", anth_nonstream), ("anthropic 流式", anth_stream),
                     ("anthropic tool 非流式", anth_tool_nonstream),
                     ("anthropic tool 流式", anth_tool_stream),
                     ("responses 非流式", resp_nonstream), ("responses 流式", resp_stream),
                     ("responses tool 非流式", resp_tool_nonstream)]:
        check(name, fn)


def run_block_phase():
    import openai
    import anthropic
    oai = openai.OpenAI(base_url=GATEWAY + "/v1", api_key="dummy", timeout=30.0)
    ant = anthropic.Anthropic(base_url=GATEWAY, api_key="dummy-key", timeout=30.0)

    def chat_block():
        s = oai.chat.completions.create(model="m", messages=[{"role": "user",
                                                              "content": "DANGEROUS_TEST run"}],
                                        stream=True)
        for _ in s:
            pass
        raw = raw_post("/v1/chat/completions", {"model": "m", "messages": [{"role": "user",
                  "content": "DANGEROUS_TEST run"}], "stream": True})
        assert "[blocked:" in raw, raw
        assert raw.count("data: [DONE]") + raw.count("data:[DONE]") == 1, raw
        assert "rm -rf" not in raw, raw

    def anth_block():
        s = ant.messages.create(model="m", max_tokens=64, messages=[{"role": "user",
                                                                     "content": "DANGEROUS_TEST run"}],
                                stream=True)
        for _ in s:
            pass
        raw = raw_post("/v1/messages", {"model": "m", "max_tokens": 64,
                                        "messages": [{"role": "user",
                                                      "content": "DANGEROUS_TEST run"}],
                                        "stream": True})
        assert "message_stop" in raw, raw
        assert "content_block_stop" in raw, raw
        assert "rm -rf" not in raw, raw

    def resp_truncated():
        s = oai.responses.create(model="m", input="EMPTY_TEST run", stream=True)
        types = [getattr(e, "type", "") for e in s]
        assert "response.failed" in types, types
        raw = raw_post("/v1/responses", {"model": "m", "input": "EMPTY_TEST run",
                                         "stream": True})
        assert "response.failed" in raw, raw

    for name, fn in [("chat 阻断", chat_block), ("anthropic 阻断", anth_block),
                     ("responses 截断", resp_truncated)]:
        check(name, fn)


def main():
    build = subprocess.run(["cargo", "build", "--bin", "veil"], cwd=VEIL_ROOT,
                           capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stdout[-3000:])
        print(build.stderr[-3000:])
        raise SystemExit("cargo build 失败")
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstream)
    mock_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    veil = start_veil({"LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port})
    try:
        run_normal_phase()
    finally:
        veil.terminate()
        veil.wait(timeout=15)
    veil_b = start_veil({"LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port,
                         "AUDIT_MODE": "block", "AUDIT_HOLD_MAX_BYTES": "16"})
    try:
        run_block_phase()
    finally:
        veil_b.terminate()
        veil_b.wait(timeout=15)
        server.shutdown()
    failed = [n for n, ok in RESULTS if not ok]
    print("共 %d 项，失败 %d 项" % (len(RESULTS), len(failed)))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
