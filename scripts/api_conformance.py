#!/usr/bin/env python3
# scripts/api_conformance.py — 8.2 真实 SDK 对照（openai==3.5.0 anthropic==1.1.0）。
# 用原仓 .venv python 运行：/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/api_conformance.py
# 流程：cargo build → mock 上游（:0 随机端口）→ veil 二进制（固定 127.0.0.1:8877，
# 必填 env 用 dummy 值，LLM_UPSTREAM 指 mock）→ openai/anthropic 官方 SDK 经网关
# 消费三协议流式/非流式/tool call/阻断，断言 SDK 可解析且内容正确。
# 取用相：pykeepass 现场建临时 kdbx（主密码取 Mock TPM 解封值，仅开发）→ DB_DIR
# 指向固件验证整条目/单字段脱敏/原文/404/400/无库 503，固件随临时目录丢弃不入库。
# pykeepass 把自定义 <String> 追加在 <AutoType> 之后，Rust 侧 quick-xml 要求同名
# 元素相邻，故建固件时把 <String> 集中移到 <AutoType> 之前（与官方客户端一致）。
# TPM 说明：无硬件 TPM 的开发机/CI 默认以 VEIL_ALLOW_MOCK_TPM=1 启动（仅开发）；
# 若 TPM 门禁失败，脚本自动回退到 mock-TPM 重试一次并打印指引（生产必须接 TPM 硬件）。
# 阻断触发说明：网关流式阻断由审计 hold 超限 fail-closed 触发（AUDIT_HOLD_MAX_BYTES=16
# 极小值 + 危险 tool args），阻断相以 AUDIT_MODE=block 运行；responses 流式无 tool
# 输出数组可供 hold 捕获，取空流截断合成 response.failed 路径；responses 非流阻断由
# 非流审计提取危险 function_call 触发，断言阻断体经真 SDK 解析（11.1）。
# NON_GOAL 豁免：独立 admin.html 静态控制台不在本仓交付（见 README 管理控制台说明），
# 本脚本不覆盖其前端行为（静态页/CSP/Chart），仅覆盖后端管理面 API。

import hashlib
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


def anth_stream_error():
    # TST-9：Anthropic `error` 事件即终端，其后不注入 `message_stop`（README §7.2/§8.6）。
    return anth_frame("error", {"type": "error",
                                "error": {"type": "overloaded_error",
                                          "message": "Overloaded"}})


def anth_stream_cr():
    # TST-9：CR-only 分块——以 `\r` 作行终止（WHATWG SSE），绕开 `anth_frame` 的 `\n` 拼接。
    return anth_stream_normal().replace(b"\n", b"\r")


def anth_stream_thinking():
    # TST-9：extended thinking 帧（`thinking_delta` + `signature_delta`）。
    return (anth_frame("message_start", ANTH_START)
            + anth_frame("content_block_start", {"type": "content_block_start", "index": 0,
                                                 "content_block": {"type": "thinking",
                                                                   "thinking": ""}})
            + anth_frame("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                 "delta": {"type": "thinking_delta",
                                                           "thinking": "step by step"}})
            + anth_frame("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                 "delta": {"type": "signature_delta",
                                                           "signature": "sig-abc"}})
            + anth_frame("content_block_stop", {"type": "content_block_stop", "index": 0})
            + anth_frame("message_delta", {"type": "message_delta",
                                           "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                           "usage": {"output_tokens": 3}})
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
            + resp_frame("response.content_part.added", {"type": "response.content_part.added",
                                                         "item_id": "msg_1", "output_index": 0,
                                                         "content_index": 0,
                                                         "part": {"type": "output_text", "text": "",
                                                                  "annotations": []}}, 2)
            + resp_frame("response.output_text.delta", {"type": "response.output_text.delta",
                                                        "item_id": "msg_1", "output_index": 0,
                                                        "content_index": 0, "delta": "hello veil"}, 3)
            + resp_frame("response.output_text.done", {"type": "response.output_text.done",
                                                       "item_id": "msg_1", "output_index": 0,
                                                       "content_index": 0, "text": "hello veil"}, 4)
            + resp_frame("response.output_item.done", {"type": "response.output_item.done",
                                                       "output_index": 0, "item": RESP_OUT_TEXT}, 5)
            + resp_frame("response.completed", {"type": "response.completed",
                                                "response": {"id": "resp_1", "object": "response",
                                                             "created_at": 1, "model": "m",
                                                             "status": "completed",
                                                             "output": [RESP_OUT_TEXT]}}, 6))


def resp_object(tool=False, dangerous=False):
    if dangerous:
        output = [{"type": "function_call", "id": "fc_1", "call_id": "call_1",
                   "name": "exec", "arguments": '{"command":"rm -rf /"}'}]
    elif tool:
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
                if "ERROR_TEST" in text:
                    self._send(anth_stream_error(), "text/event-stream")
                elif "CR_TEST" in text:
                    self._send(anth_stream_cr(), "text/event-stream")
                elif "THINKING_TEST" in text:
                    self._send(anth_stream_thinking(), "text/event-stream")
                else:
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
                self._send(resp_object(tool=tool, dangerous=dangerous), "application/json")
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


def cred_post(payload, tag="conformance"):
    import urllib.error
    req = urllib.request.Request(
        GATEWAY + "/credential",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "X-Get-Binary-Hash": "conformance-caller-%s" % tag,
                 "X-Get-Binary-Secret": "veil-conformance-secret"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace"))


def cred_auth(entry=None, field=None, token=None, tag="conformance"):
    body = {"auth": {"caller_hash": "conformance-caller-%s" % tag,
                     "caller_path": "/srv/conformance-%s.sh" % tag}}
    if entry is not None:
        body["entry"] = entry
    if field is not None:
        body["field"] = field
    if token is not None:
        body["token"] = token
    return body


def normalize_entry_strings(entry):
    el = entry._element
    strings = [c for c in el if c.tag == "String"]
    for s in strings:
        el.remove(s)
    anchor = el.find("AutoType")
    for s in strings:
        if anchor is not None:
            anchor.addprevious(s)
        else:
            el.append(s)


def _caller_entry(caller_path, caller_hash):
    # 与 Rust `RegisterParams` 默认 + `enabled=true` 同构；`script_sha256` 走
    # 派生回退 `sha256(expected_hash:caller_path)`（脚本路径不存在时）。
    derived = hashlib.sha256(("%s:%s" % (caller_hash, caller_path)).encode("utf-8")).hexdigest()
    return {
        "caller_path": caller_path,
        "expected_hash": caller_hash,
        "script_sha256": derived,
        "enabled": True,
        "revoked": False,
        "auto_approve": None,
        "name": caller_path,
        "description": "",
        "entries": {"不存在": ["授权码"], "网易": ["授权码"]},
        "allow_mode": None,
        "old_hash": None,
        "old_hash_expires_at": None,
    }


def seed_registry(path, tags):
    # AUTH-4 后未 enrolled 调用方默认转 Matrix 审批，无 Matrix 上游时 fail-closed 403；
    # 取用相须预置已启用调用方（完整性 sha256 与 Rust `integrity_of` 同口径）。
    entries = {}
    for tag in sorted(tags):
        caller_path = "/srv/conformance-%s.sh" % tag
        caller_hash = "conformance-caller-%s" % tag
        entries[caller_path] = _caller_entry(caller_path, caller_hash)
    canonical = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    payload = {"entries": entries,
               "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    return path


def run_credential_phase(mock_port):
    from pykeepass import create_database
    work = tempfile.mkdtemp(prefix="veil-conformance-kdbx-")
    reg_path = seed_registry(os.path.join(work, "caller_registry.json"),
                             ["full", "single", "raw", "missing", "selector", "nodb"])
    master = "veil-dev-mock-tpm-seal"
    kp = create_database(os.path.join(work, "ci.kdbx"), password=master)
    entry = kp.add_entry(kp.root_group, "网易", "mail-user", "mail-secret-001",
                         url="https://mail.example.com")
    entry.set_custom_property("授权码", "authcode-abc-123", protect=True)
    entry.set_custom_property("备注", "plain-note", protect=False)
    normalize_entry_strings(entry)
    kp.save()

    def full_entry():
        status, body = cred_post(cred_auth(entry="网易", tag="full"), tag="full")
        assert status == 200, (status, body)
        cred = body["credential"]
        assert cred["title"] == "网易", cred
        assert cred["username"] == "mail-user", cred
        assert cred["password"].startswith("__VG_CRED_"), cred
        assert "mail-secret-001" not in json.dumps(body), body
        props = cred["custom_properties"]
        assert props["授权码"].startswith("__VG_CRED_"), props
        assert props["备注"] == "plain-note", props

    def single_protected():
        status, body = cred_post(cred_auth(entry="网易", field="授权码", tag="single"),
                                 tag="single")
        assert status == 200, (status, body)
        assert body["credential"]["value"].startswith("__VG_CRED_"), body

    def single_raw():
        status, body = cred_post(cred_auth(entry="网易", field="授权码", token=False,
                                           tag="raw"),
                                 tag="raw")
        assert status == 200, (status, body)
        assert body["credential"]["value"] == "authcode-abc-123", body

    def missing_entry():
        status, body = cred_post(cred_auth(entry="不存在", tag="missing"), tag="missing")
        assert status == 404, (status, body)
        assert "不存在" in json.dumps(body, ensure_ascii=False), body

    def missing_selector():
        status, body = cred_post(cred_auth(tag="selector"), tag="selector")
        assert status == 400, (status, body)

    veil = start_veil({"DB_DIR": work,
                       "CALLER_REGISTRY_PATH": reg_path,
                       "LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port})
    try:
        for name, fn in [("取用 整条目", full_entry), ("取用 单字段脱敏", single_protected),
                         ("取用 原文", single_raw), ("取用 缺条目404", missing_entry),
                         ("取用 缺entry400", missing_selector)]:
            check(name, fn)
    finally:
        veil.terminate()
        veil.wait(timeout=15)

    def no_db():
        status, body = cred_post(cred_auth(entry="网易", tag="nodb"), tag="nodb")
        assert status == 503, (status, body)

    veil_nodb = start_veil({"DB_DIR": os.path.join(work, "empty"),
                            "CALLER_REGISTRY_PATH": reg_path,
                            "LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port})
    try:
        os.makedirs(os.path.join(work, "empty"), exist_ok=True)
        check("取用 无库503", no_db)
    finally:
        veil_nodb.terminate()
        veil_nodb.wait(timeout=15)


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
    base = {
        "HOMESERVER": "https://matrix.example.com",
        "ROOM_ID": "!r:example.com",
        "MATRIX_ACCESS_TOKEN": "syt_dummy_veil_conformance",
        "OBSERVABILITY_ADMIN_TOKEN": "veil-conformance-admin-token-0123456789",
        "GET_BINARY_SECRET": "veil-conformance-secret",
        "DATA_DIR": tempfile.mkdtemp(prefix="veil-conformance-"),
    }
    if "VEIL_ALLOW_MOCK_TPM" not in env and "VEIL_ALLOW_MOCK_TPM" not in env_extra:
        base["VEIL_ALLOW_MOCK_TPM"] = "1"
    env.update(base)
    env.update(env_extra)

    def _launch(env):
        proc = subprocess.Popen([VEIL_BIN], env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            wait_healthy()
        except Exception:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
            raise
        return proc

    try:
        return _launch(env)
    except Exception:
        if env.get("VEIL_ALLOW_MOCK_TPM") == "1":
            raise
        print("veil 网关未就绪：疑似 TPM 门禁失败（本机无 TPM 硬件）。"
              "自动以 VEIL_ALLOW_MOCK_TPM=1（仅开发/CI，生产禁用）重试一次；"
              "开发机可 export VEIL_ALLOW_MOCK_TPM=1 后重跑，生产必须接 TPM 2.0 硬件。")
        env["VEIL_ALLOW_MOCK_TPM"] = "1"
        return _launch(env)


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
        types, deltas = [], []
        with oai.responses.stream(model="m", input="hello veil") as s:
            for e in s:
                types.append(getattr(e, "type", ""))
                d = getattr(e, "delta", "")
                if isinstance(d, str) and d:
                    deltas.append(d)
            assert "response.completed" in types, types
            final = s.get_final_response()
            assert "hello veil" in (final.output_text or ""), final

    def resp_tool_nonstream():
        r = oai.responses.create(model="m", input="TOOL_TEST run")
        calls = [b for b in r.output or [] if getattr(b, "type", "") == "function_call"]
        assert calls and calls[0].name == "get_weather", r
        assert json.loads(calls[0].arguments) == {"city": "Paris"}

    def anth_error_stream():
        raised = None
        try:
            s = ant.messages.create(model="m", max_tokens=64,
                                    messages=[{"role": "user", "content": "ERROR_TEST run"}],
                                    stream=True)
            for _ in s:
                pass
        except Exception as e:  # SDK 对 error 事件须报错而非静默成功
            raised = e
        assert raised is not None, "error 事件须使 SDK 报错"
        assert "verload" in str(raised).lower(), raised
        raw = raw_post("/v1/messages", {"model": "m", "max_tokens": 64,
                                        "messages": [{"role": "user", "content": "ERROR_TEST run"}],
                                        "stream": True})
        assert "overloaded" in raw, raw
        assert "message_stop" not in raw, "Anthropic error 即终端，不得补 message_stop"

    def anth_cr_stream():
        text = ""
        with ant.messages.stream(model="m", max_tokens=64,
                                 messages=[{"role": "user", "content": "CR_TEST run"}]) as s:
            for _ in s.text_stream:
                pass
            text = s.get_final_message().content[0].text
        assert "hello veil" in text, text

    def anth_thinking_stream():
        think, sig, types = [], "", []
        s = ant.messages.create(model="m", max_tokens=64,
                                messages=[{"role": "user", "content": "THINKING_TEST run"}],
                                stream=True)
        for e in s:
            t = getattr(e, "type", "")
            types.append(t)
            if t == "content_block_delta":
                d = getattr(e, "delta", None)
                dt = getattr(d, "type", "")
                if dt == "thinking_delta":
                    think.append(getattr(d, "thinking", ""))
                elif dt == "signature_delta":
                    sig = getattr(d, "signature", "")
        assert "step by step" in "".join(think), (think, types)
        assert sig == "sig-abc", (sig, types)

    for name, fn in [("chat 非流式", chat_nonstream), ("chat 流式", chat_stream),
                     ("chat tool 非流式", chat_tool_nonstream),
                     ("chat tool 流式", chat_tool_stream),
                     ("anthropic 非流式", anth_nonstream), ("anthropic 流式", anth_stream),
                     ("anthropic tool 非流式", anth_tool_nonstream),
                     ("anthropic tool 流式", anth_tool_stream),
                     ("anthropic error 事件", anth_error_stream),
                     ("anthropic CR-only 分块", anth_cr_stream),
                     ("anthropic thinking", anth_thinking_stream),
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
        # 11.1/A-3：阻断五件套（message_start → content_block_start →
        # content_block_stop → message_delta → message_stop）经 SDK 累加器解析；
        # 缺 message_start 时首事件断言失败、`get_final_message` 无初始快照。
        types = []
        with ant.messages.stream(model="m", max_tokens=64,
                                 messages=[{"role": "user",
                                            "content": "DANGEROUS_TEST run"}]) as s:
            for e in s:
                types.append(getattr(e, "type", ""))
            final = s.get_final_message()
        assert types == ["message_start", "content_block_start", "content_block_stop",
                         "message_delta", "message_stop"], types
        texts = [b.text for b in final.content if getattr(b, "type", "") == "text"]
        assert any("[blocked:" in t for t in texts), texts
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

    def resp_block_nonstream():
        # 11.1/A-1：非流 Responses 阻断体经真 SDK 解析——`output`/`status` 可读、
        # `output_text` 不抛错（canonical `llm-protocol-hardening` 必需字段完整）。
        r = oai.responses.create(model="m", input="DANGEROUS_TEST run")
        assert r.status == "failed", r
        assert r.output == [], r
        assert r.output_text == "", r
        assert r.error is not None and "[blocked:" in (r.error.message or ""), r

    for name, fn in [("chat 阻断", chat_block), ("anthropic 阻断", anth_block),
                     ("responses 截断", resp_truncated),
                     ("responses 非流阻断", resp_block_nonstream)]:
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
    run_credential_phase(mock_port)
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
