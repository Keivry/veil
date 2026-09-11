#!/usr/bin/env python3
# scripts/go_interop_e2e.py — veil-hardening 5.1–5.3「Go 对接验证」端到端 runner。
# 用原仓 venv python 运行（含 pykeepass）：
#   /home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/go_interop_e2e.py
#
# 复用 api_conformance.py 的 MockUpstream / start_veil / raw_post / 临时 kdbx 设施，
# 覆盖：5.1 Go 直连取用全链路（整条目/单字段原文/status/转发以 HTTP 代表）+
# 5.2 三因子齐全放行与缺失/错误明确拒绝（含 403 与转审 202）+ 5.3 Go 消费阻断流终止。
# Go 二进制经 make build 产出 get-credential-linux-amd64；veil 经 cargo build --bin veil。
# 打印 PASS/FAIL <name> 与耗时，汇总「共 N 项，失败 M 项」，失败非零退出。
# 前置不可得（TPM/pykeepass/go 工具链/网络）时显式报错并非零退出，不静默跳过。

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import api_conformance as ac  # noqa: E402

VEIL_ROOT = ac.VEIL_ROOT
GATEWAY = ac.GATEWAY
SECRET = "veil-conformance-secret"

PROXY_ROOT = "/home/keivry/项目/Python/credential-proxy"
GET_DIR = os.path.join(PROXY_ROOT, "get")
GO_BIN = os.path.join(GET_DIR, "get-credential-linux-amd64")

RESULTS = []
WRAP_DIR = None


def check(name, fn):
    start = time.monotonic()
    try:
        detail = fn() or ""
    except Exception as e:
        elapsed = time.monotonic() - start
        print("FAIL %s (%.2fs): %r" % (name, elapsed, e))
        RESULTS.append((name, False))
    else:
        elapsed = time.monotonic() - start
        suffix = " [%.2fs]" % elapsed
        if detail:
            suffix += " " + detail
        print("PASS %s%s" % (name, suffix))
        RESULTS.append((name, True))


def build_all():
    build = subprocess.run(["cargo", "build", "--bin", "veil"], cwd=VEIL_ROOT,
                           capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stdout[-3000:])
        print(build.stderr[-3000:])
        raise SystemExit("cargo build --bin veil 失败")
    make = subprocess.run(["make", "-C", GET_DIR, "build"], capture_output=True, text=True)
    if make.returncode != 0:
        print(make.stdout[-3000:])
        print(make.stderr[-3000:])
        raise SystemExit("make -C get build 失败")
    if not os.path.exists(GO_BIN):
        raise SystemExit("Go 二进制缺失: %s" % GO_BIN)


def create_kdbx():
    from pykeepass import create_database
    work = tempfile.mkdtemp(prefix="veil-gointerop-kdbx-")
    kp = create_database(os.path.join(work, "ci.kdbx"), password="veil-dev-mock-tpm-seal")
    entry = kp.add_entry(kp.root_group, "网易", "mail-user", "mail-secret-001",
                         url="https://mail.example.com")
    entry.set_custom_property("授权码", "authcode-abc-123", protect=True)
    entry.set_custom_property("备注", "plain-note", protect=False)
    ac.normalize_entry_strings(entry)
    kp.save()
    return work


def make_wrapper(tag):
    path = os.path.join(WRAP_DIR, "caller_%s.sh" % tag)
    with open(path, "w", encoding="utf-8") as f:
        f.write('#!/usr/bin/env bash\n"%s" "$@"\nexit $?\n' % GO_BIN)
    os.chmod(path, 0o755)
    return path


def run_go(tag, args, secret=SECRET, timeout=60):
    wrapper = make_wrapper(tag)
    env = dict(os.environ)
    env["GET_BINARY_SECRET"] = secret
    env["PROXY_URL"] = GATEWAY
    env["PROXY_HTTP_TIMEOUT"] = "30"
    return subprocess.run(["bash", wrapper, *args], env=env,
                          capture_output=True, text=True, timeout=timeout)


def http_post(path, payload, headers=None, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(GATEWAY + path, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def s51_go_full_entry():
    cp = run_go("full", ["credential", "网易"])
    assert cp.returncode == 0, (cp.returncode, cp.stderr)
    out = cp.stdout
    for needle in ["标题: 网易", "用户名: mail-user", "__VG_CRED_",
                   "https://mail.example.com"]:
        assert needle in out, (needle, out)
    return "含标题/用户名/占位密码/URL"


def s51_go_single_raw():
    cp = run_go("raw", ["credential", "网易", "授权码", "--raw"])
    assert cp.returncode == 0, (cp.returncode, cp.stderr)
    assert "authcode-abc-123" in cp.stdout, cp.stdout
    return "原文 authcode-abc-123"


def s51_go_status():
    cp = run_go("status", ["status"])
    assert cp.returncode == 0, (cp.returncode, cp.stderr)
    out = cp.stdout
    assert "状态: ok" in out, out
    assert "解锁: ✅ 已解锁" in out, out
    assert "待审批:" in out and "LLM 凭据:" in out, out
    return out.strip().replace("\n", " | ")


def s51_forward_http():
    nonstream = ac.raw_post("/v1/chat/completions", {
        "model": "m", "messages": [{"role": "user", "content": "hello veil"}]})
    assert "hello veil" in nonstream, nonstream
    stream = ac.raw_post("/v1/chat/completions", {
        "model": "m", "messages": [{"role": "user", "content": "hello veil"}], "stream": True})
    assert stream.count("data: [DONE]") + stream.count("data:[DONE]") == 1, stream
    return "非流式 200 含 hello veil；流式恰一 [DONE]"


def s52_go_full_allow():
    cp = run_go("allow", ["credential", "网易"])
    assert cp.returncode == 0, (cp.returncode, cp.stderr)
    assert "标题: 网易" in cp.stdout, cp.stdout
    return "齐全三因子 Go 放行"


def s52_go_wrong_secret():
    cp = run_go("badsecret", ["credential", "网易"], secret="wrong-secret")
    assert cp.returncode != 0, (cp.returncode, cp.stdout)
    msg = cp.stderr + cp.stdout
    assert "Secret 校验失败" in msg, msg
    assert "解析响应失败" not in msg, msg
    return "Go 打印网关拒绝：Secret 校验失败"


def s52_http_missing_caller():
    status, body = http_post("/credential", {
        "entry": "网易", "token": True,
        "auth": {"get_binary_hash": "sha256:x", "get_binary_secret": SECRET}},
        {"X-Get-Binary-Secret": SECRET})
    assert status == 403, (status, body)
    text = json.dumps(body, ensure_ascii=False)
    assert "caller_hash" in text, body
    return "403 缺 caller_hash/caller_path"


def s52_http_missing_auth():
    status, body = http_post("/credential", {"entry": "网易", "token": True},
                             {"X-Get-Binary-Secret": SECRET})
    assert status == 403, (status, body)
    code = (body.get("error") or {}).get("code")
    assert code == "E_AUTH", body
    return "403 缺 body.auth"


def s52_http_wrong_secret():
    status, body = http_post("/credential", {
        "entry": "网易", "token": True,
        "auth": {"caller_hash": "sha256:caller-x", "caller_path": "/srv/x.sh",
                 "get_binary_hash": "sha256:x", "get_binary_secret": "wrong"}},
        {"X-Get-Binary-Secret": "wrong-secret"})
    assert status == 403, (status, body)
    text = json.dumps(body, ensure_ascii=False)
    assert "Secret 校验失败" in text, body
    return "403 Secret 校验失败"


def s52_http_transfer_202():
    path = os.path.join(WRAP_DIR, "pending_caller.sh")
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/usr/bin/env bash\ntrue\n")
    os.chmod(path, 0o755)
    status, body = http_post("/register-caller", {
        "caller_path": path, "caller_hash": "sha256:pending-h1",
        "name": "e2e-pending", "entries": {"网易": []}, "allow_mode": "true"})
    assert status == 200, (status, body)
    status, body = http_post("/credential", {
        "entry": "网易", "token": True,
        "auth": {"caller_hash": "sha256:deadbeef", "caller_path": path,
                 "get_binary_hash": "sha256:x", "get_binary_secret": SECRET}},
        {"X-Get-Binary-Secret": SECRET})
    assert status == 202, (status, body)
    code = (body.get("error") or {}).get("code")
    assert code == "E_PENDING", body
    return "已注册路径哈希失配 → 202 E_PENDING 转审"


def run_abuse_case(mock_port, work):
    get_hash = "sha256:" + "a" * 64
    veil = ac.start_veil({"DB_DIR": work, "GET_BINARY_HASH": get_hash,
                          "LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port})
    try:
        status, body = http_post("/credential", {
            "entry": "网易", "token": False,
            "auth": {"caller_hash": get_hash, "caller_path": "/srv/direct.sh",
                     "get_binary_hash": get_hash, "get_binary_secret": SECRET}},
            {"X-Get-Binary-Hash": get_hash, "X-Get-Binary-Secret": SECRET})
        assert status == 403, (status, body)
        text = json.dumps(body, ensure_ascii=False)
        assert "拒绝" in text, body
    finally:
        veil.terminate()
        veil.wait(timeout=15)
    return "caller_hash == GET_BINARY_HASH（token=false）403 拒绝"


def build_sse_e2e_binary(tmpdir):
    out = os.path.join(tmpdir, "sse_e2e.test")
    cp = subprocess.run(["go", "test", "-c", "-o", out, "./internal/"],
                        cwd=GET_DIR, capture_output=True, text=True)
    if cp.returncode != 0:
        print(cp.stdout[-3000:])
        print(cp.stderr[-3000:])
        raise RuntimeError("go test -c 编译失败")
    return out


def run_sse_case(bin_path, url, body):
    env = dict(os.environ)
    env["VEIL_SSE_E2E_URL"] = url
    env["VEIL_SSE_E2E_BODY"] = body
    start = time.monotonic()
    cp = subprocess.run(
        [bin_path, "-test.run", "TestConsumeSSEAgainstGatewayE2E", "-test.v"],
        env=env, capture_output=True, text=True, timeout=60)
    elapsed = time.monotonic() - start
    out = cp.stdout + cp.stderr
    assert cp.returncode == 0, out
    assert "PASS" in out, out
    assert elapsed < 10.0, ("SSE 未在数秒内闭合，疑重试/挂起", elapsed)
    return "terminal=true %.2fs" % elapsed


def main():
    global WRAP_DIR
    WRAP_DIR = tempfile.mkdtemp(prefix="veil-gointerop-wrap-")
    build_all()
    work = create_kdbx()

    server = ThreadingHTTPServer(("127.0.0.1", 0), ac.MockUpstream)
    mock_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    veil = ac.start_veil({"DB_DIR": work,
                          "LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port})
    try:
        check("5.1 取用 Go 整条目", s51_go_full_entry)
        check("5.1 取用 Go 单字段原文", s51_go_single_raw)
        check("5.1 状态 Go status（pending/llm_secrets）", s51_go_status)
        check("5.1 转发 非流+流式（SDK/HTTP 代表）", s51_forward_http)
        check("5.2 齐全 Go 放行", s52_go_full_allow)
        check("5.2 错误密钥 Go 明确拒绝", s52_go_wrong_secret)
        check("5.2 缺 caller_hash/caller_path 403", s52_http_missing_caller)
        check("5.2 缺 body.auth 403", s52_http_missing_auth)
        check("5.2 错误 Secret 403", s52_http_wrong_secret)
        check("5.2 转审 202 E_PENDING", s52_http_transfer_202)
    finally:
        veil.terminate()
        veil.wait(timeout=15)

    check("5.2 caller_hash 冒用 GET_BINARY_HASH 403",
          lambda: run_abuse_case(mock_port, work))

    veil_b = ac.start_veil({"DB_DIR": work,
                            "LLM_UPSTREAM": "http://127.0.0.1:%d" % mock_port,
                            "AUDIT_MODE": "block", "AUDIT_HOLD_MAX_BYTES": "16"})
    try:
        sse_bin = build_sse_e2e_binary(WRAP_DIR)
        check("5.3 Go 消费阻断流 chat [DONE]",
              lambda: run_sse_case(
                  sse_bin, GATEWAY + "/v1/chat/completions",
                  json.dumps({"model": "m",
                              "messages": [{"role": "user", "content": "DANGEROUS_TEST run"}],
                              "stream": True})))
        check("5.3 Go 消费阻断流 anthropic message_stop",
              lambda: run_sse_case(
                  sse_bin, GATEWAY + "/v1/messages",
                  json.dumps({"model": "m", "max_tokens": 64,
                              "messages": [{"role": "user", "content": "DANGEROUS_TEST run"}],
                              "stream": True})))
        check("5.3 Go 消费截断流 responses response.failed",
              lambda: run_sse_case(
                  sse_bin, GATEWAY + "/v1/responses",
                  json.dumps({"model": "m", "input": "EMPTY_TEST run", "stream": True})))
    finally:
        veil_b.terminate()
        veil_b.wait(timeout=15)
        server.shutdown()

    failed = [n for n, ok in RESULTS if not ok]
    print("共 %d 项，失败 %d 项" % (len(RESULTS), len(failed)))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
