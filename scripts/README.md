# scripts

- `api_conformance.py` — 8.2 真实 SDK 对照。用原仓 `.venv` python 运行：
  `/home/keivry/项目/Python/credential-proxy/.venv/bin/python scripts/api_conformance.py`
- SDK pin：`openai==3.5.0`、`anthropic==1.1.0`（与原仓 `.venv` 锁定版本一致）。
- mock 上游监听 `:0` 随机端口；veil 二进制固定 `127.0.0.1:8877`。
