## 1. 安全与 env 兼容

- [x] 1.1 去除紧急吊销 XFF 回退，只认 ConnectInfo，并补伪造头回归单测
- [x] 1.2 兼容 `PII_REDACTION_ENABLED` 别名并恢复 `PII_RESPONSE_SIDE/FUZZY/HARDENING` 语义
- [x] 1.3 `PII_CUSTOM_*` 缺文件/解析失败拒启动（fail-closed）并补单测
- [x] 1.4 采样三变量收敛进 `Config`，移除请求路径 env 直读

## 2. 协议终止与 usage

- [x] 2.1 Chat DONE 裸帧化 + 去重恰 1，`ensure_event_lines` 对 DONE 豁免
- [x] 2.2 Anthropic 阻断补 `content_block_start` 并锁定三件套顺序
- [x] 2.3 Responses `incomplete/error` 闭环为 `failed`，单层 usage 优先
- [x] 2.4 usage 双段改单调 max，快路径兼查裸 token 键

## 3. Go 互操作闭环

- [x] 3.1 网关兼容读 `body.auth.get_binary_hash/secret` 并补取用回归
- [x] 3.2 错误体/健康镜像字段（`error_detail`/`status`/`unlocked`）并验证 Go 可解析
- [x] 3.3 `entry/field` 缺失改 400 指引，不再静默忽略

## 4. 文档与门禁

- [x] 4.1 README 补 env 全表/单端口语义/admin 缺失/mock-TPM 指引，阈值零漂移校验
- [x] 4.2 回归 6 组单测全绿 + `cargo fmt/clippy/test` 门禁（222 passed，clippy 零告警）
- [x] 4.3 `api_conformance.py` 内建 mock-TPM 回退，14/14 通过并记录对应 `veil-hardening 5.1-5.3` 闭环
