## F1. F-P1a Responses 用量顶层优先（D1）

- [x] F1.1 `usage.rs` 改三级回退并补真实体单测
  - Verify：顶层 `usage{input_tokens:12,output_tokens:45}` 提取 12/45 且缓存列命中；仅双层体回退不断链，`cargo test usage` 通过
  - Verify：流式 `response.completed.response.usage` 同口径，`cargo test` 全绿
- [x] F1.2 README §7.2 追加顶层优先一句并跑回归
  - Verify：文档含顶层优先字样，`grep -n "顶层优先" README.md` 命中
  - Verify：`scripts/api_conformance.py` 用量用例通过

## F2. F-P1b 多 choice 桶隔离（D2）

- [x] F2.1 `fragments.rs/tool.rs` 桶键混入 `ci` 并同步 `synth_id`
  - Verify：`n=2` 同 `index:0` 分桶隔离、参数不串扰单测通过，`cargo test tool` 通过
  - Verify：`custom_obj_to_call` 同步，legacy 与新形态快照更新
- [x] F2.2 跑流泵回归
  - Verify：`cargo test pump` 通过；截断丢弃计数不变

## F3. F-P2a 占位精确形态与幂等（D3）

- [x] F3.1 `has_placeholder_tokens` 改精确校验并加幂等守卫
  - Verify：`__PII_*__` 字面判 false，`__PII_1_ab12cd34__` 判 true；已含说明不再前插，`cargo test placeholder` 通过
  - Verify：`cargo test rewrite` 通过，无字节等价回退
- [x] F3.2 跑占位全回归
  - Verify：三协议注入快照全绿

## F4. F-P2b 用量快路径零分配（D4）

- [x] F4.1 `extract_usage_stream` 改借用判断
  - Verify：心跳分片返回 None 且行为等价；有用量分片结论不变，`cargo test usage` 通过
  - Verify：`cargo test` 全绿，无 bench 门禁
