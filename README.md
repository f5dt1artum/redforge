# RedForge

这是一个面向渗透测试与攻防演练的渗透测试与攻防演练平台。长期目标是提供资产发现与指纹识别、端口与服务测绘、漏洞模板匹配、凭证探测、载荷生成、攻击链编排、授权边界强制和结果评分，把攻防演练沉淀为可复用平台。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m redforge.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `REDFORGE_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 接口

- `POST /v1/scope/evaluate`：以 `allow`/`deny` 规则评估 `targets` 的授权范围，纯本地判定。
- `POST /v1/vulnerabilities/match`：离线漏洞模板匹配。请求体含 `allow`、`deny`、`templates`、`observations`；
  先对全部观察目标执行范围评估（任一被拒则整体返回 403 `scope_violation`），再把每个观察与每个模板按
  `all`/`any` 逻辑匹配，响应仅含 `findings`（按观察顺序、再按模板顺序），每项给出 `observation_id`、
  规范化 `target`、`template_id`、`name`、`severity` 和命中匹配器下标 `evidence`。
- `POST /v1/findings/consolidate`：离线汇总多次扫描的匹配结果。请求体含 `allow`、`deny`、非空 `runs`；
  每个 run 含唯一非空 `id`、0–100 的整数 `reliability` 和 `findings` 数组（字段同 match 的发现）。
  先规范化并授权检查全部 finding 的 target（任一被拒则整体 403 `scope_violation`），再以
  「规范化 target + 区分大小写的 template_id」为键，按首次出现顺序合并：`name` 保留首次值
  （同键不同 name 视为 400 `invalid_request`），`severity` 取最高，`observation_ids`/`sources`
  按首次出现顺序去重，`evidence` 合并为升序去重的非负整数。`confidence` 对每个含该键的不同 run
  只计一次，按 runs 顺序以 `c=c+floor((100-c)*reliability/100)` 从 0 迭代（整数）；同一 run 内的
  重复发现仍参与观察编号与证据合并。响应仅含 `consolidated`，无发现时为空数组。纯本地计算，不落盘。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含资产发现、漏洞模板与攻击链编排的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
