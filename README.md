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
- `POST /v1/findings/consolidate`：汇总多次扫描的匹配结果，纯本地处理。请求体含 `allow`、`deny` 和非空
  `runs`；每个 run 有唯一非空 `id`、0–100 的整数 `reliability` 和 `findings`（字段与
  `/v1/vulnerabilities/match` 的单项一致，拒绝未知字段）。先对全部 finding 的 `target` 执行范围评估，
  任一被拒则整体返回 403 `scope_violation`；随后以规范化 `target` 与区分大小写的 `template_id` 为键去重，
  按首次出现顺序返回 `consolidated`：保留首次出现的 `name`（同键不同 name 为 400），`severity` 取最高者，
  `observation_ids` 与 `sources`（run id）各自按首次出现顺序去重，`evidence` 合并为升序去重的非负整数；
  `confidence` 对包含该键的每个不同 run 按 runs 顺序计算
  `c = c + floor((100 - c) * reliability / 100)`（c 从 0 开始），同一 run 内的重复 finding 只计一次
  置信度，但仍参与观察编号与证据合并。没有 finding 时返回空数组；结构错误一律 400 `invalid_request`。
- `POST /v1/findings/retest`：把一次复测与既有汇总结果比较，纯本地处理。请求体只含 `allow`、`deny`、
  `baseline`（既有 consolidate 响应的 `consolidated` 同形数组，可为空）和非空 `retest_runs`（与
  consolidate 的 `runs` 同形）。先完成全部结构校验（含 baseline 项字段/类型、重复 baseline 键、
  非布尔整数的 0–100 `confidence`、非负整数数组 `evidence`、重复 run id），再对 baseline 与复测中
  每个 finding 的 `target` 执行范围评估，任一越界则整体返回 403 `scope_violation`；通过后按既有汇总
  语义生成本次结果。以规范化 `target` 与区分大小写的 `template_id` 为键比较：同键为 `persistent`，
  baseline 有而本次缺失为 `resolved`，本次新增为 `new`。响应只含 `comparisons` 与 `summary`；
  comparisons 先按 baseline 顺序、再按本次汇总首次出现顺序追加 new，每项只含 `target`、`template_id`、
  `name`（persistent/resolved 取 baseline）、`status`、`before`、`after`（两侧完整汇总项，缺失为
  `null`，字段变化不改变状态）；summary 只含 `total_before`、`total_after`、`persistent`、`resolved`、
  `new`。空 baseline 可产生 new，复测无发现时 baseline 全部为 resolved；结构错误一律
  400 `invalid_request`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含资产发现、漏洞模板与攻击链编排的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
