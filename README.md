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
- `POST /v1/findings/retest`：把一次复测与既有汇总结果比较，纯本地处理。请求体仅含 `allow`、`deny`、
  `baseline`、`retest_runs`；`baseline` 是既有 consolidate 响应的 `consolidated` 同形数组（可为空），
  `retest_runs` 是非空 runs 同形数组。先完成全部结构校验，再对两侧每个 finding 的规范化 `target`
  执行范围评估，任一越界则整体返回 403 `scope_violation`，不返回比较结果；通过后按既有汇总语义生成本次结果。
  比较键为规范化 `target` 与区分大小写的 `template_id`；baseline 键重复、同键 name 冲突、非法
  severity/confidence/evidence、重复 run id、字段缺失或多余均返回 400 `invalid_request`（confidence
  为 0–100 的非布尔整数，evidence 为非负整数数组）。成功响应仅含 `comparisons` 和 `summary`：
  comparisons 先按 baseline 顺序给出同键 `persistent` 或缺失 `resolved`，再按本次汇总首次出现顺序追加
  baseline 没有的 `new`；每项只含 `target`、`template_id`、`name`（优先取 baseline）、`status`、
  `before`、`after`（两侧为完整汇总项，缺失为 `null`；字段变化不改变状态）。summary 只含
  `total_before`、`total_after`、`persistent`、`resolved`、`new` 五个一致整数。空 baseline 可产生
  `new`；复测无发现时 baseline 项全部为 `resolved`；同一输入数组顺序稳定。
- `POST /v1/attack-chains/plan`：按汇总发现项规划攻击链阶段，纯本地处理，不发起网络请求、不执行阶段、
  不持久化。请求体仅含 `allow`、`deny`、`findings`、`stages`；`findings` 与 consolidate 响应的
  `consolidated` 数组同形（可为空），规范化 `target` 与区分大小写的 `template_id` 组合不得重复。
  `stages` 为非空数组，每个阶段只含非空 `id`、非空 `name`、`logic`（仅 `all`/`any`）、非空 `requires`
  和 `depends_on`；`requires` 每项只含非空 `template_id`、`min_severity`（既有严重性等级）和
  `min_confidence`（0–100 的非布尔整数）；`depends_on` 为阶段 id 数组，不得重复、自指、引用未知 id 或
  形成环，阶段 `id` 必须唯一。先完整校验结构，再规范化并对全部 finding 的 `target` 执行范围评估，
  任一越界则整体返回 403 `scope_violation`（结构错误优先，为 400 `invalid_request`），不返回局部计划。
  通过后按规范化 `target` 分组并保持首次出现顺序；条件只匹配同一目标下 `template_id` 大小写一致、
  `severity` 与 `confidence` 均达到门槛的发现项。阶段按拓扑顺序评估、同层保持输入顺序：自身条件按
  `logic` 成立且所有依赖均为 `ready` 时为 `ready`（`reason` 为 `null`）；条件不成立为 `skipped`/
  `missing_requirements`；条件成立但依赖未就绪为 `skipped`/`dependency_blocked`。成功响应仅含 `plans`，
  每项含 `target` 和覆盖全部阶段的 `stages`（含 `id`、`name`、`status`、`reason`）。空 findings 返回空
  `plans`；相同输入数组顺序稳定。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含资产发现、漏洞模板与攻击链编排的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
