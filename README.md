# RedForge

这是一个面向渗透测试与攻防演练的渗透测试与攻防演练平台。长期目标是提供资产发现与指纹识别、端口与服务测绘、漏洞模板匹配、凭证探测、载荷生成、攻击链编排、授权边界强制和结果评分，把攻防演练沉淀为可复用平台。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m redforge.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `REDFORGE_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 离线漏洞模板匹配

`POST /v1/vulnerabilities/match` 把已采集的 HTTP 观察与漏洞模板做纯本地匹配，不访问目标网络。请求体包含 `allow`、`deny`（沿用 `/v1/scope/evaluate` 的范围规则）、非空数组 `templates` 和 `observations`：

- 观察：唯一非空 `id`、`target`、100–599 的整数 `status`、字符串键值 `headers`、字符串 `body`。
- 模板：唯一非空 `id`、`name`、`severity`（`info`/`low`/`medium`/`high`/`critical`）、`logic`（`all`/`any`）、非空 `matchers`。
- 匹配器：`status`（`values` 非空整数数组）、`header`（`name`/`operator`/`value`，头名称不区分大小写）、`body`（`operator`/`value`）。`operator` 为 `equals`、`contains`（区分大小写的完整相等/子串）或 `regex`（Unicode 正则搜索）。

匹配前先用全部观察的 `target` 执行范围评估，任一目标被拒绝则整体返回 `403 scope_violation`，不返回部分结果。结构或类型不符、数组为空、`id` 重复、枚举非法、状态码越界、匹配值为空、正则非法时返回 `400 invalid_request`；请求体超过 1 MiB 返回 `413`。

响应仅含 `findings`，按观察顺序再按模板顺序列出命中组合；每项包含 `observation_id`、规范化 `target`、`template_id`、`name`、`severity` 与 `evidence`（按原次序的全部命中匹配器下标，未命中不占位）。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含资产发现、漏洞模板与攻击链编排的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
