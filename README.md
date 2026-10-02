# RedForge

这是一个面向渗透测试与攻防演练的渗透测试与攻防演练平台。长期目标是提供资产发现与指纹识别、端口与服务测绘、漏洞模板匹配、凭证探测、载荷生成、攻击链编排、授权边界强制和结果评分，把攻防演练沉淀为可复用平台。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m redforge.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `REDFORGE_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 授权边界判定

`POST /v1/scope/evaluate` 对目标范围做统一的授权前置判定，不发起网络请求、不写入持久化状态。请求体为 JSON 对象，含 `allow`、`deny`、`targets` 三个数组（各不超过 1000 项），元素支持 IPv4、IPv6、CIDR、DNS 主机名，规则额外支持 `*.example.com` 通配。响应为 `{"decisions": [...]}`，按 `targets` 顺序给出每项的 `original`、`normalized`、`allowed`、`reason`、`matched_rule`。拒绝规则优先；网段目标须被某一允许网段完整包含且不与任何拒绝网段相交。请求非法时返回 400 `invalid_request`，请求体超过 1 MiB 返回 413 `request_too_large`，非 POST 方法返回 405 `method_not_allowed`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含资产发现、漏洞模板与攻击链编排的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
