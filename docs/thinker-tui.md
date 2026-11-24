# Thinker 终端规格卡（T3）

实现基线：V0.5 §§7、10。目标是用键盘完成「查看建议 → 展开证据 → 纠正 → 核对结果」。界面只调用共享控制面，不运行建议里的命令，不管理独立数据库或观察器。

## 组件与入口

Python 3.9 标准库自绘终端：`termios`、`tty`、`select`、ANSI 清屏；纯文本输出可用于管道。采用标准库实现，减少安装依赖，无第三方组件库。独立入口由 `thinker tui` 调用 `tui.run(request, args)`；嵌入入口复用 `Session`，其中 `request(op, args) -> dict` 是已鉴权的共享控制客户端。

## 80 × 24

```text
Thinker · 项目 P · 任务 change-42
仓库 repo-a · refs/heads/main · 源码已观察 / 索引待对账
连接：已连接   焦点：时间线
──────────────────────────────────────────────────────────────────────────────
> 建议 rec-17 · impact-ab@2 · 待处理
  先跑 B 的集成测试，再确认影响范围
  证据 2 · 过期时间：2026-11-24T12:00:00Z
  [展开证据] [采纳] [忽略] [纠正]
执行者：正在评估 A 的改动范围
你：反馈已记录 · 结果尚未验证 · 未执行建议
──────────────────────────────────────────────────────────────────────────────
反馈 > 这次失败来自测试环境，需补可复现日志
Tab 切焦点  Enter 展开/确认  Esc 返回  ? 帮助  q 退出
```

窄屏只保留时间线；证据与判断版本是单独面板。正文按终端字符宽度换行，PgUp/PgDn 翻页；面板中 j/k 滚动。标题与状态行截断，不让 CJK 字符挤占相邻栏。

## 120 × 32（宽屏）

```text
Thinker · 项目 P · 任务 change-42                       仓库 repo-a / main
连接：已连接   焦点：时间线                              源码已观察 / 索引待对账
────────────────────────────────────────────────────────────────────────────────────────
> 建议 rec-17 · impact-ab@2 · 待处理                   │ 证据 / 版本
  先跑 B 的集成测试，再确认影响范围                    │ src-23  commit: fixed-sha
  [展开证据] [采纳] [忽略] [纠正]                      │ src/a.py:12–20
你：纠正：需补可复现日志                               │ CI run-104 · 未验证
思考者：反馈已记录 · 判断待复核                        │ 旧版本仍保留授权内标识
────────────────────────────────────────────────────────────────────────────────────────
反馈 >
Tab 切焦点  Enter 展开/确认  Esc 返回  ? 帮助  q 退出
```

## 状态与交互

| 状态 | 可见结果 | 可写动作 |
| --- | --- | --- |
| 加载 | 正在同步当前任务 | 禁用 |
| 正常 | 建议、版本、证据、效期与观察/索引状态 | 采纳、忽略、纠正；仅记录反馈 |
| 空 | 当前任务暂无建议 | 无 |
| 断线 | 已断线；已加载内容仅显示非敏感标识 | 禁用，重连后重新拉取快照 |
| 过期/撤回 | 已失效，请查看新版；不显示撤回正文 | 禁用 |
| 无权限 | 无权访问当前项目；清空标题、摘要和证据 | 禁用 |
| 浮层 | 帮助、证据、版本、纠正输入 | Esc 关闭；输入时普通字符不触发快捷键 |
| 待同步 | 正在确认反馈；保留同一幂等键以重试 | 不重复生成反馈 |

Tab 在时间线、操作、输入间切换；方向键/j/k 移动；Enter 展开或确认；e 打开证据；v 打开判断版本；a/i/c 分别采纳、忽略、纠正；m 标记当前快照已读；r 重连；? 帮助；q 退出。输入焦点时 a/i/c/m/q/? 都是正文。每次展开证据重新请求服务。提交携带 recommendation、judgment_revision、task 和 source triple，服务端再次比较版本；客户端也在提交前刷新。

快照携带游标；增量按事件 ID 去重。游标不可续读则重拉快照。服务事件只触发重新读取授权快照，避免把历史事件里的正文重新显示。退出不会停止控制面或观察器。

`timeline.read` 读取本人元数据；`timeline.mark` 仅 human/admin 可写。SQLite `timeline_reads` 按服务派生 scope、actor 和 task/repo/ref 保存单调游标，且不得超过该 scope 的事件高水位；它不保存正文。每批最多查询 200 张卡。忽略状态直接由 `core_feedback` 中已确认的 ignored 记录派生，按相同用户、任务、仓库、分支、建议 ID、判断版本过滤；客户端不能自行关闭卡片。重开仍关闭旧卡，新判断版本仍显示。SQLite 运行时须提供 JSON1（当前受测运行时已验证）。

来源或证据变化产生的 `open_questions` 显示为“待补证据”条目。旧判断正文不通过这些元数据条目恢复。已读状态只表示用户显式按 m 确认看过当前快照，不代表采纳或完成执行。

反馈去重包含当前租户、工作区、项目、仓库、分支、任务、建议与判断版本。确认丢失时，重连查询同身份的只读反馈回执；即使纠正已让原判断失效，仍可确认记录成功，回执不恢复旧判断权限或泄露正文。

## 验收与风险

| 风险 / AC | 可观察断言 | 验证方式 |
| --- | --- | --- |
| 终端注入 | ESC、OSC、CSI、C0/C1、双向控制字符不会进入渲染内容 | 单元 + PTY |
| 中文与缩窄 | 80×24、120×32 每行不超过可用列数且无越界 | 布局断言 + PTY |
| 双击/断线 | 未确认反馈重试使用相同 id；确认后不写第二份 | 控制客户端夹具 |
| 版本竞争 | 提交前刷新仍引用原版本；服务拒绝后显示失效 | 集成夹具 |
| 重连重复 | snapshot/replay 重复 event_id 只计一次 | Session 测试 |
| 越权/撤回 | 项目拒绝清空所有已加载正文；不回放旧 payload | Session 测试 |
| 键盘完整路径 | PTY 输入证据、纠正、提交、退出后读到确认 | 真实终端子进程 |
| 执行隔离 | 界面只发控制请求，无 shell/命令执行 | 调用记录断言 |

浏览器视口和 DOM 不适用：本任务为终端界面。像素复刻不适用：无用户视觉基线。真人耗时试用尚未执行；自动 PTY 用例不冒充真人可用性结论。

## 记忆边界

SQLite 判断和证据是唯一权威。记忆和 Wiki 都是可重建投影；读取前重新验证 scope、当前判断版本、证据有效状态和来源。记忆必须显式同意留存，Reflect 只生成候选。Forget 先设置本地墓碑并阻止读取，再通过有界 Outbox 投递清理后端；不宣称删除备份或审计。

Hindsight 为可选固定版本 v1.2.3 适配器。管理员显式 setup、数据分类白名单、远端处理 opt-in 后才允许调用；默认使用本地确定性后端。未配置、版本不符、异步写入尚未完成或后端故障均返回不可用/partial。不会上传本项目真实代码或会话做验收。

每个鉴权 scope 独立限制 Hindsight 的模型操作：`retain`、`recall`、`reflect` 每次上游 POST 各预留 **1 次操作**，单位为 `reserved_model_operations`。默认 UTC 周额度为 1,000 次、同时在途最多 2 次。管理员可在 `memory setup` 的原后端配置中设置 `weekly_model_operations`（0–100,000）及 `max_concurrent_model_operations`（1–16），也可在已有投影时调整这两项；0 周额度禁用新增模型操作。次数包含预留后失败、超时、无有效输出的请求，重试重新计数。它不是 token 数或货币金额；上游内部模型次数、实际 token 用量及费用不可观测，因此不宣称控制了实际金额。原有每次响应 token 上限继续适用。

预留在访问上游前，通过权威库同目录的 `state.sqlite.model-usage.sqlite` 独立 SQLite 事务完成，以 scope 和 UTC ISO 周记账。账本保留操作类型、次数、进程票据、时间，以及异步文档/作业标识、请求哈希和确认状态，不保存提示词、正文或凭据。进程重启、主事务回滚、重复 setup 不会重置周用量；UTC 周一开始新的周额度。跨线程及进程的并发检查与扣额度在同一个短事务内完成，远端慢读取不会持有权威库写锁，也不持有运行账本事务锁。并发限制同时计算本地在途调用与已提交但未确认终结的异步作业，同一异步作业不会重复占位。异步占位不会随提交进程退出而丢失；上游内部子模型调用数、同步请求超时后的执行状态仍不可观测。

正常请求结束释放并发票据；崩溃后，下一次预留会清理确认已退出进程的票据，但不退还周用量。仍存活的慢请求保守占位，不按墙钟超时猜测完成；无法确认退出或 PID 复用可能保留占位，需确认旧进程退出后重试。额度或并发不足、运行账本不可用时返回 partial，`partial_sources` 包含 `memory_model_budget`，被拒绝的投影保持待处理而不消耗重试次数。`memory status` 返回当前周用量、限制和在途数。后台配置/版本确认、删除及删除后 GET 确认不消耗模型额度；本地确定性后端没有模型调用，也不创建额度账本。保留授权的删除操作不会因模型额度耗尽受阻。

适配器依据 [v1.2.3 官方 OpenAPI](https://github.com/vectorize-io/hindsight/blob/v1.2.3/hindsight-docs/static/openapi.json)。远端配置需要 HTTPS、`api_key_env` 环境变量名、`processing_opt_in=true` 和 `remote_opt_in=true`；loopback 同样需要处理 opt-in，因为其模型后端可能位于远端。不会存储密钥明文。管理员示例：

```sh
bin/thinker memory setup --project demo --args '{"backend":"local"}'
bin/thinker memory retain --project demo --args '{"id":"decision-memory","kind":"observation","judgment_revision":"impact@1","evidence_ids":[],"consent":true,"data_class":"internal"}'
bin/thinker memory project --project demo
bin/thinker memory recall --project demo
bin/thinker memory wiki --project demo
bin/thinker memory forget --project demo --id decision-memory
```

新作用域第一次 `memory setup` 为 Hindsight 时，未指定 `retain_mode` 默认采用 `async`，适合较慢的本机模型。已经保存的旧配置若没有该字段，继续按 `sync` 运行，重跑 setup 或调整额度也不静默切换；显式 `"retain_mode":"sync"` 仍支持快速同步成功。已有投影的作用域不能静默切换模式。异步模式通过 v1.2.3 `RetainRequest.operation_id` 传入 scope 与 document 派生的确定 UUID，超时重试使用同一 UUID 和请求哈希。每次 `memory project` 至多查询一次该作业状态，必要时提交一次；成功入队仍返回 `awaiting` / `memory_async_pending`，不会成为 ready，也不消耗三次失败预算。后台 tick 至少间隔 5 秒，客户端无内部等待循环。

作业查询使用 `GET /v1/default/banks/{bank}/operations/{uuid}`。只有标识匹配的 `retain` / `batch_retain` 作业返回 `status=completed`、带时区的 `completed_at`，且子作业均完成，才确认投影；真实 v1.2.3 单条输入也可能返回 `batch_retain` 父作业。`pending`、`processing` 或不明完成字段保持阻断。404 / `not_found` 在留存时允许用同一 UUID 首次提交或幂等重试。确认 GET 不计模型额度，所有 POST 预留仍保守计入次数。只存在待完成异步记忆时，recall 也明确返回 partial，避免把缺失投影显示为完整结果。

POST 前先在独立运行账本提交意图，因此即使权威事务回滚或 HTTP ACK 丢失，删除也能识别可能迟到的 retain。Forget 立即设置本地墓碑，然后等待在途 retain 确认结束，再执行 DELETE 和 document GET 回读。已有提交意图但作业查询不到时不确认删除；不会为了完成清理而重新提交 retain。v1.2.3 的 `cancelled` 是协作取消，工作线程可能仍在写当前批次，所以该状态也保守阻断，不能充当安全删除的证明。未知、失配或失败作业不会让记忆进入上下文。

同步模式没有可查询的异步 UUID，所以也必须在额度准入后、POST 前持久记录 `sending` 意图；只有同步成功 ACK 才变为 `confirmed`。超时、异常或无法确认的 ACK 保持 `memory_sync_uncertain`：不自动重发该旧写，不释放它可能仍占用的模型并发名额，不发布该投影，也不把 DELETE/404 当成删除证明。Forget 立即本地阻读，却保持 `pending_delete`，不会先删后被迟到 retain 复活。该 Bank 的 Reflect 同时禁用，已有确认记忆的 canonical recall 仍可返回，但明确 partial。额度未准入时不会留下不确定写意图。

同步不确定状态没有自动清除或强制成功开关。管理员需在 Hindsight 端核对请求/工作线程，先确认旧写已不可能继续提交，再按授权清理旧 Bank 并核验；无法证明时隔离旧 Bank，保留本地墓碑及运行账，使用新的作用域和默认异步 Bank 重新留存已授权证据。不要删除运行账或直接改 SQLite 状态来解除屏障。这里说明的是处置边界，不宣称已删除上游备份、审计或仍在执行的旧请求。

`invalidate(db, scope)` 先阻断失效投影并排队清理，无网络调用；`tick(db)` 每次公平选择一个作用域的一个任务，持久化至少 5 秒退避，自动失败最多三次，之后等待显式 `memory retry`。pending 等待不计失败；长期未知的队首任务可能延迟该作用域后续留存，删除优先处理，不承诺自动完成时限。手动 project 最多 100 项且有批次时间预算。重复 forget 保留已确认的删除状态。Hindsight 删除后回读 document，仍存在时不得确认完成；备份和审计删除不在该确认范围。删除后派生摘要的新鲜度无法充分证明，因此存在历史墓碑的 Hindsight Bank 保守禁用 Reflect，需另行明确迁移后才能恢复。

本机验证覆盖确定性后端、Hindsight HTTP 协议夹具，以及真实 Unix socket、PTY 和 SQLite 回读。另用 Hindsight 1.2.3、PostgreSQL 和本地 Gemma 4 E2B 验证了异步保留、带出处的召回、反思候选与删除读回。AgentTeams 宿主实际嵌入、真人操作耗时及长期建议质量留待试点。候选需由有权人员检查，再决定是否发布。
