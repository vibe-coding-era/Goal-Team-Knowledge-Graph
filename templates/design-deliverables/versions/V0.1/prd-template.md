---
type: knowledge
title: "GTKG PRD Template"
description: "用于编制 Goal-Team Knowledge Graph 产品需求文档 V0.1 的 OKF v0.2 模板；仅定义结构、填写规则和可追踪字段，不包含 PRD 正文。"
resource: "./prd-template.md"
tags:
  - gtkg
  - prd
  - product-requirements
  - template
  - okf-v0.2
generated: true
verified: false
status: draft
sources:
  - id: "R3.3-D1"
    kind: "confirmed-design-baseline"
    title: "GTKG R3.3-D1 详细设计基线"
okf_version: "0.2"
gtkg:
  schema: "gtkg.design-deliverable-template/v1"
  document_kind: "prd-template"
  template_id: "gtkg-prd"
  template_version: "0.1.0"
  source_baseline:
    id: "R3.3-D1"
    state: "confirmed"
  intended_output:
    document_id: "GTKG-PRD"
    version: "V0.1"
    format: "OKF Markdown"
  immutable_release: true
  progressive_loading:
    level: "L1"
    summary_first: true
    sections_addressable: true
---

# {{产品名称}} PRD {{文档版本}}

> 模板状态：仅定义 PRD 的结构与填写合同。所有 `{{...}}` 均为待填写槽位，不得把模板占位符视为已确认需求或完成证据。

## 0. 模板使用合同

### 0.1 输出约束

- 输出文档必须继续使用 OKF v0.2 YAML Frontmatter。
- `sources` 必须保留 `R3.3-D1`，新增来源只能追加，不得覆盖原始来源。
- 输出必须绑定本模板的 exact `template_id`、`template_version` 和 manifest digest。
- 已发布版本不可原位修改；人工修改必须进入 draft，并派生新的文档版本。
- `confirmed`、`verified`、`implemented`、`released` 必须分别记录，不得互相替代。
- 未决项保持 `open | blocked | deferred`，不得静默补全为已决定事实。

### 0.2 稳定 ID 规则

| 对象 | ID 格式 | 示例占位 | 不变量 |
|---|---|---|---|
| Persona | `PER-###` | `PER-001` | 发布后不得复用 |
| JTBD | `JOB-###` | `JOB-001` | 必须绑定 Persona |
| 场景 | `SCN-###` | `SCN-001` | 必须绑定触发条件和目标 |
| 用户故事 | `US-###` | `US-001` | 必须绑定 Persona、场景和需求 |
| Journey | `JRN-###` | `JRN-001` | 每一步必须引用需求或失败模式 |
| 功能需求 | `FR-<DOMAIN>-###` | `FR-CORE-001` | 必须有消费者、revision 和 AC |
| 非功能需求 | `NFR-<DOMAIN>-###` | `NFR-PERF-001` | 必须有量化 Oracle |
| 验收条件 | `AC-<REQ-ID>-##` | `AC-FR-CORE-001-01` | 必须可观察且可判定 |
| 失败模式 | `FM-###` | `FM-001` | 必须定义显式产品行为 |
| 依赖 | `DEP-###` | `DEP-001` | 必须有 Owner 和阻断范围 |
| 开放决策 | `OD-###` | `OD-001` | 必须有决策者和截止条件 |
| 里程碑 | `MS-###` | `MS-001` | 必须绑定退出条件 |
| 非目标 | `NG-###` | `NG-001` | 必须说明排除理由 |
| 风险 | `RSK-###` | `RSK-001` | 必须绑定触发器与缓解策略 |

稳定 ID 的内容发生实质变化时，提高 `revision`；废弃 ID 只能标记为 `deprecated`，不得分配给其他语义。

## 1. 文档控制

| 字段 | 值 |
|---|---|
| 文档 ID | `{{GTKG-PRD}}` |
| 文档版本 | `{{V0.1}}` |
| 文档状态 | `{{draft / review / confirmed / deprecated}}` |
| 产品版本 | `{{V0.1}}` |
| 来源基线 | `R3.3-D1` |
| 模板绑定 | `gtkg-prd@0.1.0 + {{template_manifest_digest}}` |
| 产品 Owner | `{{owner}}` |
| 架构 Owner | `{{architecture_owner}}` |
| 需求确认人 | `{{approver}}` |
| 创建时间 | `{{ISO-8601}}` |
| 最近修订时间 | `{{ISO-8601}}` |
| 替代文档 | `{{none / document_id@version}}` |

### 1.1 来源与事实分级

| 来源 ID | 类型 | revision / digest | 可支持的声明 | 当前状态 |
|---|---|---|---|---|
| `R3.3-D1` | confirmed baseline | `{{digest_or_reference}}` | `{{由该来源支持的范围}}` | confirmed |
| `{{SRC-002}}` | `{{user / standard / research / observation}}` | `{{revision_or_digest}}` | `{{claim_scope}}` | `{{observed / inferred / confirmed / stale}}` |

## 2. 产品摘要

### 2.1 一句话定义

`{{目标用户}}` 可以通过 `{{核心产品能力}}` 完成 `{{核心任务}}`，从而获得 `{{可观察价值}}`。

### 2.2 问题陈述

| 字段 | 填写内容 |
|---|---|
| 当前问题 | `{{可被来源证据支持的问题}}` |
| 受影响用户 | `{{Persona ID 列表}}` |
| 现有替代方案 | `{{现有行为或工具；未知则写 unknown}}` |
| 主要摩擦 | `{{时间、成本、可信度、安全或协作摩擦}}` |
| 不解决的后果 | `{{可观察后果}}` |

### 2.3 产品愿景

`{{描述产品希望形成的长期用户状态；不得写实现细节或未经确认的市场结论}}`

### 2.4 V0.1 产品结果

| 结果 ID | 期望结果 | 对应 Persona/JTBD | 量化信号 | 时间窗口 | 状态 |
|---|---|---|---|---|---|
| `OUT-001` | `{{outcome}}` | `{{PER-### / JOB-###}}` | `{{metric_and_threshold}}` | `{{window}}` | `{{proposed / confirmed}}` |

## 3. 用户与 Persona

为每个当前消费者建立 Persona；只有“未来可能使用”的角色标为 `backlog_candidate`。

### 3.1 Persona 卡

#### {{PER-001：Persona 名称}}

| 字段 | 内容 |
|---|---|
| ID / revision / 状态 | `{{PER-001 / 1 / proposed}}` |
| 角色与工作背景 | `{{context}}` |
| 当前目标 | `{{goal}}` |
| 关键痛点 | `{{pain}}` |
| 技术熟练度 | `{{level}}` |
| 权限与信任边界 | `{{authorization_boundary}}` |
| 成功定义 | `{{observable_success}}` |
| 当前消费者确认 | `{{consumer_confirmed: true / false}}` |
| 来源 | `{{source_ids}}` |

## 4. Jobs To Be Done

| JTBD ID | Persona | 触发情境 | 想完成的工作 | 期望结果 | 替代行为 | 状态 | 来源 |
|---|---|---|---|---|---|---|---|
| `JOB-001` | `{{PER-001}}` | `{{when}}` | `{{job}}` | `{{outcome}}` | `{{alternative}}` | `{{proposed / confirmed}}` | `{{SRC IDs}}` |

JTBD 句式：当 `{{情境}}` 时，我想 `{{完成的工作}}`，以便 `{{获得的结果}}`。

## 5. 使用场景

### 5.1 场景目录

| 场景 ID | 名称 | Actor | 触发条件 | 前置条件 | 目标 | 完成信号 | 优先级 |
|---|---|---|---|---|---|---|---|
| `SCN-001` | `{{scenario_name}}` | `{{PER-###}}` | `{{trigger}}` | `{{preconditions}}` | `{{goal}}` | `{{observable_end_state}}` | `{{Must / Should / Could}}` |

### 5.2 场景详情

#### {{SCN-001：场景名称}}

1. 起始状态：`{{state}}`
2. 用户触发：`{{action}}`
3. 产品行为：`{{business_behavior}}`
4. 可观察结果：`{{result}}`
5. 失败分支：`{{FM IDs}}`
6. 关联需求：`{{FR / NFR IDs}}`
7. 未知项：`{{unknowns_or_none}}`

## 6. 产品范围

### 6.1 V0.1 In Scope

| 范围 ID | 能力边界 | 当前消费者 | 来源 | 验收入口 | 状态 |
|---|---|---|---|---|---|
| `SCP-IN-001` | `{{included_capability}}` | `{{PER / JOB IDs}}` | `{{source_ids}}` | `{{AC IDs}}` | `{{proposed / confirmed}}` |

### 6.2 Out of Scope

| 范围 ID | 排除项 | 排除理由 | 未来进入条件 | 状态 |
|---|---|---|---|---|
| `SCP-OUT-001` | `{{excluded_capability}}` | `{{reason}}` | `{{admission_condition_or_never}}` | out_of_scope |

### 6.3 Backlog Candidate

| 候选 ID | 候选能力 | 缺失的 Consumer Gate 条件 | 重新评估触发器 |
|---|---|---|---|
| `BCL-001` | `{{future_capability}}` | `{{consumer / scope / AC / budget / exit condition}}` | `{{trigger}}` |

### 6.4 假设

| 假设 ID | 假设内容 | 影响需求 | 验证方法 | 失效后动作 | 状态 |
|---|---|---|---|---|---|
| `ASM-001` | `{{assumption}}` | `{{requirement_ids}}` | `{{method}}` | `{{replan / block / de-scope}}` | `{{open / confirmed / invalid}}` |

## 7. 产品能力地图

| 能力 ID | 能力名称 | 用户价值 | 对应场景 | 需求集合 | 优先级 | V0.1 状态 |
|---|---|---|---|---|---|---|
| `CAP-001` | `{{capability}}` | `{{value}}` | `{{SCN IDs}}` | `{{FR IDs}}` | `{{Must / Should / Could}}` | `{{in_scope / out_of_scope}}` |

## 8. 功能需求

### 8.1 功能需求目录

| Requirement ID | revision | 标题 | Domain | 当前消费者 | 优先级 | 状态 | AC |
|---|---:|---|---|---|---|---|---|
| `FR-CORE-001` | `1` | `{{requirement_title}}` | `{{domain}}` | `{{PER / JOB / SCN IDs}}` | `{{Must / Should / Could}}` | `{{proposed / confirmed / deferred / deprecated}}` | `{{AC IDs}}` |

### 8.2 单项需求卡

#### {{FR-CORE-001：需求标题}}

| 字段 | 内容 |
|---|---|
| ID / revision / 状态 | `{{FR-CORE-001 / 1 / proposed}}` |
| 来源 | `{{R3.3-D1 section / source IDs}}` |
| 当前消费者 | `{{PER / JOB / SCN IDs}}` |
| 用户价值 | `{{value}}` |
| 业务规则 | `{{rules}}` |
| 输入与前置条件 | `{{inputs_and_preconditions}}` |
| 产品行为 | `{{behavior_without_implementation_detail}}` |
| 可观察输出 | `{{observable_output}}` |
| 失败边界 | `{{failure_boundary_and_expected_user_behavior}}` |
| 数据与权限边界 | `{{data_and_authorization_surface}}` |
| 依赖 | `{{DEP IDs}}` |
| 验收条件 | `{{AC IDs}}` |
| 验证方式 | `{{review / contract / runtime / external readback}}` |
| Consumer Gate | `{{confirmed / blocked + missing fields}}` |
| 退出条件 | `{{fixed_exit_condition}}` |

## 9. 用户故事

| Story ID | Persona | 用户故事 | 关联场景 | 关联需求 | AC | 状态 |
|---|---|---|---|---|---|---|
| `US-001` | `{{PER-001}}` | 作为 `{{persona}}`，我希望 `{{capability}}`，以便 `{{value}}`。 | `{{SCN IDs}}` | `{{FR IDs}}` | `{{AC IDs}}` | `{{proposed / confirmed}}` |

禁止用用户故事替代完整的业务规则、失败边界或验收条件。

## 10. 用户 Journey

### {{JRN-001：Journey 名称}}

| 步骤 | 用户目标 | 用户动作 | 产品反馈 | 依赖状态 | 失败模式 | 关联需求 | Evidence 需求 |
|---:|---|---|---|---|---|---|---|
| 1 | `{{goal}}` | `{{action}}` | `{{feedback}}` | `{{state}}` | `{{FM IDs}}` | `{{FR IDs}}` | `{{observable_evidence}}` |

Journey 必须覆盖初始化、正常流程、空状态、处理中、失败、恢复和终态中适用的状态。

## 11. 失败模式与恢复体验

| Failure ID | 触发器 | 影响对象 | 产品可观察行为 | 用户恢复动作 | 数据一致性要求 | 关联需求 / AC |
|---|---|---|---|---|---|---|
| `FM-001` | `{{trigger}}` | `{{scope}}` | `{{visible_failure_behavior}}` | `{{retry / rollback / manual action / none}}` | `{{consistency_rule}}` | `{{FR / NFR / AC IDs}}` |

失败模式至少评估：无输入、输入不支持、格式损坏、权限不足、Git 漂移、模板漂移、Sandbox 保证不足、节点不可用、节点结果冲突、增量基线缺失、A2UI 不兼容、发布或 readback 失败。

## 12. 非功能需求

### 12.1 NFR 目录

| NFR ID | 类别 | 需求 | 测量口径 | 阈值 | 负载/环境 | 失败边界 | AC |
|---|---|---|---|---|---|---|---|
| `NFR-PERF-001` | `{{performance / security / reliability / usability / portability / maintainability / accessibility}}` | `{{requirement}}` | `{{metric_and_oracle}}` | `{{threshold}}` | `{{fixture_and_environment}}` | `{{fail_closed_behavior}}` | `{{AC IDs}}` |

### 12.2 必填类别

- 性能与规模：`{{文件量、仓库量、索引大小、首屏和增量口径}}`
- 确定性与一致性：`{{全量/增量、重试、多节点归并口径}}`
- 安全与隐私：`{{输入隔离、凭证、路径、网络和输出清理}}`
- 可用性与恢复：`{{失败可见性、重试、回滚、恢复点}}`
- 可访问性：`{{静态 Wiki 与 A2UI 的适用等级和 Oracle}}`
- 可移植性：`{{目标操作系统、架构、Renderer 和版本矩阵}}`
- 可维护性：`{{Schema、模板、协议向前兼容和迁移策略}}`

## 13. R3.3-D1 强制横切需求槽位

以下各组必须形成独立、可判定的 `FR`/`NFR` 和 `AC`，不能只写在架构说明中。

### 13.1 Git 强绑定

| 必填项 | Requirement ID | 待填写内容 | AC |
|---|---|---|---|
| Core/Skill 来源身份 | `FR-GIT-001` | `{{将 R3.3-D1 对来源 Git 身份的约束转录为产品行为}}` | `{{AC IDs}}` |
| 输入仓库身份 | `FR-GIT-002` | `{{commit/tree/dirty/submodule/path scope 的用户可观察语义}}` | `{{AC IDs}}` |
| 产物版本身份 | `FR-GIT-003` | `{{artifact manifest/commit/tag/receipt/activation 的产品语义}}` | `{{AC IDs}}` |
| 漂移与回滚 | `FR-GIT-004` | `{{漂移阻断、readback 和非破坏性回滚体验}}` | `{{AC IDs}}` |

必须另行声明本地写入、commit、push、tag、PR、Release、安装等授权面；不得由“生成文档”隐式取得外部写入权限。

### 13.2 Sandbox

| 必填项 | Requirement ID | 待填写内容 | AC |
|---|---|---|---|
| 保证等级 | `FR-SBX-001` | `{{SB0/SB1/SB2 的产品语义与适用边界}}` | `{{AC IDs}}` |
| 默认拒绝 | `FR-SBX-002` | `{{网络、凭证、HOME、执行、写路径和子进程边界}}` | `{{AC IDs}}` |
| 不可降级 | `FR-SBX-003` | `{{保证不可用时的 fail-closed 用户行为}}` | `{{AC IDs}}` |
| Receipt | `FR-SBX-004` | `{{用户如何识别实际采用的 Provider 与保证级别}}` | `{{AC IDs}}` |

### 13.3 无数据库

| 必填项 | Requirement ID | 待填写内容 | AC |
|---|---|---|---|
| 语义 SSOT | `FR-NODB-001` | `{{OKF 作为 canonical knowledge 的产品边界}}` | `{{AC IDs}}` |
| 文件投影 | `FR-NODB-002` | `{{JSON/NDJSON/YAML/HTML/A2UI 可删除重建语义}}` | `{{AC IDs}}` |
| 禁止项 | `FR-NODB-003` | `{{数据库、嵌入式 KV、向量库、broker 等禁止范围}}` | `{{AC IDs}}` |
| 离线重建 | `NFR-NODB-001` | `{{fresh clone 和删除缓存后的可验证重建口径}}` | `{{AC IDs}}` |

### 13.4 模板优先与版本化交付物

| 必填项 | Requirement ID | 待填写内容 | AC |
|---|---|---|---|
| 模板先决条件 | `FR-TPL-001` | `{{无 exact 模板锁时禁止生成的行为}}` | `{{AC IDs}}` |
| Exact 解析 | `FR-TPL-002` | `{{version + manifest digest；禁止浮动引用}}` | `{{AC IDs}}` |
| 人工修改 | `FR-TPL-003` | `{{draft/derive/stable slot override 的用户流程}}` | `{{AC IDs}}` |
| 不可变版本 | `FR-TPL-004` | `{{versions 目录和 CURRENT 发现指针的产品行为}}` | `{{AC IDs}}` |
| 提前获取 | `FR-TPL-005` | `{{Agent/人工 prefetch、读取和引用模板的体验}}` | `{{AC IDs}}` |

### 13.5 A2UI 与前端复刻证据

| 必填项 | Requirement ID | 待填写内容 | AC |
|---|---|---|---|
| Frontend Semantic IR | `FR-A2UI-001` | `{{框架中立语义/视觉/交互表达}}` | `{{AC IDs}}` |
| A2UI 投影 | `FR-A2UI-002` | `{{锁定 schema/catalog/renderer 后生成 surface 的产品行为}}` | `{{AC IDs}}` |
| 动态加载 | `FR-A2UI-003` | `{{manifest、capability、surface、data/action 的渐进加载体验}}` | `{{AC IDs}}` |
| 兼容映射 | `FR-A2UI-004` | `{{exact/approximation/unsupported 的呈现和阻断语义}}` | `{{AC IDs}}` |
| 证据分级 | `FR-A2UI-005` | `{{四级证据状态及禁止越级规则}}` | `{{AC IDs}}` |
| 复刻验收 | `NFR-A2UI-001` | `{{renderer/browser/viewport/DPR/theme/locale/state/fixture/threshold 的精确口径}}` | `{{AC IDs}}` |

## 14. CLI、MCP 与多节点产品面

本节只写用户可观察合同；命令解析、crate 和内部模块归入架构设计。

| Surface ID | 用户入口 | 用户任务 | 输入合同 | 可观察输出 | 错误合同 | 关联需求 |
|---|---|---|---|---|---|---|
| `SUR-CLI-001` | `{{CLI operation}}` | `{{job}}` | `{{schema_ref}}` | `{{response}}` | `{{error_envelope}}` | `{{FR IDs}}` |
| `SUR-MCP-001` | `{{MCP tool}}` | `{{job}}` | `{{same_schema_ref}}` | `{{same_semantics}}` | `{{same_error_envelope}}` | `{{FR IDs}}` |
| `SUR-NODE-001` | `{{node address/profile}}` | `{{job}}` | `{{node_lock}}` | `{{receipt}}` | `{{conflict/failure}}` | `{{FR IDs}}` |

需明确覆盖：单二进制、CLI/MCP 1:1 语义、多实例逻辑地址、Coordinator 单写者、Worker 能力边界、provider pinning、纯工作单元重试以及结果冲突阻断。

## 15. 可判定验收条件

### 15.1 AC 模板

#### {{AC-FR-CORE-001-01：验收条件标题}}

| 字段 | 内容 |
|---|---|
| Requirement revision | `{{FR-CORE-001@r1}}` |
| 场景 / Persona | `{{SCN / PER IDs}}` |
| 输入与前置条件 | `{{exact_input_and_preconditions}}` |
| 触发动作 | `{{user_or_system_action}}` |
| 业务行为 | `{{required_behavior}}` |
| 可观察结果 | `{{value/status/artifact/UI/readback}}` |
| 判定 Oracle | `{{comparison_rule_or_threshold}}` |
| 失败边界 | `{{explicit_failure_result}}` |
| Evidence 类型 | `{{document review / contract / runtime / browser / external readback}}` |
| 目标环境 | `{{environment_identity_or_open_decision}}` |
| 当前状态 | `{{draft / confirmed / blocked / not_run / passed / failed}}` |

### 15.2 Given/When/Then 表达

```text
Given {{精确输入、身份、版本和前置状态}}
When  {{用户或系统动作}}
Then  {{业务可观察结果}}
And   {{失败边界、权限边界或持久化结果}}
```

AC 禁止使用“功能已完成”“测试退出码为 0”“看起来正确”等不可判定表述。

## 16. 依赖与授权面

| Dependency ID | 类型 | 依赖对象与 exact identity | Owner | 影响需求 | 不可用时行为 | 当前状态 |
|---|---|---|---|---|---|---|
| `DEP-001` | `{{standard / parser / OS / Git / renderer / host / repository}}` | `{{name + version/digest}}` | `{{owner}}` | `{{FR/NFR IDs}}` | `{{blocked / degraded / out_of_scope}}` | `{{open / confirmed / blocked}}` |

### 16.1 授权矩阵

| 动作类别 | 默认状态 | 授权主体 | 目标范围 | Readback 要求 | PRD V0.1 是否需要 |
|---|---|---|---|---|---|
| 本地文档生成 | `{{allowed / approval_required}}` | `{{actor}}` | `{{paths}}` | `{{local exact readback}}` | `{{yes/no}}` |
| Git init / commit | approval_required | `{{actor}}` | `{{repository/version}}` | `{{commit/tree}}` | `{{yes/no}}` |
| Git push / tag / note | approval_required | `{{actor}}` | `{{remote/ref}}` | `{{remote exact readback}}` | `{{yes/no}}` |
| PR / Release / 安装 | approval_required | `{{actor}}` | `{{external target}}` | `{{platform readback}}` | `{{yes/no}}` |

## 17. 开放决策

| Decision ID | 决策问题 | 可选方案 | 决策标准 | 影响需求 | 决策者 | 截止条件 | 默认行为 | 状态 |
|---|---|---|---|---|---|---|---|---|
| `OD-001` | `{{question}}` | `{{options}}` | `{{criteria}}` | `{{FR/NFR IDs}}` | `{{owner}}` | `{{date_or_milestone}}` | `{{block / defer / safe_default}}` | open |

R3.3-D1 中仍未确认的目标平台、首批解析器矩阵、A2UI renderer/catalog 和视觉阈值，应在本节拥有独立 Decision ID，不得静默写成已确认需求。

## 18. 风险与失败后果

| Risk ID | 风险描述 | 触发器 | 影响 | 概率 | 严重度 | 发现方式 | 缓解策略 | 残余风险 | Owner |
|---|---|---|---|---|---|---|---|---|---|
| `RSK-001` | `{{risk}}` | `{{trigger}}` | `{{impact}}` | `{{L/M/H}}` | `{{L/M/H/Critical}}` | `{{signal}}` | `{{mitigation}}` | `{{residual}}` | `{{owner}}` |

风险种子至少评估：不可信输入、路径逃逸、凭证泄漏、Sandbox 假保证、Git 身份漂移、模板漂移、数据库依赖误入、多节点非确定性、增量遗漏、A2UI 证据越级、静态 Wiki 注入和版本激活错误。

## 19. 产品指标

| Metric ID | 指标 | 用户价值假设 | 计算口径 | 基线 | V0.1 目标 | 数据来源 | 防误导说明 |
|---|---|---|---|---|---|---|---|
| `MET-001` | `{{metric}}` | `{{linked_outcome}}` | `{{formula}}` | `{{known / unknown}}` | `{{target}}` | `{{source}}` | `{{guardrail}}` |

在“不使用数据库”的约束下，指标证据的保存和重建机制必须引用普通文件或外部可信 Evidence，不能反向引入状态数据库。

## 20. 里程碑与产品退出条件

| Milestone ID | 名称 | 产品交付范围 | 前置依赖 | 退出条件 | 非退出项 | 状态 |
|---|---|---|---|---|---|---|
| `MS-001` | `{{milestone}}` | `{{requirement_ids}}` | `{{DEP / OD IDs}}` | `{{observable_product_exit_conditions}}` | `{{not implied: runtime/release/install...}}` | `{{planned / ready / blocked / complete}}` |

里程碑必须分别陈述：设计确认、Development、runtime validation、business validation、Release、发布和安装；不得因其中一项完成而推断其余项目完成。

## 21. 非目标

| Non-goal ID | V0.1 不提供的能力 | 排除理由 | 防止误解的边界描述 | 未来进入条件 |
|---|---|---|---|---|
| `NG-001` | `{{non_goal}}` | `{{reason}}` | `{{boundary}}` | `{{condition_or_never}}` |

非目标必须覆盖 R3.3-D1 已排除的网络节点/远程 transport、数据库与 broker、全语言/全框架保证、泛化的 100% 像素复刻、CodeGraph/Qoder 兼容承诺以及未授权的 Git/Release/安装动作。

## 22. 需求追踪矩阵

| Source | Outcome | Persona/JTBD | Scenario | Requirement@revision | AC | Failure Mode | Architecture Decision | Milestone | 状态 |
|---|---|---|---|---|---|---|---|---|---|
| `R3.3-D1` | `{{OUT IDs}}` | `{{PER/JOB IDs}}` | `{{SCN IDs}}` | `{{FR/NFR IDs@revision}}` | `{{AC IDs}}` | `{{FM IDs}}` | `{{ADR IDs}}` | `{{MS IDs}}` | `{{open / traced / blocked}}` |

每个 active Requirement 必须至少有一个当前消费者和一个可判定 AC；不存在当前消费者的条目不得进入 V0.1 active scope。

## 23. Consumer Gate

| Requirement ID | consumer_confirmed | in_locked_scope | acceptance_observable | budget_assigned | exit_condition_defined | 准入结果 | 缺口 |
|---|---:|---:|---:|---:|---:|---|---|
| `{{FR/NFR ID}}` | `{{true/false}}` | `{{true/false}}` | `{{true/false}}` | `{{true/false}}` | `{{true/false}}` | `{{active / backlog_candidate / blocked}}` | `{{missing conditions}}` |

只有五项全部为 `true` 的需求才能进入后续 Development TaskExactSet；本 PRD 模板本身不创建 TaskExactSet，也不授权开发。

## 24. 变更影响

| Change ID | 原 revision | 新 revision | 变更原因 | 影响对象 | 是否范围漂移 | 需要的重新确认 | 状态 |
|---|---|---|---|---|---|---|---|
| `CHG-001` | `{{version/revision}}` | `{{version/revision}}` | `{{reason}}` | `{{requirements/AC/architecture/milestones}}` | `{{yes/no}}` | `{{approver/action}}` | `{{proposed / confirmed}}` |

## 25. 确认记录

| 角色 | 确认对象 | revision / digest | 结论 | 开放缺口 | 时间 |
|---|---|---|---|---|---|
| 产品 Owner | `{{PRD}}` | `{{revision/digest}}` | `{{confirmed / changes_requested}}` | `{{OD / GAP IDs}}` | `{{ISO-8601}}` |
| 架构 Owner | `{{PRD-to-architecture input}}` | `{{revision/digest}}` | `{{accepted_input / changes_requested}}` | `{{OD / GAP IDs}}` | `{{ISO-8601}}` |
| 用户/业务确认人 | `{{V0.1 scope and AC}}` | `{{revision/digest}}` | `{{confirmed / changes_requested}}` | `{{OD / GAP IDs}}` | `{{ISO-8601}}` |

## 26. PRD 完整性检查表

- [ ] Frontmatter 使用 OKF v0.2，并绑定 `R3.3-D1`。
- [ ] 模板使用 exact version + manifest digest，而不是 `latest/current/main`。
- [ ] Persona、JTBD、场景、Journey 和失败模式均有稳定 ID。
- [ ] 每项功能与非功能需求有来源、revision、当前消费者、状态和退出条件。
- [ ] 每项 active Requirement 至少绑定一个可判定 AC。
- [ ] In Scope、Out of Scope、Backlog Candidate 和非目标互不混淆。
- [ ] Git、Sandbox、无数据库、模板版本化和 A2UI 已形成独立需求与 AC。
- [ ] 外部写入、Git、Release 和安装授权面已显式声明。
- [ ] 开放决策没有被伪装成已确认事实。
- [ ] 产品、运行、业务、Release、发布和安装状态保持正交。
- [ ] 追踪矩阵没有 orphan Requirement 或 orphan AC。
- [ ] 文档仍处于 Discussion/Design 产物范围，没有隐式授权 Development。

