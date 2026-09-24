---
type: Reference
title: CodeGraph 与 Qoder RepoWiki 产品参考
description: 面向 GTKG 产品定义的竞品能力拆解、取舍矩阵与可直接使用的参考文案。
resource: ./CodeGraph-Qoder-RepoWiki-reference.md
tags: [gtkg, codegraph, qoder, repowiki, product-reference]
status: stable
sources:
  - resource: https://github.com/codegraph-ai/CodeGraph/blob/489ccf1612555510f8367e3e673181f6a1275fe4/README.md
    author: codegraph-ai
  - resource: https://docs.qoder.com/user-guide/repo-wiki
    author: Qoder
  - resource: https://docs.qoder.com/cli/repo-wiki
    author: Qoder
okf_version: "0.2"
gtkg:
  schema: gtkg.product-reference/v1
  document_version: "1.0.0"
  reviewed_at: "2026-08-22"
  evidence_scope: informative-only
---

# CodeGraph 与 Qoder RepoWiki 产品参考

## 1. 使用边界

本文是 GTKG 产品文案与设计取舍的 informative reference，不是运行时依赖、
兼容性声明或对第三方产品的完整评测。CodeGraph 事实锁定到
`489ccf1612555510f8367e3e673181f6a1275fe4`；Qoder 官方文档按
2026-08-22 的公开页面记录。第三方后续变化不自动改变 GTKG 的验收合同。

## 2. CodeGraph：可吸收的产品思想

CodeGraph 把代码解析成 symbol、import、call 与 dependency graph，再把相关上下文
通过 MCP/LSP 提供给编码 Agent。其官方能力面还包括全量/增量重索引、修改影响分析、
模块摘要、设计文档索引、doc-to-code 验证、design gap 与架构文档生成。

对 GTKG 最有价值的不是某个 UI，而是三条产品原则：

1. 先形成可查询的语义图，再为 LLM 组装与意图相关的上下文；
2. 增量更新必须沿依赖关系计算影响面，而不是只看修改文件；
3. 架构文档应可由当前代码图重建，并能反向发现文档与代码的漂移。

CodeGraph 的 RocksDB、向量库、自动模型下载和常驻服务不是 GTKG 的实现基线。
GTKG 保持“OKF + 普通文件 + 独立 NDJSON/JSON 索引”的 no-database 边界。

## 3. Qoder RepoWiki：可吸收的产品思想

Qoder RepoWiki 面向 Git 项目生成结构化 Wiki，并在代码或文档发生变化时更新受影响
内容。官方 `wiki_plan.yaml` 可声明模板、写作目标、页面白名单以及 scope 的
include/exclude；人工修改会被识别和保护。官方 CLI 的 `qoder wiki --repo` 可重复传入
以处理多个仓库，并支持 branch、language 与 regenerate。

对 GTKG 最有价值的原则是：

1. 初次全量生成与后续受影响内容更新是同一产品闭环；
2. 路径范围、职能、文档目标必须持久化，而不是只存在于一次请求里；
3. Wiki 目录与知识文档应能进入 Git，同步与恢复都保留明确身份；
4. 人工知识和生成知识需要不同的覆盖策略与 provenance。

Qoder 的账号、Credits、云端团队同步和自动组件更新不属于 GTKG 本地 Development
验收；GTKG 也不以这些外部服务证明自身能力。

## 4. GTKG 取舍矩阵

| 参考能力 | GTKG 采用方式 | 当前边界 |
|---|---|---|
| 语法树与 symbol/import/call graph | Rust/Python/TypeScript/JavaScript 静态语义 + `indexes/graph.ndjson` | 不宣称覆盖 CodeGraph 的全部语言与分析器 |
| 全量/增量重索引 | content/source lock + dependency invalidation + immutable bundle | 只消费锁定 Git 对象，不监控未提交工作树 |
| 影响分析 | changed source 与依赖传播 exact-set | 更深控制流/数据流仍需独立基准 |
| 架构文档生成 | `agent.md`、`claude.md`、`rules.md`、`architecture.md`、`design.md` 差异化生成 | 文档只陈述静态与 accepted-summary 证据 |
| Wiki plan / scope | `gtkg.config/v2` 持久化 repo/path `role/include/exclude` | 不复刻 Qoder 私有配置或云同步协议 |
| 多仓输入 | `source.inspect` 多 repository + bundle compare | compare 是已验证 bundle 级，不是远端 Git mirror |
| Wiki 分享与恢复 | 静态文件、Git、snapshot create/verify/restore | S4 远端发布与真实宿主加载需单独授权 |
| 数据库与向量存储 | 不采用 | no-DB 是强门禁，不以隐藏缓存替代文件证据 |

## 5. GTKG 正式参考文案

> GTKG 是一个本地优先、强绑定 Git 身份的文件化知识工程工具。它借鉴
> CodeGraph 的代码语义图与影响分析思路，以及 Qoder RepoWiki 的结构化 Wiki、
> 路径规划和增量更新思路，把文档与代码转换为 Google OKF v0.2 知识文档、
> 独立索引、文档化知识图谱、五类版本化架构视图、静态 Wiki，以及可由
> Google A2UI v0.9.1 官方 Basic Catalog renderer 消费的 A2UI stream 投影。全量、增量、多仓比较与
> snapshot 恢复均绑定明确 digest；生成证据、renderer 证据、发布证据和业务证据
> 分轴记录，不相互替代。

## 6. 来源

- CodeGraph README：上述固定 commit 的官方仓库页面。
- Qoder Repo Wiki：<https://docs.qoder.com/user-guide/repo-wiki>。
- Qoder CLI RepoWiki：<https://docs.qoder.com/cli/repo-wiki>。
