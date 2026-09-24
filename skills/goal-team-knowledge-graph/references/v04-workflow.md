# V0.4 项目知识工作流

能力 profile：`GTKG-V0.4-KNOWLEDGE-QUALITY`。所有本文请求都使用 `gtkg.protocol/v2`，显式 payload revision `gtkg.knowledge-quality/v0.4-r1`。普通 V1/V2 payload 保持原路由。

## 只有一个目录时

先发现 Core 能力，再读取该目录的 Git commit/tree 身份。明确固定源码版本与输出 workspace；dirty 工作树不等于其 HEAD 内容。V0.4 capture 从锁定 Git blob 读取，不 checkout、不执行目标代码。非 Git 目录没有完整 Git 叶子分母，不能声称全树完整；能力不支持时保留该缺口。

当前 CLI 的授权根为 cwd。来源和输出不在同一根时，以二者明确的共同父目录作为本次调用 cwd，JSON 中仍传精确来源与输出路径；仅访问此次指定范围。后续操作可以回到输出 workspace。若返回的 FileReceiptRef 以先前 cwd 为基准，依据实际同一文件换成 workspace 相对路径并保留原 SHA，不能将路径或 digest 指向另一份对象。

先固定理解域与正文适用集合，再提取。不要按已支持格式反向缩减范围，不隐式选择 `static_transcription` 来替代用户的语义理解目标。

## Core 操作链

通用信封：`{protocol_version,operation_id,request_id,payload}`。CLI 用 `gtkg v2-op <operation> --profile <profile> --request <input.json> --output json`；输入文件通过 JSON 序列化保存。实际 schema 以本次 discovery 为准。

| 步骤 | 输入 / 输出 |
|---|---|
| capability.describe / core | payload含 revision、capability_profile；检查主语言、分析上下文、操作与质量边界 |
| source.capture / core | revision、repository_id、source_root、source_commit、expected_tree、output_path、policy；policy含revision/rules/archive_binary。默认空rules保留全部tracked路径。回读集合、正文/语义阶段和原因 |
| analysis.plan / core | revision、workspace_root、artifact_ref=source ledger；返回有完整selection manifest的计划 |
| analysis.build / core | artifact_ref=plan；返回候选facts和每个call-site的证明/unknown原因 |
| analysis.verify / core | artifact_ref=candidate；重放来源和关系，产生index_ref/graph_ref以及独立未验证质量轴 |
| graph.search / graph或core | revision、workspace_root、index_ref、query、query_policy、max_results、max_tokens、continuation；普通来源索引用 preferred_query_policy，受审知识索引用 knowledge_query_policy 与 query_index_ref |
| context.pack / core | 保留 inline query 输入；也可用 revision、workspace_root、artifact_ref 指向下述 PackRequest，消费已认证的查询计划与命中引用 |
| graph.explain / graph | revision、workspace_root、index_ref、source_path、call_id、max_depth、max_results；检查已确认调用投影，unknown仍可追溯到analysis candidate |
| graph.trace / graph | 同上，做有范围的文件级静态依赖追溯；不当作真实运行调用轨迹 |

正文、普通文件索引与图都绑定精确版本。被选 shard/对象缺失或摘要不符应失败；未读取的对象不声称当前健康。预算耗尽保留 partial 和累计计费，不能通过循环重置同一问题预算。缓存/续页 authority 是 workspace 私有运行身份，在构建/导入时初始化；只读查询不偷偷创建它。

## 项目解释与审阅

所有后续输入文件由 host 保存为**输入 JSON**，通过真实文件字节 SHA 构造 FileReceiptRef（`sha256:<64hex>`）；它们不自行成为 accepted OKF。

1. 准备 JobRequest：`{verified_ref,input}`。input包括job_id、goal=`semantic_understanding`、source_paths、understanding_items、prompt、policy、max_context_units≤8000、可选source_spans。窗口保留原始byte/line坐标；同一大文件只给部分窗口时，未给到的实现不得写成已知事实。
2. `summary.job.next` / authoring，payload为revision/workspace_root/artifact_ref=JobRequest。此Read操作返回 `job_artifact` 与 `persistence=host_staged_input`。保存该数据作为下一次输入，不能把未保存路径当成已创建收据。
3. 让真实作者消费该job的context/prompt/policy。保存候选 KnowledgeCandidate 与真实可得 GenerationExecutionRecord：job/context/prompt/policy/output摘要、作者模式、执行方、原始output、transcript及摘要、模型身份、usage。不可得usage用null；host观察不声称外部独立attestation。
4. ProposalRequest为`{job_ref,candidate,execution_record}`。调用 `summary.proposal.submit`；静态模式或缺执行记录不能闭合语义目标。
5. `summary.verification.next`给出精确claim摘要。两名与作者不同的审阅者各提交对同一proposal、完整claim分母的判断和原因。ReviewRequest为`{proposal_ref,reviews}`，经`summary.verification.submit`取得review artifact。
6. `summary.accept.v2`消费review artifact。Core重放整条链并写canonical OKF。受限predicate与解释性正文分开；更换否定、主体、目标或版本条件会使原审阅失效。重复ID/改写不能增加理解项分子。
7. ViewsRequest为`{verified_ref,input,accepted_refs}`；input声明project_name、inventory_id、understanding_items及modules。通过 `deliverable.derive` / templates 生成五类项目视图；源码/符号明细只保留一个入口，未覆盖的理解项与模块面显示unknown。导航字段来自调用方，不能冒充已验证业务事实。

若真实作者/审阅者不可用，停在准确的 `semantic_authoring_pending` 或 review pending，保留可恢复输入与资料。不要填写虚构 model/usage/reviewer 记录来推进。

## 包、迁移与导入

`build.finalize.v2` / core 消费输入 ref。旧 FinalizeRequest 保持兼容。要使受审知识参与检索，使用 `schema=gtkg.qk.semantic-finalize/v1`，以及 verified_ref、accepted_refs、views_ref、output_path、可选 predecessor。输出限制在 workspace 的 `.gtkg/qk/bundles/`；manifest 闭包包含来源、accepted OKF、视图、索引与图，保持包内相对路径。新 manifest 分开记录 `base_index_ref`、`query_index_ref` 与 `semantic_catalog_ref`，不改写原 VerifiedAnalysis 的来源索引身份。

`bundle.verify` / lifecycle 使用包workspace_root与包内manifest_ref，完整回放引用链，不需要原仓库，也不写query authority。V2既有operation副作用声明保持，CLI仍应使用允许该操作的context。

`bundle.migrate.v1_to_v2` / lifecycle 消费 MigrationRequest（legacy_root、legacy_manifest_ref、可选source_ref），保留旧字节和legacy_unverified缺口；它不会将旧resolved改名为新证明。

`snapshot.restore` 的显式QK分支以包workspace_root/manifest_ref导入已验证的可移交包并初始化新的私有query authority；不更改Current或安装。私有authority/运行锁不属于导出闭包，旧workspace的cursor不能冒充新workspace身份。

最终交付须区分可移交包、知识理解项就绪、检索阈值、真实问答与业务验证。未完成独立gold/固定模型/原始运行时，G05/G06/G10保持not_run或blocked；不得用本地fixture替代真实项目评估，也不关闭历史B01/H2H阻塞。

## r9 查询与索引行为

较大的posting桶使用带摘要的子路由，只读取选中的hash分区；旧小桶保持可读，索引generation已更新。查询仍累计计入实际router/子分片/来源读取，冻结额度不变。候选或posting数量耗尽时，Core可以用剩余IO/时间额度返回已观察候选的来源片段，但保留`partial`、`ranking_complete=false`及`observed_candidates_provisional_scores`；这不表示完整全局top-K。continuation不刷新扫描预算。

## 显式查询策略 v2

先读取 `capability.describe` 的 `query_policies` 与 `preferred_query_policy`。当前优先选择 `gtkg.qk.query/v2`；只有请求明确携带该值才启用新策略，`v1` 继续可用。

v2在posting层先组合查询信号：同组替代词取并集，独立组优先取交集；交集为空时明确标记`union_fallback`。之后最多准入2000个不同候选块进行评分/读取。`posting_ids_observed`、`eligible_ids`、`filtered_ids`与`candidates`分别报告，不能把前筛命中ID当作已经评价的候选。全部实际posting读取、来源读取与续页仍共享原100000/5%及64MiB/5秒上限；过多eligible仍是partial。

v2可通过明确的兼容关系读取当前v1词法物化索引，索引字节保持原样；结果分别返回`index_projection_policy`与`query_policy`。未知组合失败，v1/v2续页互相拒绝。交集完成只表示按声明查询策略完成排序，不表示回答已正确或完整。

## 受审知识检索与引用式装包

完成真实生成、审阅和 accept 后，通过 semantic finalize 生成查询 overlay。查询使用 discovery 返回的 `knowledge_query_policy`（`gtkg.qk.query-reviewed-context/v1`），`index_ref` 指向 `query_index_ref`。普通来源 manifest 不能替代 overlay；空 accepted 集合明确表示语义知识不可用。

该策略同时匹配来源词项与受审正文。`evidence[].text` 始终是可按 byte/line/hash 回读的原文；`reviewed_contexts` 单独给出受审主张、推断状态、版本条件、审阅身份和来源引用。候选 summary、未经核验的 natural_language 与导航标题不进入受审正文索引。重复 accepted 主张不增加语义语料分母或累计加分。

查询返回 `pack_preparation`。Host 按以下顺序保存输入；Core 的只读查询不会代写这些文件：

1. 原样保存 `plan_json` 和 `hits_json` 两个 UTF-8 字符串，不重新格式化 JSON。
2. 分别按实际保存字节计算 `sha256:<64hex>`，构造 workspace 相对 FileReceiptRef。
3. 保存 `PackRequest`：`{schema:"gtkg.qk.context-pack-request/v1",plan_ref,hits_ref,pack_ticket,max_context_units:8000}`。ticket 原样取自本次 `pack_preparation`。
4. 将 PackRequest 的文件引用交给 `context.pack` 的 ArtifactPayload 分支。读取 `raw_evidence`、`summary_context`、`omitted` 与累计 `budget`。

装包只处理该认证批次，不重新搜索、排序或追加结构扩展。即使重新计算外层文件 SHA，修改 plan、hits 或 ticket 仍会被拒绝。它复核选中的索引、来源对象与 accepted 审阅链，保留已有审阅结论；装包本身不产生新的语义审阅。

原文、不同主张正文和版本条件共用最多 8,000 个 Unicode codepoint。原文可在合法字符边界截取，主张及其条件必须整条保留或整条省略。`citation_coverage_in_pack` 只有在全部原始引用区间被返回原文覆盖时才为 complete；缺少尾换行也保持 partial。不能通过缩短引用、丢弃条件或添加未读取的证据 ID 修正覆盖率。

来源和语义 posting 合计最多实际解码 100,000 行，并共享 2,000 候选、4 个初始信号组、2 次结构扩展、索引总字节 5% 与 64 MiB 较小值的 IO 额度、协作式 5 秒 Core 时间。引用式 pack 继承查询已消费额度；只读 verify 不创建私有准入凭据，导入完整回放后才重新准入。小索引必读认证头可能已超过严格 5% 额度，此时诚实返回 partial。

这些累计约束覆盖认证的线性查询→续页→终止装包链。旧 cursor 或 ticket 仍可重放，Host 负责跨重试和分叉的总成本；协作式时间检查不等于操作系统强制中断。私有 authority、准入凭据、cursor 和 ticket 均不作为可移交知识导出。普通文件完整性、受审链验证与实际问答质量分别报告。
