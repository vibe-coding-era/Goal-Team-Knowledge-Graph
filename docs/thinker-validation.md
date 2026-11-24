# GTKG 与 Thinker 公开验证说明

两次完整 Rust 验证分别使用公开首份源码快照 `2f7859474219f034556ffd1e492960b70496cdc6`，以及基于 `2f68f74c1a63ce3aa1739af7019cfa705cd6842e` 完成本轮修改后冻结的工作区。

完整 Rust 验证之后，两条 Python 集成测试改为接受可配置的索引查询，使用说明同步更新。提交前使用默认查询和真实知识库复跑 Thinker 全套 141 项测试，全部通过。指定查询下的两条集成测试也通过，门禁解析器的 20 项测试全部通过。

## 两套原始结果

两个版本均完整覆盖同名的 276 个 Cargo 目标。计数取各目标最外层汇总，不重复累计嵌套子测试；两次原始 Cargo 进程均退出 **101**。

| 验证对象与条件 | 通过 | 失败 | 忽略 | 含失败目标 |
| --- | ---: | ---: | ---: | ---: |
| 公开首快照：干净源码，直接运行 Cargo | 893 | 146 | 14 | 70 |
| 发布前冻结工作区：先构建 CLI，再运行 Cargo | 937 | 104 | 14 | 46 |

目标级对照为：24 个从有失败变为零失败，46 个两边均有失败，206 个两边均为零失败，0 个新增失败目标。这些变化同时受到实现、测试输入和运行前置条件影响，不能全部归因为源码修复。当前工作区将两项混合的历史断言各自拆为独立用例，总用例数因此增加 2 条。

## 当前门禁的 942 表示什么

按照仓库中按目标及完整测试函数名登记的分类，当前门禁结果为 **942 通过、0 失败、14 忽略**：

- 99 条历史用例在本次原始 Cargo 中为 1 通过、98 失败；这些结果完整保留，原阶段验收另行处理。
- 6 条需要实际构建产物和摘要的用例在原始 Cargo 中失败，随后由同次构建和输入绑定的专用运行器逐条验证通过。
- 因此当前通过数为 `937 − 1 + 6 = 942`，失败数为 `104 − 98 − 6 = 0`；14 条原有忽略保持不变。

942 是上述规则下的当前门禁计数，原始 Cargo 的 104 条失败仍可与分类和补验逐条对应。验证入口、分类规则和复跑命令见[分版本验证说明](../scripts/validation/README.md)。

## 同一公开提交上的受控补验

| 补验条件 | 完整目标 | 通过 / 失败 / 忽略 | 范围 |
| --- | ---: | ---: | --- |
| CLI 前置条件成立后复跑 | 8 | 23 / 0 / 0 | 构建和 Cargo 均退出 0；源码字节前后一致 |
| 将检出位置移出系统临时目录 | 2 | 7 / 0 / 0 | 测试临时目录策略保持一致；源码字节前后一致 |

CLI 补验开始时程序已存在，显式构建前后摘要相同；其中旧耗时相等断言本次也通过，只能说明该断言的观测存在波动。补验驱动因同期辅助记录变化而退出 1，五个核心原始证据文件摘要均未改变；不能把整个证据目录描述为未变化。两项补验均单独保留，不覆盖或扣减第一轮全量失败。

## 历史材料与证明范围

99 条历史用例分布于 42 个目标。原阶段验收仍需对应的原始源码提交、冻结语料及原始制品或回执；公开快照不等同于更早阶段的源码。历史入口对这些原阶段任务做适用性预检时返回 blocked，缺提交或冻结材料时退出 2，没有以新生成的材料代替历史原件。

公开首快照上另行执行的原始 T01 用例通过 1 条；原始 E07 用例为 1 通过、1 失败，后者是旧生成器版本要求与公开快照实际版本不一致。它们只证明所选公开提交上的观察。现行规模用例通过也不代表旧的小规模性能门槛通过。公开分发边界见[源码同步说明](../SOURCE_SYNC.md)。

## 原始文件摘要

以下 SHA-256 对应未经改写的原始文件。原始日志和本机记录不随本文发布；摘要用于取得原件后核对字节身份，不代替原始记录。

| 原件 | SHA-256 |
| --- | --- |
| 公开全量报告 JSON | `c00cb6ceccad169d6965714d377439aac6637b82d238a582b8a2f3580e7e8a54` |
| 当前逐案结果 JSON | `1d05f275cee626c434632e1f28ded9ac0c0124fcd082a5ed292c42daee66a662` |
| 公开原始 Cargo 日志 | `f3a4d7e1878275120e7775e48e9b9fc38fe9926ce002a87f36870fa3930697ec` |
| 当前原始 Cargo 日志 | `52ab8e353f89d3bf9f2d0252464f50bc67a380ea88ef35adcf9f1cf71ccb4aeb` |

## 276 目标逐项对照

<details>
<summary>展开全部目标：通过 / 失败 / 忽略</summary>

“零失败”仅表示该目标外层失败计数为 0；原有忽略及每项功能的适用范围仍分别保留。

| Cargo 目标 | 公开首快照 | 冻结工作区 | 目标级变化 |
| --- | ---: | ---: | --- |
| `audit_followup_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `audit_hardening_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `audit_process_crash_contract` | 11 / 0 / 0 | 11 / 0 / 0 | 均为零失败 |
| `audit_recovery_anchor_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `audit_regression_contract` | 7 / 1 / 0 | 8 / 1 / 0 | 均有失败 |
| `code_extract_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `d05_browser_fixture_emitter` | 1 / 0 / 1 | 1 / 0 / 1 | 均为零失败 |
| `d05_integration_hardening_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `d05_projection_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `d05_review_regression_contract` | 13 / 0 / 0 | 13 / 0 / 0 | 均为零失败 |
| `d06_exclude_schema_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `d06_handler_lifecycle_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `d06_r10_rpc_error_contract` | 0 / 2 / 0 | 2 / 0 / 0 | 转为零失败 |
| `d06_r8_regression_contract` | 2 / 1 / 0 | 3 / 0 / 0 | 转为零失败 |
| `d06_r9_exact_read_contract` | 0 / 3 / 0 | 3 / 0 / 0 | 转为零失败 |
| `d06_registry_schema_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `d06_review_regression_contract` | 2 / 1 / 0 | 3 / 0 / 0 | 转为零失败 |
| `d06_stdio_parity_contract` | 1 / 3 / 0 | 4 / 0 / 0 | 转为零失败 |
| `d07_development_acceptance_contract` | 1 / 4 / 0 | 2 / 3 / 0 | 均有失败 |
| `d07_transport_identity_contract` | 0 / 3 / 0 | 2 / 1 / 0 | 均有失败 |
| `doc::gtkg_app` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `doc::gtkg_core` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `doc::gtkg_extract` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `doc::gtkg_protocol` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `doc::gtkg_testkit` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `e01_input_admission_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `e02_code_semantics_contract` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `e03_summary_supply_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `e04_semantic_gate_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `e05_graph_v2_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `e06_dependency_incremental_contract` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `e07_arch_docs_contract` | 1 / 1 / 0 | 2 / 0 / 0 | 转为零失败 |
| `f02_ranked_query_contract` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `f03_browser_runtime_lock_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `federation_sandbox_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `foundation_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `g02_no_db_runtime_dir_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `g04_browser_fixture_emitter` | 0 / 0 / 3 | 0 / 0 / 3 | 均为零失败 |
| `g04_renderer_replicable_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `h01_okf_conformance_contract` | 12 / 0 / 0 | 12 / 0 / 0 | 均为零失败 |
| `h02_okf_context_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `h02b_summary_frontmatter_contract` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `h03_a2ui_conformance_contract` | 10 / 0 / 0 | 10 / 0 / 0 | 均为零失败 |
| `h05_official_renderer_contract` | 1 / 0 / 1 | 1 / 0 / 1 | 均为零失败 |
| `h07_product_completion_contract` | 4 / 1 / 0 | 4 / 1 / 0 | 均有失败 |
| `i06_codex_wiki_contract` | 1 / 3 / 0 | 1 / 3 / 0 | 均有失败 |
| `k01_config_source_negative_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `k03_legacy_bundle_compatibility_contract` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `l01_source_inspect_presence_contract` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `l02_i06_evidence_security_contract` | 1 / 2 / 0 | 1 / 2 / 0 | 均有失败 |
| `l02_pixel_diff_adversarial_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `l03_bundle_digest_precedence_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `m01_pixel_diff_race_budget_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `m02_i06_root_portability_contract` | 0 / 3 / 0 | 1 / 2 / 0 | 均有失败 |
| `n01_publish_transaction_contract` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `n02_browser_writer_identity_contract` | 1 / 1 / 0 | 2 / 0 / 0 | 转为零失败 |
| `o01_publish_content_readback_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `o01_publish_readback_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `o02_identity_bound_compare_contract` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `o02_pixel_identity_transaction_contract` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `pipeline_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `protocol_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `sandbox_home_input_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `sandbox_levels_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `sandbox_policy_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `unit::gtkg` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `unit::gtkg_app` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `unit::gtkg_core` | 19 / 0 / 0 | 19 / 0 / 0 | 均为零失败 |
| `unit::gtkg_extract` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `unit::gtkg_protocol` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `unit::gtkg_testkit` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `v02_t00_profile_hard_gate_contract` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v02_t01_source_snapshot_contract` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v02_t02_typed_ir_contract` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v02_t03_okf_four_axis_contract` | 7 / 8 / 0 | 7 / 8 / 0 | 均有失败 |
| `v02_t04_corpus_freeze_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v02_t04_external_holdout_freeze_contract` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `v02_t05_local_resolver_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v02_t06_document_relations_contract` | 0 / 6 / 0 | 0 / 6 / 0 | 均有失败 |
| `v02_t07_context_pack_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v02_t08_transport_e2e_contract` | 0 / 3 / 0 | 2 / 1 / 0 | 均有失败 |
| `v02_t08_v2_transport_contract` | 1 / 2 / 0 | 1 / 2 / 0 | 均有失败 |
| `v02_t09_local_provider_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v02_t10_claim_verification_contract` | 0 / 8 / 0 | 0 / 8 / 0 | 均有失败 |
| `v02_t11a_structural_graph_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v02_t11b_knowledge_overlay_contract` | 0 / 10 / 0 | 0 / 10 / 0 | 均有失败 |
| `v02_t12a_structural_query_contract` | 4 / 1 / 0 | 4 / 1 / 0 | 均有失败 |
| `v02_t13_lifecycle_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v02_t14a_runtime_e2e_contract` | 1 / 1 / 0 | 1 / 1 / 0 | 均有失败 |
| `v02_t14b_local_wiki_a2ui_contract` | 0 / 4 / 1 | 0 / 4 / 1 | 均有失败 |
| `v02_t15c_local_okf_four_axis_contract` | 2 / 3 / 0 | 2 / 3 / 0 | 均有失败 |
| `v02_t15d_local_readiness_contract` | 1 / 1 / 0 | 1 / 1 / 0 | 均有失败 |
| `v03_a00_adapter_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_a01_native_adapter_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_a02_relationship_evidence_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_a02_scip_adapter_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_a03_lsp_adapter_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v03_a03_lsp_adapter_security_successor` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_a04_codegraph_adapter_contract` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v03_a05_graphify_adapter_contract` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v03_a05_graphify_adapter_security_successor` | 6 / 1 / 0 | 6 / 1 / 0 | 均有失败 |
| `v03_a06_adapter_verifier_contract` | 9 / 0 / 0 | 9 / 0 / 0 | 均为零失败 |
| `v03_a06_persisted_oracle_successor` | 15 / 0 / 0 | 15 / 0 / 0 | 均为零失败 |
| `v03_a06_sealed_input_successor` | 18 / 0 / 0 | 18 / 0 / 0 | 均为零失败 |
| `v03_a06_trusted_gate_successor` | 12 / 0 / 0 | 12 / 0 / 0 | 均为零失败 |
| `v03_b00_benchmark_plan_contract` | 1 / 5 / 0 | 1 / 5 / 0 | 均有失败 |
| `v03_b01_environment_contract` | 0 / 3 / 0 | 0 / 3 / 0 | 均有失败 |
| `v03_d03_architecture_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v03_i00_migration_contract` | 20 / 0 / 0 | 20 / 0 / 0 | 均为零失败 |
| `v03_i00_source_bound_attestation_v2` | 40 / 0 / 0 | 40 / 0 / 0 | 均为零失败 |
| `v03_i01_identity_join_contract` | 21 / 0 / 0 | 21 / 0 / 0 | 均为零失败 |
| `v03_i01_identity_join_successor_r2` | 18 / 2 / 0 | 18 / 2 / 0 | 均有失败 |
| `v03_p00_operation_profiles_contract` | 1 / 3 / 0 | 1 / 3 / 0 | 均有失败 |
| `v03_p00_runtime_regression_contract` | 0 / 2 / 0 | 0 / 2 / 0 | 均有失败 |
| `v03_p01_system_source_contract` | 2 / 3 / 0 | 2 / 3 / 0 | 均有失败 |
| `v03_p02_adapter_orchestration_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_p02_analysis_handlers_contract` | 3 / 1 / 0 | 3 / 1 / 0 | 均有失败 |
| `v03_p02_profile_successor` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_p02_security_matrix_successor` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v03_p02_selected_snapshot_binding_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p02_stored_plan_binding_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p03_chain_forgery_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_p03_context_summary_handlers_contract` | 3 / 1 / 0 | 3 / 1 / 0 | 均有失败 |
| `v03_p03_profile_successor` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_p03_transport_parity_successor` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `v03_p03_trust_chain_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p04_chain_replay_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p04_legacy_boundary_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_p04_lifecycle_handlers_contract` | 3 / 1 / 0 | 4 / 0 / 0 | 转为零失败 |
| `v03_p04_profile_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p04_snapshot_migration_security_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_p04_transport_parity_successor` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `v03_p05_domain_handlers_contract` | 3 / 2 / 0 | 5 / 1 / 0 | 均有失败 |
| `v03_p05_domain_handlers_readback_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_p05_profile_successor` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_p06_current_transport_successor_r4` | 0 / 5 / 0 | 2 / 3 / 0 | 均有失败 |
| `v03_p06_current_transport_successor_r5` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_p06_current_transport_successor_r6` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_p06_explicit_profile_parity_successor` | 0 / 1 / 0 | 1 / 0 / 0 | 转为零失败 |
| `v03_p06_transport_e2e_contract` | 0 / 4 / 0 | 2 / 2 / 0 | 均有失败 |
| `v03_p06_transport_oracle_successor` | 0 / 2 / 0 | 2 / 0 / 0 | 转为零失败 |
| `v03_q00_binding_regression_contract` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_q00_index_schema_contract` | 4 / 1 / 0 | 5 / 0 / 0 | 转为零失败 |
| `v03_q01_lexical_index_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v03_q01_normalization_collision_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q02_adjacency_routing_contract` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v03_q03_continuation_security_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_q03_file_planner_contract` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q03_final_attack_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_q03_independent_review_repair_successor` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v03_q03_unicode_no_answer_successor` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v03_q04_authority_crash_recovery_successor` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v03_q04_authority_determinism_successor` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_authority_determinism_successor_r15` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_balanced_continuation_successor` | 5 / 1 / 0 | 5 / 1 / 0 | 均有失败 |
| `v03_q04_balanced_continuation_successor_r7` | 5 / 1 / 0 | 5 / 1 / 0 | 均有失败 |
| `v03_q04_balanced_continuation_successor_r8` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_boundary_successor` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_q04_claim_trust_successor` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v03_q04_claim_trust_successor_r21` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q04_continuation_attack_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q04_continuation_authority_successor` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_continuation_transport_successor` | 5 / 1 / 0 | 6 / 0 / 0 | 转为零失败 |
| `v03_q04_continuation_transport_successor_r12` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_file_graph_operations` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v03_q04_one_shot_continuation_successor_r19` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_one_shot_continuation_successor_r20` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_q04_previous_page_schema_successor_r18` | 2 / 1 / 0 | 3 / 0 / 0 | 转为零失败 |
| `v03_q04_public_schema_successor` | 1 / 1 / 0 | 2 / 0 / 0 | 转为零失败 |
| `v03_q04_public_schema_successor_r10` | 1 / 2 / 0 | 3 / 0 / 0 | 转为零失败 |
| `v03_q04_schema_runtime_parity_successor` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v03_q04_transport_process_successor_r17` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v03_q05_cold_build_budget_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q05_cold_metric_boundary_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q05_cold_metric_boundary_successor_r4` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q05_manifest_cache_security_successor` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v03_q05_query_budget_contract` | 3 / 1 / 0 | 3 / 1 / 0 | 均有失败 |
| `v03_q05_scale_budget_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q05_structural_scale_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_q06_equivalence_successor_r3` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_q06_query_index_equivalence` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u00_package_contract` | 2 / 1 / 0 | 3 / 0 / 0 | 转为零失败 |
| `v03_u01_fixed_temp_lifecycle_successor_r7` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u01_fixed_temp_parent_security_successor_r7` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u01_fixed_temp_parent_successor_r7` | 3 / 1 / 0 | 4 / 0 / 0 | 转为零失败 |
| `v03_u01_home_policy_successor_r5` | 2 / 1 / 0 | 3 / 0 / 0 | 转为零失败 |
| `v03_u01_installer_contract` | 0 / 2 / 0 | 0 / 2 / 0 | 均有失败 |
| `v03_u01_installer_mode_successor_r3` | 0 / 1 / 0 | 0 / 1 / 0 | 均有失败 |
| `v03_u01_installer_security_successor_r2` | 0 / 3 / 0 | 0 / 3 / 0 | 均有失败 |
| `v03_u01_isolated_root_successor_r4` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_u01_parent_binding_successor_r6` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_u01_raw_entrypoints_fixed_normal_successor_r7` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u01_raw_entrypoints_normal_successor_r5` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u01_raw_path_normal_build` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u02_assistant_installer_contract` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v03_u02_assistant_installer_security_successor` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v03_u02_atomic_cas_json_successor` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v03_u02_ownership_bounds_successor` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v03_u02_postexchange_cas_successor` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u03_explorer_contract` | 0 / 1 / 1 | 0 / 1 / 1 | 均有失败 |
| `v03_u03_explorer_successor_r3` | 3 / 0 / 1 | 3 / 0 / 1 | 均为零失败 |
| `v03_u04_evidence_drawer` | 2 / 0 / 1 | 2 / 0 / 1 | 均为零失败 |
| `v03_u04_evidence_drawer_context_r6` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_u04_evidence_drawer_parent_auth_r7` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_u04_evidence_drawer_security_r3` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v03_u04_evidence_drawer_security_r4` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v03_u04_evidence_drawer_security_r5` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v03_u04_evidence_drawer_successor_r2` | 2 / 0 / 1 | 2 / 0 / 1 | 均为零失败 |
| `v03_u05_docs_as_tests` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v03_u06_local_e2e` | 0 / 1 / 1 | 0 / 1 / 1 | 均有失败 |
| `v03_u06_local_e2e_successor_r2` | 0 / 1 / 1 | 0 / 1 / 1 | 均有失败 |
| `v04_analysis` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_authoring` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_authoring_readonly` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_binding` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v04_binding_batch` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_binding_dynamic` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_binding_review` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v04_context_pack_r2` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_entrypoints` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v04_graph_context` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_graph_read` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_index` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v04_index_review` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v04_knowledge` | 11 / 0 / 0 | 11 / 0 / 0 | 均为零失败 |
| `v04_knowledge_calls` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v04_knowledge_constraints` | 3 / 0 / 0 | 3 / 0 / 0 | 均为零失败 |
| `v04_knowledge_spans` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v04_knowledge_views` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v04_knowledge_views_constraints` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_box_review_r3` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_contract` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_fixture` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_graph` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_packages` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `v04_lifecycle_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_pack_integration` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_partial_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_payload` | 7 / 0 / 0 | 7 / 0 / 0 | 均为零失败 |
| `v04_payload_scope` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_plan_context` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_posting_decoder_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_posting_partition` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_posting_partition_review` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_query` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_query_context_limit_r12` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_query_graph_admission_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_query_graph_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_query_partial` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_query_resume` | 1 / 0 / 1 | 1 / 0 / 1 | 均为零失败 |
| `v04_query_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_query_schema_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_reviewed_query_boundaries` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_reviewed_query_fixture` | 0 / 0 / 0 | 0 / 0 / 0 | 均为零失败 |
| `v04_reviewed_query_r12` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_selective_policy` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_selective_review` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_semantic_lifecycle` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_semantic_lifecycle_adversarial` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_semantic_pack_integration_r2` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_semantic_projection` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_semantic_projection_adversarial` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v04_semantic_projection_review` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_semantic_projection_review_r2` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_semantics` | 6 / 0 / 0 | 6 / 0 / 0 | 均为零失败 |
| `v04_semantics_edges` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v04_semantics_go_imports` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_semantics_review` | 5 / 0 / 0 | 5 / 0 / 0 | 均为零失败 |
| `v04_source` | 8 / 0 / 0 | 8 / 0 / 0 | 均为零失败 |
| `v04_source_no_fetch` | 1 / 0 / 1 | 1 / 0 / 1 | 均为零失败 |
| `v04_source_posting_budget_r12` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_source_posting_budget_review_r12` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |
| `v04_t08_entrypoints_review` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_views_code_preservation_review` | 2 / 0 / 0 | 2 / 0 / 0 | 均为零失败 |
| `v04_views_review` | 4 / 0 / 0 | 4 / 0 / 0 | 均为零失败 |
| `workspace_gate_contract` | 1 / 0 / 0 | 1 / 0 / 0 | 均为零失败 |

</details>
