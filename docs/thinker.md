# Thinker 0.5 本地交接

从仓库根目录运行 `bin/thinker`，或使用 `python3 -m thinker`。运行环境为 Python 3.9+、SQLite、Git 和 Unix 域套接字。GTKG 的 Rust CLI 提供工程证据，Thinker 单独维护本地判断、权限和撤回记录。

## 初始化与启动

```sh
export THINKER_HOME="$(mktemp -d)"
bin/thinker init
bin/thinker serve --interval 2
```

第二个终端使用相同的 `THINKER_HOME`。持久化试用可设置固定的、用户独占的 0700 目录。服务使用独占文件锁；`--interval 0` 允许纯手动对账。Ctrl-C 结束观察服务。数据库与 operator.key 置于私有目录，MCP 进程应运行在只能访问所授令牌及 socket 的受控执行环境。拥有本机管理员文件读取能力的进程属于操作者信任边界。

```sh
bin/thinker repos add --project demo --repo gtkg --location "$PWD" \
  --args '{"refs":["refs/heads/main"],"paths":["VERSION","Cargo.toml"]}'
bin/thinker watch reconcile --project demo --repo gtkg
bin/thinker source read --project demo --repo gtkg --ref refs/heads/main --path VERSION
bin/thinker evidence capture --project demo --repo gtkg --ref refs/heads/main --path VERSION
bin/thinker context get --project demo --repo gtkg --ref refs/heads/main --task review
```

用 `repos add` 的 `adapter` 指定固定的 GTKG handoff 和已安装的二进制。Git 读源模式直接读取登记分支的提交对象。GTKG 索引模式额外校验返回片段和文件摘要。查询与反馈使用服务返回的完整 commit、证据 ID、判断版本。适配器示例：

```json
{"kind":"gtkg","handoff":"/absolute/knowledge-base.json","binary":"/absolute/gtkg"}
```

## 发布判断与反馈

所有双层子命令接受 `--args` JSON，或 `--args -` 从标准输入读取。标准输出是结果 JSON。请求错误退出 2；`context get --require-fresh` 在返回的上下文不完整或过期时退出 3。源码捕获会返回 `id`。然后按以下顺序调用：

| 命令 | 输入 |
|---|---|
| `judgment propose` | `repo, ref, source_revision, judgment_id, base_revision, claim, supports, contradicts, review_after`；首次 base_revision 为 0；时间为 Unix 秒 |
| `judgment publish` | 同一仓库版本、judgment_id、候选 revision、预期 base_revision |
| `recommendation send` | 同一仓库版本、id、judgment_revision（如 impact@1）、executor_task_id、next_action、expected_check、expires_at |
| `ci record` | 授权操作者导入实际测得的 commit、run_id、check、conclusion 与 attribution。运行系统保有原始证明 |
| `ci import` | 管理员提供 repo、ref、source_revision、数值 job_id。服务从该仓已登记的 GitHub origin 读取公开 Actions 作业与运行，核实 push 分支、受测提交、运行归属和作业结果 |
| `decision record` | 授权操作者将自己的决定绑定到 repo、ref、source_revision；id 和 text 标识可撤回的记录 |
| `feedback record` | 同一仓库版本、id（重试沿用）、recommendation_id、judgment_revision、executor_task_id、acceptance、outcome、expected_check、evidence_ids、attribution |
| `evidence revoke` | id、reason；新的执行上下文立即重新核查 |
| `judgment explain ID` | 展开有权查看的当前及历史版本 |

发布判断的同一笔事务会生成版本简报。执行者从 `context get` 的 `briefs` 读取正文、支持证据和反证的定位信息。每次交接都会重查权限、判断版本和证据状态。较早的数据库也可读取，响应中的 `pre_generated` 标明简报是否已在发布时保存。

## 按身份查询

```sh
bin/thinker access grant --project demo --actor worker --task review \
  --role reader --ttl 3600 --output "$THINKER_HOME/review-reader"
bin/thinker --token-file "$THINKER_HOME/review-reader" mcp
```

Executor 的 stdio 工具清单为 `thinker_repo_status`、`thinker_get_context` 和 `thinker_explain_judgment`。授权与撤销的唯一入口为管理 CLI。使用 `access revoke --project demo --token-file-id review-reader` 终止该授权。TUI 可使用另行签发的 `--role human` 令牌，通过同一服务记录对特定任务的反馈。

```sh
bin/thinker tui --project demo --repo gtkg --ref refs/heads/main --task review
python3 -m unittest discover -s thinker_tests -v
```

AgentTeams 宿主可调用相同的上下文、事件游标和反馈接口，或嵌入终端会话组件。记录事件与建议只会形成待处理的数据，执行下一步仍由执行方决定。[TUI 规格与操作](thinker-tui.md) · [领域 JSON Schema](../thinker/contracts.json)

## 记忆与评测

默认后端将投影保存在私有 SQLite 中。使用 `memory retain` 显式提供 id、kind、evidence_ids、consent=true、data_class，按需提供 judgment_revision。可用类型为 world、experience、observation 和 mental_model。`memory project` 投递积压；`memory status`、`memory recall`、`memory wiki` 分别读投递状态、召回和只读页面。`memory forget` 立即阻断该投影并排队清理。恢复旧数据库时，先离线核对并重放快照之后发生的收权和撤回，再开放服务。

管理员可在新项目通过 `memory setup` 配置 Hindsight，参数包括 backend=hindsight、version=1.2.3、url 和 processing_opt_in=true。远端实例额外需要 HTTPS、remote_opt_in=true 和 api_key_env（服务进程中的凭据环境变量名）。连接的服务依照作用域派生 Bank ID。

每个项目可设置 `weekly_model_operations` 与 `max_concurrent_model_operations`。一次 Hindsight retain、recall 或 reflect 预留一个操作额度，周界以 UTC 为准。用 `memory status` 查看当前用量。忘记与删除确认在额度耗尽后仍可进行。实际 token 和费用取决于上游模型服务的用量记录。

新项目使用异步保留，也可在 `memory setup` 中显式指定 `"retain_mode":"async"`。首次投递会向 Hindsight 提交带固定操作 ID 的作业。`memory project` 返回的 `awaiting` 表示还有作业等待确认，可由观察服务继续对账。只有上游确认完成且来源仍有效，执行者才会收到这条记忆。旧版同步配置继续按原模式运行。同步写入若失去上游确认，本地将隔离该记录；核实旧 Bank 上的操作已终止后，再处置其远端资料。

两个可重放的交接测试使用相同 Git 快照与 10 个任务 ID，判定是否返回对应的已记录动作。测试运行时间包含 CLI 进程启动时间。

```sh
THINKER_EVAL=baseline python3 -m unittest thinker_tests.test_workflows.Handoff.test_paired_handoffs
THINKER_EVAL=agent python3 -m unittest thinker_tests.test_workflows.Handoff.test_paired_handoffs
```

需要测试自己的 GTKG 索引时，设置 `THINKER_REAL_GTKG_HANDOFF` 为知识库入口 JSON 的绝对路径，运行 `python3 -m unittest discover -s thinker_tests -v`。源提交需由本地分支引用。套件会在临时控制目录登记仓库，用当前 CLI 和本地 socket 取回检索结果，并逐字节核对提交里的 Git blob。普通单元测试使用临时仓库和隔离 SQLite。

CI 导入已用公开项目 inih 的真实作业验证。Thinker 读取 `master` 上提交 `18d8e283` 的 `build-linux` 结果，再与同一提交的 `ini.c` 第 273–277 行共同引用。该作业记录了上游 CI 成功。一次建议是否有价值，还需结合采纳情况、具体检查和人工试用衡量。[GitHub Actions 作业](https://github.com/benhoyt/inih/actions/runs/44286514346/job/134740464441)
