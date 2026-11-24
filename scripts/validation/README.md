# GTKG 本机版本验收

从工程根目录运行。当前公开代码基于 V0.4 开发快照，Rust 包版本为 0.3.0。Thinker 单独使用 0.5.0。

## 当前工作区

```bash
python3 scripts/restore-t04-public-sources.py
python3 scripts/validation/run-current.py output/local-gate
python3 scripts/validation/run-current.py --verify output/local-gate
```

第一个命令从公开固定提交取回八个测试输入，缓存已经就绪时可以直接运行门禁。第二个命令需要一个新目录、本机 Rust 工具链、Python 3.9+、Git、Bash 和 jq。它先构建 CLI，再执行完整的 `cargo test --workspace --locked --no-fail-fast`，同时保留 Cargo 的退出码和逐项输出。随后运行需要本机二进制及摘要的 P06、I01 和 U06 验证。

- `cargo.log` 和 `cargo-run.json` 记录 Cargo 的完整输出、退出码、提交和输入摘要。
- `runners/` 保存专用运行器的实际命令、测试日志和绑定。每条通过的补充结果都必须对应该次运行和精确用例名。
- `current-result.json` 给出当前版本的判定，并列出历史用例及其在当前源码上的实际结果。历史归属按 target 和完整测试函数名登记。新增失败默认阻断当前门禁。
- `--verify` 用现有源码和原始记录重新计算，检查提交、输入、分类和结果是否一致。

原始 Cargo 全量结果可独立查阅。历史断言需要多少个操作、能否提供原始语料等事实不会因分类而改变。

## 历史提交

用完整提交 SHA 和原始测试函数名运行。以下例子重放公开首份源码快照中的一条架构文档测试。

```bash
python3 scripts/validation/check-history.py \
  --checkout "$PWD" --commit 2f7859474219f034556ffd1e492960b70496cdc6 \
  --target e07_arch_docs_contract \
  --test architecture_documents_are_deterministic_and_verifiable \
  --report output/public-snapshot-e07.json
```

历史入口使用隔离的临时 Git 检出和该提交的原始测试，记录源码身份、运行命令、退出码及输出。针对已登记的目标，可以省略 `--test` 选择该目标的历史用例。对于未公开的原始材料，可以用 `--material-root` 指向已有归档。命令成功返回 0，原始断言失败返回 1，缺少提交、冻结输入或可验证的前置条件返回 2。早期阶段的验收需要该阶段源码；公开 V0.4 快照的测试结果仅代表所选公开提交。

## Thinker 与已有的 GTKG 知识库

将 `THINKER_REAL_GTKG_HANDOFF` 设为本机知识库交接文件的路径。可用 `THINKER_REAL_GTKG_QUERY` 选择一个已索引的源码符号，默认使用 `main`。

```bash
cargo build --release --locked -p gtkg-app --bin gtkg
PATH="$PWD/target/release:$PATH" \
THINKER_REAL_GTKG_HANDOFF="/path/to/knowledge-base.json" \
python3 -m unittest discover -s thinker_tests -v
```

测试会通过控制服务查询真实索引，并从交接文件指定的 Git 提交读回命中片段，逐字节核对内容和摘要。运行时需要能访问该提交的本地源码。
