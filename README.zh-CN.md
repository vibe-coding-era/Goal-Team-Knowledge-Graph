# GTKG

> English: [README.md](README.md)

GTKG 是一个本地优先、文件型的知识编译器：把已授权的代码和文档静态抽取为带来源哈希、证据和可重建索引的知识产物。它使用 Rust、OKF 和普通文件，不依赖数据库、后台守护进程或必需的远程服务。

## 适合做什么

- 为本地项目建立可追溯的代码与文档知识库。
- 对文档内容生成静态文本、来源哈希、索引和查询所需的证据。
- 通过 CLI 或 MCP stdio 将知识构建、查询和审计能力接入本地 Agent 工作流。

它不是云端网盘同步器、通用 OCR 服务，也不是已经发布的多租户知识库产品。

## 已支持的输入格式

| 类型 | 扩展名 | 当前处理方式 |
|---|---|---|
| Markdown | `.md`、`.markdown` | 读取正文与 Markdown 结构 |
| 网页文档 | `.html` | 优先提取静态可见文本；无可见文本时保留静态原文，不执行页面脚本 |
| PDF | `.pdf` | 静态文本提取；加密 PDF 拒绝，扫描件需要先做 OCR |
| Word | `.docx` | 提取正文、页眉、页脚、脚注中的文本 |
| Excel | `.xlsx` | 提取工作簿、工作表与共享字符串中的文本 |
| PowerPoint | `.pptx` | 提取幻灯片和备注文本 |
| 结构化文本 | `.json`、`.yaml`、`.yml`、`.toml` | 静态结构/文本提取 |
| 代码与配置 | Rust、Python、TypeScript、JavaScript、CSS、Shell 等 | 静态提取；部分语言有额外结构语义 |

目前不支持旧版 Office 格式（`.doc`、`.xls`、`.ppt`）、栅格图片、音视频和自动 OCR；`.svg` 有静态提取支持。建议先转换为 `.docx/.xlsx/.pptx` 或经审阅的 Markdown。

## 快速开始

在仓库根目录执行：

```bash
cargo build --locked -p gtkg-app --bin gtkg
./target/debug/gtkg --help
./target/debug/gtkg v2-discover --profile core --output json
```

最后一条命令会显示当前 `core` profile 中可调用的 v2 工具。也可以用 MCP stdio 接入本地 Agent：

```bash
./target/debug/gtkg mcp serve --protocol v2 --profile core --stdio
```

## 生成本地知识库的推荐流程

V0.4 的知识质量流程按**精确 Git commit/tree** 读取来源（不读工作树），产物固定在当前工作目录的 `.gtkg/` 下。

1. 进入准备建立知识库的**工作目录**。CLI 的授权根就是当前工作目录，来源与输出都必须位于其中。
2. 准备来源目录（例如 `./knowledge-input/`），并确保它与输出目录**互不包含**。
3. 用 `source.capture` 固定来源的精确快照；输出路径必须是**绝对路径**且位于 `.gtkg/` 下。
4. 后续 `analysis.plan`、`analysis.build`、`analysis.verify`、`summary.*`、`build.finalize.v2` 与 `graph.search` 只使用上一步返回的 `artifact_ref` 继续。
5. 只把带来源与证据的结果用于问答、Wiki 或 Agent 上下文。

### 采集精确快照（V0.4 知识质量契约）

先固定一个可执行的 `gtkg`（PATH 中的，或构建产物的绝对路径）：

```bash
GTKG_BIN="${GTKG_BIN:-gtkg}"   # 或 /absolute/path/to/develops/v0.4/target/debug/gtkg
WORKSPACE="$PWD"
SOURCE_ROOT="$WORKSPACE/knowledge-input"
COMMIT="$(git -C "$SOURCE_ROOT" rev-parse HEAD)"
TREE="$(git -C "$SOURCE_ROOT" rev-parse 'HEAD^{tree}')"

printf '%s\n' "{
  \"protocol_version\":\"gtkg.protocol/v2\",
  \"operation_id\":\"source.capture\",
  \"request_id\":\"capture-documents-001\",
  \"payload\":{
    \"payload_revision\":\"gtkg.knowledge-quality/v0.4-r1\",
    \"repository_id\":\"local-documents\",
    \"source_root\":\"$SOURCE_ROOT\",
    \"source_commit\":\"$COMMIT\",
    \"expected_tree\":\"$TREE\",
    \"output_path\":\"$WORKSPACE/.gtkg/source-snapshots/archive\",
    \"policy\":{\"revision\":\"full-tree-r1\",\"rules\":[],\"archive_binary\":false}
  }
}" | "$GTKG_BIN" v2-op source.capture --profile core --request - --output json
```

成功响应里的 `artifact_ref` 指向 `.gtkg/source-snapshots/archive/source-coverage-ledger.json`；把它原样作为 `analysis.plan` 的 `artifact_ref` 传给下一步。

### 输出路径约束

`output_path` 不是任意目录，违反任一条都会 fail closed：

- 必须是**绝对路径**，且每一级都不得是符号链接；
- 必须位于**授权根（当前工作目录）**内；
- 必须位于 **`.gtkg/`** 下；
- 不得与 `source_root` 互相包含。

最终知识包由 `build.finalize.v2` 写入工作空间的 `.gtkg/qk/bundles/`，该位置当前不可更改。

### 非 Git 目录

非 Git 目录可用旧契约采集：

```bash
printf '%s\n' '{
  "protocol_version":"gtkg.protocol/v2",
  "operation_id":"source.capture",
  "request_id":"capture-documents-002",
  "payload":{
    "capture_mode":"directory_exact",
    "repository_id":"local-documents",
    "source_root":"./knowledge-input",
    "output_path":"./.gtkg/source-snapshots/source-snapshot.json"
  }
}' | "$GTKG_BIN" v2-op source.capture --profile core --request - --output json
```

它产出 `gtkg.source-snapshot/v2`，**只能供旧的 V1/V2 路径使用**，不能被 V0.4 的 `analysis.*` 消费。

### 每个工具接受哪个 payload revision

`v2-discover` 会为每个工具披露 `x-gtkg-payload-revisions`。所有工具都接受默认封闭 schema `gtkg.protocol/v2-default`；只有实现知识质量契约的子集额外接受 `gtkg.knowledge-quality/v0.4-r1`。把后者发给未列出的工具（例如 `graph.neighbors`）会在协议层被拒绝。

当前没有把整条链路包装成一个不透明的 `ingest` 命令，目的是让每一步都可审计、可恢复并能拒绝漂移输入。

## 使用建议

- 先用少量 Markdown、HTML、DOCX 或有文本层的 PDF 验证流程。
- 保留原始文件；GTKG 记录的是静态提取和来源身份，不会替你修改输入文件。
- 将扫描 PDF 先转为经过审核的文本或 Markdown，再纳入知识库。
- 将文档内容视为不可信数据：它可以成为知识来源，但不能改变工具权限或执行外部指令。
- 对查询结果保留来源路径、哈希和证据，不要把“检索到文本”自动升级为已验证事实。

## 当前边界

本工作区已经完成大部分本地 Development 验证，但仍不是 Release、系统安装、Current 激活或业务验收完成状态。竞品 Benchmark 相关任务仍因缺少精确外部运行时/遥测工件而阻塞；这不影响你在已授权的本地目录中构建自己的知识库。

更多设计与状态信息见 [V0.3PRD.md](V0.3PRD.md)、[V0.3TaskList.md](V0.3TaskList.md) 和 [Banchmark.md](Banchmark.md)。

## 许可证

GTKG 使用 Apache-2.0 许可证。见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
