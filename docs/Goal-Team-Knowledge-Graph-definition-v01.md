# Goal-Team Knowledge Graph
## 版本号：V0.1

## 核心产品定义：
- 文档库：支持 PDF / WORD / Excle / PPT / Markdown 等多种文档格式的摘要化
- 代码库：通过逆向工程，把代码转为LLM 便于理解的摘要文档，并声明增量和全量，并抽象出统一的架构文档 agent.md / claude.md、rules.md、architecture.md、design.md，并附加版本号，参考 codeGraph 及 Qoder RepoWiki（先分析这两个产品形成参考文案）
- 支持 LLM WIKI 架构
- 支持 多路径配置，不同路径的职能内容可以不同
- 强绑定 git 仓库，至少一个，也支持多个 git 仓库的对比，备份，核心索引库独立文件

## 技术要求：
- 摘要文件全部使用 Google OKF格式
- 每个目录和文件都要有索引，并声明渐进式加载
- 文档化的知识图谱
- 支持 LLM WIKI 架构思路，构建一个独立的 静态 HTML + Google A2UI 文件，加载相应的索引和 OKF 文档做展示（左索引，右内容）
- 使用 rust 做脚本，尽量多使用脚本

## 参考：
- docs/文档知识图谱.md

## 生成要求：
- 使用 $goal-teams 生成需求规格卡,人工确认，再生成详细方案
