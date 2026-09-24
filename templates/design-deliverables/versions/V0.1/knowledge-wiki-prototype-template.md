---
type: template
title: "GTKG Knowledge Wiki HTML Prototype Template"
description: "用于生成 Knowledge Wiki V0.1 单文件静态 HTML 设计原型的 OKF v0.2 模板。"
resource: "./knowledge-wiki-prototype-template.md"
tags: [gtkg, knowledge-wiki, html-prototype, a2ui, template]
generated: true
verified: false
status: draft
sources:
  - id: "R3.3-D1"
    kind: "confirmed-design-baseline"
  - id: "A2UI-0.9.1"
    kind: "protocol-reference"
    uri: "https://a2ui.org/specification/v0.9.1-a2ui/"
okf_version: "0.2"
gtkg:
  schema: "gtkg.design-deliverable-template/v1"
  template_id: "knowledge-wiki-prototype"
  template_version: "0.1.0"
  intended_output:
    document_id: "GTKG-KNOWLEDGE-WIKI-PROTOTYPE"
    version: "V0.1"
    format: "standalone HTML"
  implementation_status: "not_run"
  runtime_status: "prototype_only"
  progressive_loading:
    level: "L1"
    sections_addressable: true
---

# Knowledge Wiki HTML Prototype Template V0.1

> 本模板只定义设计原型的页面、状态和交互合同。生成的 HTML 不得宣称已连接真实 `gtkg`、CLI、MCP、Git、OKF 索引或 A2UI renderer。

## 1. 输出合同

| 项目 | 必须满足 |
|---|---|
| 文件形态 | 单个 UTF-8 HTML 文件，可直接打开或通过本地静态服务器浏览 |
| 外部依赖 | 无 CDN、远程字体、远程图片、外部脚本和外部样式 |
| 数据 | 只使用源自 R3.3-D1 的、明确标记为 `prototype_fixture` 的演示数据 |
| 布局 | 左侧知识索引，右侧内容，顶栏搜索/版本/证据状态 |
| 状态 | normal、loading、empty、error、permission、disabled |
| 响应式 | 桌面双栏；窄屏索引变为可开合抽屉 |
| 无障碍 | 语义结构、可见焦点、键盘导航、ARIA、降低动画偏好 |
| 安全 | 不执行文档内容，不拼接任意 HTML，不访问网络或本机文件系统 |
| A2UI | 展示 v0.9.1 readiness 与锁定概念，不宣称 renderer 已验证 |

## 2. 信息架构

### 2.1 顶栏

- 产品标识与 `Prototype V0.1`。
- 全局搜索框，支持 `/` 聚焦与 `Esc` 清除。
- 当前交付版本、知识状态、离线状态和主题切换。

### 2.2 左侧索引

- Overview。
- Product：PRD、Persona、需求与 AC。
- Architecture：上下文、Core、CLI/MCP、多节点、Sandbox、Git。
- Knowledge：文档、代码、图谱、索引与渐进加载。
- Frontend：Semantic IR、A2UI、复刻证据。
- Evidence：来源、状态、未知项与限制。

索引节点必须显示内容类型、数量或加载级别，并保留当前选择态。

### 2.3 右侧内容

- 面包屑、标题、摘要、版本和证据徽标。
- 关键指标卡只展示设计范围数据，不伪造运行指标。
- 主体内容支持文档、架构、关系、索引、A2UI Surface 五类视图。
- 相关知识、来源、限制和未知项独立呈现。

## 3. 核心原型场景

| 场景 | 触发 | 可观察结果 |
|---|---|---|
| 浏览知识 | 点击左侧节点 | 右侧替换为对应 fixture，URL hash 同步 |
| 搜索 | 输入关键词 | 左侧过滤并高亮匹配；无结果显示 empty state |
| 渐进加载 | 打开 L2/L3 节点 | 先显示骨架，再显示 fixture，并标注为模拟加载 |
| 证据检查 | 点击 Evidence | 显示来源、状态、限制、未知项，不只显示结论 |
| A2UI 检查 | 打开 A2UI Surface | 显示 protocol/catalog/renderer lock 与四级证据 |
| 响应式 | 视口小于 900px | 左侧索引折叠为抽屉，内容仍可操作 |

## 4. 状态矩阵

| 状态 | UI 行为 | 禁止行为 |
|---|---|---|
| normal | 展示完整 fixture | 不标记为真实运行数据 |
| loading | skeleton 与加载说明 | 不无限旋转、不隐藏来源 |
| empty | 说明无匹配结果并提供清除搜索 | 不把空状态写成错误 |
| error | 明确原型加载失败并提供重试 | 不伪造成功内容 |
| permission | 展示受限来源和最小说明 | 不泄露受限正文 |
| disabled | 控件解释不可用原因 | 不让禁用控件触发行为 |

原型必须提供可见的状态切换入口，便于人工审查全部状态。

## 5. A2UI 原型合同

- 协议显示值固定为 `A2UI v0.9.1`。
- 展示 `createSurface`、`updateComponents`、`updateDataModel`、`deleteSurface` 四类消息。
- 展示 `schema lock`、`catalog lock`、`renderer lock`，digest 可用设计占位值，但必须标记 `not_bound`。
- 映射状态只允许 `exact | approximation | unsupported`。
- 证据级别必须分开：
  1. `a2ui_ready_summary`
  2. `a2ui_generatable`
  3. `renderer_replicable`
  4. `verified_replica`
- 原型当前最多展示前两级为“设计目标”；后两级必须保持 `not_run`。

## 6. 视觉语言

- 方向：安静、可信、工具型知识工作台。
- 主色：深墨蓝与青绿色；证据状态使用克制的语义色。
- 字体：系统字体栈，正文优先可读性。
- 层级：细边框、低对比背景、少量阴影；避免大面积渐变和营销式卡片堆叠。
- 动效：仅用于抽屉、加载与内容切换；遵循 `prefers-reduced-motion`。

## 7. 原型验收

- [ ] 单文件且无网络依赖。
- [ ] 左索引、右内容、顶栏三域清晰。
- [ ] 搜索、导航、主题和状态切换可操作。
- [ ] normal/loading/empty/error/permission/disabled 全部可观察。
- [ ] 桌面和窄屏布局没有内容溢出。
- [ ] 控件可用键盘访问，焦点可见。
- [ ] 所有演示数据标记为原型 fixture。
- [ ] 页面明确说明未连接真实 Core/CLI/MCP/Git。
- [ ] A2UI 四级证据没有越级。
- [ ] 浏览器控制台无页面自身错误。

## 8. 明确非目标

- 不实现 OKF 解析器、索引器、搜索引擎或知识图谱算法。
- 不调用真实 CLI/MCP、Git、LLM、A2UI renderer 或远程服务。
- 不证明 Sandbox、增量构建、复刻级生成或 10k 容量。
- 不作为生产 UI、可部署站点或正式 A2UI payload。

