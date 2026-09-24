---
type: index
title: "GTKG Design Deliverable Template Pack V0.1"
description: "绑定 R3.3-D1 的 PRD、架构和 Knowledge Wiki 原型模板包。"
resource: "./"
tags: [gtkg, templates, v0.1, index]
generated: true
verified: false
status: draft
sources:
  - id: "R3.3-D1"
    kind: "confirmed-design-baseline"
okf_version: "0.2"
gtkg:
  schema: "gtkg.template-pack-index/v1"
  template_pack_id: "gtkg-design-deliverables"
  template_pack_version: "V0.1"
  load_level: "L3"
  digest_state: "pending_git_binding"
---

# GTKG Design Deliverable Template Pack V0.1

| 文件 | Template ID | SHA-256 | Bytes | 输出 | 状态 |
|---|---|---|---:|---|---|
| `prd-template.md` | `gtkg-prd` | `895659a0bd9d0df5a8b5669d2b511bbcc06e2d63c045afb68a3232029c28d382` | 23581 | `PRD.md` | draft |
| `architecture-template.md` | `architecture-design` | `8b62a9ef44e9ee8b302c28040b8dd0c6952daf9f4d2380ece3054b142d4c9712` | 34784 | `ARCHITECTURE.md` | draft |
| `knowledge-wiki-prototype-template.md` | `knowledge-wiki-prototype` | `c930461da460d9730e743e599c3104213310c9169bde621982bab7d10e4efc54` | 5942 | `knowledge-wiki.html` | draft |

## 使用约束

- 所有交付物生成前必须先解析本目录中的 exact 模板版本。
- 当前工作区不是 Git 仓库，模板 digest 和 commit lock 保持 `pending_git_binding`。
- 模板状态不证明交付物已经实现、运行或获得业务验收。
