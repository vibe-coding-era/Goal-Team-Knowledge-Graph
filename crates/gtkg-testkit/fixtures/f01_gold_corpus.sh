#!/usr/bin/env bash
# F01/B18 gold corpus materializer: creates a small real multi-language Git
# repository used to evaluate host-LLM summary claim precision/citation.
# Usage: bash crates/gtkg-testkit/fixtures/f01_gold_corpus.sh <target-dir>
set -euo pipefail

TARGET="${1:?target directory required}"
if [[ -e "$TARGET" ]]; then
  echo "target already exists: $TARGET" >&2
  exit 2
fi
mkdir -p "$TARGET/src" "$TARGET/py" "$TARGET/web" "$TARGET/docs"

cat > "$TARGET/src/lib.rs" <<'RS'
//! Core task model for the taskboard mini project.

/// A single task with a title and completion flag.
pub struct Task {
    pub id: u64,
    pub title: String,
    pub done: bool,
}

impl Task {
    /// Create a new open task.
    pub fn new(id: u64, title: &str) -> Self {
        Self { id, title: title.to_owned(), done: false }
    }

    /// Mark the task done. Returns false when it was already done.
    pub fn complete(&mut self) -> bool {
        if self.done { return false; }
        self.done = true;
        true
    }
}

/// Compute the next available task id.
pub fn next_id(tasks: &[Task]) -> u64 {
    tasks.iter().map(|t| t.id).max().unwrap_or(0) + 1
}
RS

cat > "$TARGET/src/store.rs" <<'RS'
//! JSON-lines persistence for tasks.

use crate::lib::{next_id, Task};

/// In-memory store that mirrors a JSONL file layout.
pub struct Store {
    pub tasks: Vec<Task>,
}

impl Store {
    /// Add a task, assigning the next id. Returns the new id.
    pub fn add(&mut self, title: &str) -> u64 {
        let id = next_id(&self.tasks);
        self.tasks.push(Task::new(id, title));
        id
    }

    /// Complete a task by id. Returns false when missing or already done.
    pub fn complete(&mut self, id: u64) -> bool {
        match self.tasks.iter_mut().find(|t| t.id == id) {
            Some(task) => task.complete(),
            None => false,
        }
    }

    /// Serialize open tasks as JSON lines.
    pub fn open_as_jsonl(&self) -> String {
        self.tasks
            .iter()
            .filter(|t| !t.done)
            .map(|t| format!("{{\"id\":{},\"title\":\"{}\"}}", t.id, t.title))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
RS

cat > "$TARGET/py/notify.py" <<'PY'
"""Notification helpers for the taskboard mini project."""
import json


def render_completion(task_id: int, title: str) -> str:
    """Render a completion notification line."""
    return json.dumps({"event": "completed", "id": task_id, "title": title})


def render_summary(open_count: int, done_count: int) -> str:
    """Render a daily summary notification line."""
    return json.dumps({"event": "summary", "open": open_count, "done": done_count})
PY

cat > "$TARGET/py/stats.py" <<'PY'
"""Completion statistics for the taskboard mini project."""


def completion_rate(done: int, total: int) -> float:
    """Return done/total as a float; zero total yields 0.0."""
    if total == 0:
        return 0.0
    return done / total


def is_healthy(rate: float, threshold: float = 0.5) -> bool:
    """A board is healthy when its completion rate meets the threshold."""
    return rate >= threshold
PY

cat > "$TARGET/web/board.ts" <<'TS'
/** Board rendering for the taskboard mini project. */

export interface TaskView {
  id: number;
  title: string;
  done: boolean;
}

/** Render one task row as text. */
export function renderRow(task: TaskView): string {
  const mark = task.done ? "[x]" : "[ ]";
  return `${mark} #${task.id} ${task.title}`;
}

/** Render the whole board, open tasks first. */
export function renderBoard(tasks: TaskView[]): string {
  const sorted = [...tasks].sort((a, b) => Number(a.done) - Number(b.done));
  return sorted.map(renderRow).join("\n");
}
TS

cat > "$TARGET/docs/guide.md" <<'MD'
# Taskboard 使用指南

Taskboard 是一个最小任务看板：通过 `Store.add` 创建任务，`Store.complete`
完成任务，`open_as_jsonl` 导出未完成任务。Python 侧 `notify.py` 负责
通知渲染，`stats.py` 计算完成率。TypeScript 侧 `renderBoard` 把未完成
任务排在前面渲染。
MD

cat > "$TARGET/docs/rules.md" <<'MD'
# 业务规则

1. 任务只能完成一次：重复完成返回 false。
2. 新任务 id 从 1 开始递增，取当前最大 id 加一。
3. 完成率健康阈值默认为 0.5。
4. 导出只包含未完成任务。
MD

cat > "$TARGET/Cargo.toml" <<'TOML'
[package]
name = "taskboard"
version = "0.1.0"
edition = "2021"

[dependencies]
TOML

printf '%s\n' '.gtkg/' 'artifacts/' > "$TARGET/.gitignore"

git -C "$TARGET" init -q -b main
git -C "$TARGET" add -A
git -C "$TARGET" -c user.name="F01 Fixture" -c user.email="f01@fixture.invalid" commit -q -m "gold corpus"
echo "F01_CORPUS_READY $TARGET"
git -C "$TARGET" rev-parse HEAD
