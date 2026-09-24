use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

const FORBIDDEN_DEPENDENCIES: &[&str] = &[
    "rusqlite",
    "sqlx",
    "diesel",
    "postgres",
    "tokio-postgres",
    "mysql",
    "mysql_async",
    "mongodb",
    "redis",
    "duckdb",
    "libsql",
    "neo4rs",
    "qdrant-client",
    "surrealdb",
    "lancedb",
    "rocksdb",
    "sled",
    "redb",
    "heed",
    "lmdb",
    "tantivy",
];

const FORBIDDEN_EXTENSIONS: &[&str] = &[
    "db", "db3", "sqlite", "sqlite3", "libsql", "duckdb", "mdb", "lmdb", "rdb", "aof", "bson",
    "surreal", "lance", "lancedb", "qdrant", "neo4j",
];

const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "kt", "swift", "c", "cc", "cpp", "h",
    "hpp", "sh", "bash", "zsh", "toml", "yaml", "yml",
];

const FORBIDDEN_SOURCE_APIS: &[&str] = &[
    "rusqlite::",
    "sqlx::",
    "diesel::",
    "tokio_postgres::",
    "postgres::",
    "mysql::",
    "mysql_async::",
    "mongodb::",
    "redis::",
    "duckdb::",
    "libsql::",
    "neo4rs::",
    "qdrant_client::",
    "surrealdb::",
    "lancedb::",
    "rocksdb::",
    "sled::",
    "redb::",
    "heed::",
    "lmdb::",
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "redis://",
    "neo4j://",
    "surreal://",
];

const FORBIDDEN_DAEMONS: &[&str] = &[
    "command::new(\"postgres\")",
    "command::new(\"mysqld\")",
    "command::new(\"mongod\")",
    "command::new(\"redis-server\")",
    "command::new(\"neo4j\")",
    "command::new(\"qdrant\")",
    "command::new(\"surreal\")",
    "command::new(\"surrealdb\")",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoDatabaseFinding {
    pub rule_id: String,
    pub path: PathBuf,
    pub evidence: String,
}

#[derive(Debug, Error)]
pub enum NoDatabaseError {
    #[error("failed to walk file-only tree: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("failed to inspect {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn scan_no_database(root: &Path) -> Result<Vec<NoDatabaseFinding>, NoDatabaseError> {
    let mut findings = Vec::new();
    let production_workspace = is_production_workspace(root);
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| should_visit(root, production_workspace, entry))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if let Some(extension) = path.extension().and_then(|value| value.to_str())
            && FORBIDDEN_EXTENSIONS
                .iter()
                .any(|forbidden| extension.eq_ignore_ascii_case(forbidden))
        {
            findings.push(NoDatabaseFinding {
                rule_id: "forbidden_extension".to_owned(),
                path: path.to_path_buf(),
                evidence: extension.to_owned(),
            });
        }
        let mut file = fs::File::open(path).map_err(|source| NoDatabaseError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut prefix = [0_u8; 32];
        let count = file
            .read(&mut prefix)
            .map_err(|source| NoDatabaseError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if let Some(magic) = forbidden_magic(&prefix[..count]) {
            findings.push(NoDatabaseFinding {
                rule_id: "forbidden_magic".to_owned(),
                path: path.to_path_buf(),
                evidence: magic.to_owned(),
            });
        }
        if matches!(
            path.file_name().and_then(|value| value.to_str()),
            Some("Cargo.lock" | "Cargo.toml")
        ) {
            let text = fs::read_to_string(path).map_err(|source| NoDatabaseError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            for dependency in FORBIDDEN_DEPENDENCIES {
                let cargo_lock_name = format!("name = \"{dependency}\"");
                let cargo_toml_key = format!("{dependency} =");
                if text.contains(&cargo_lock_name) || text.contains(&cargo_toml_key) {
                    findings.push(NoDatabaseFinding {
                        rule_id: "forbidden_dependency".to_owned(),
                        path: path.to_path_buf(),
                        evidence: (*dependency).to_owned(),
                    });
                }
            }
        }
        if is_source_file(path) && !is_scanner_source(path) {
            let text = fs::read_to_string(path).map_err(|source| NoDatabaseError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let normalized = text.to_ascii_lowercase();
            for pattern in FORBIDDEN_SOURCE_APIS {
                if normalized.contains(pattern) {
                    findings.push(NoDatabaseFinding {
                        rule_id: "forbidden_source_api".to_owned(),
                        path: path.to_path_buf(),
                        evidence: (*pattern).to_owned(),
                    });
                }
            }
            for pattern in FORBIDDEN_DAEMONS {
                if normalized.contains(pattern) {
                    findings.push(NoDatabaseFinding {
                        rule_id: "forbidden_daemon".to_owned(),
                        path: path.to_path_buf(),
                        evidence: (*pattern).to_owned(),
                    });
                }
            }
        }
    }
    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.evidence.cmp(&right.evidence))
    });
    findings.dedup();
    Ok(findings)
}

fn should_visit(root: &Path, production_workspace: bool, entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    if matches!(
        entry.file_name().to_str(),
        Some(".git" | ".gtkg" | "output" | "target" | "node_modules")
    ) {
        return false;
    }
    if !production_workspace {
        return true;
    }
    let relative = entry
        .path()
        .strip_prefix(root)
        .unwrap_or_else(|_| entry.path());
    if relative.starts_with(Path::new("crates/gtkg-testkit")) {
        return false;
    }
    !relative
        .components()
        .any(|component| component.as_os_str() == "fixtures")
}

fn is_production_workspace(root: &Path) -> bool {
    root.join("Cargo.toml").is_file() && root.join("crates/gtkg-core").is_dir()
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            SOURCE_EXTENSIONS
                .iter()
                .any(|source| extension.eq_ignore_ascii_case(source))
        })
}

fn is_scanner_source(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some("no_db.rs")
}

fn forbidden_magic(prefix: &[u8]) -> Option<&'static str> {
    if prefix.starts_with(b"SQLite format 3\0") {
        Some("SQLite format 3")
    } else if prefix.starts_with(b"DUCKDB\0") || prefix.windows(4).any(|window| window == b"DUCK") {
        Some("DuckDB")
    } else if prefix.starts_with(b"REDIS") {
        Some("Redis RDB")
    } else if prefix.starts_with(b"WiredTiger") {
        Some("MongoDB WiredTiger")
    } else {
        None
    }
}
