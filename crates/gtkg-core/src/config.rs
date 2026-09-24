//! Strict, read-only validation for the file-backed GTKG workspace config.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use gtkg_protocol::{ErrorCode, OperationRequest, OperationResponse, validate_path_identifier};
use serde::Deserialize;
use serde_json::json;

use crate::CallContext;
use crate::exact_read::{ExactReadFailure, read_bound_regular_file};

#[derive(Debug)]
pub struct ConfigFailure {
    pub code: ErrorCode,
    pub stage: &'static str,
    pub message: String,
    pub recovery_hint: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigValidatePayload {
    config_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ConfigVersion {
    schema_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceConfigV1 {
    schema_version: String,
    workspace_root: PathBuf,
    storage_model: String,
    database_backend: Option<String>,
    repository_roots: Vec<PathBuf>,
    template_catalog_roots: Vec<PathBuf>,
    node_endpoints: Vec<NodeEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceConfigV2 {
    schema_version: String,
    workspace_root: PathBuf,
    storage_model: String,
    database_backend: Option<String>,
    repositories: Vec<ConfiguredRepository>,
    template_catalog_roots: Vec<PathBuf>,
    node_endpoints: Vec<NodeEndpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredRepository {
    repo_id: String,
    path: PathBuf,
    role: String,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

struct NormalizedConfig {
    schema_version: String,
    workspace_root: PathBuf,
    storage_model: String,
    database_backend: Option<String>,
    repositories: Vec<ConfiguredRepository>,
    template_catalog_roots: Vec<PathBuf>,
    node_endpoints: Vec<NodeEndpoint>,
}

#[derive(Debug, Clone)]
pub(crate) struct SourceRepositoryConfig {
    pub repo_id: String,
    pub path: PathBuf,
    pub role: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

struct ValidatedConfig {
    schema_version: String,
    storage_model: String,
    repositories: Vec<SourceRepositoryConfig>,
    repository_role_count: usize,
    template_catalog_root_count: usize,
    node_endpoint_count: usize,
    config_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEndpoint {
    node_id: String,
    transport: String,
    endpoint: String,
}

pub fn validate(
    context: &CallContext,
    request: &OperationRequest,
) -> Result<OperationResponse, ConfigFailure> {
    let payload: ConfigValidatePayload = serde_json::from_value(request.payload.clone())
        .map_err(|error| invalid(format!("invalid config.validate payload: {error}")))?;
    let config = load_validated(context, &payload.config_path)?;
    let normalized_repositories = config
        .repositories
        .iter()
        .map(|repository| {
            json!({
                "repo_id": repository.repo_id,
                "path": repository.path,
                "role": repository.role,
                "include": repository.include,
                "exclude": repository.exclude,
            })
        })
        .collect::<Vec<_>>();
    Ok(OperationResponse::completed(
        request,
        json!({
            "valid": true,
            "schema_version": config.schema_version,
            "config_sha256": config.config_sha256,
            "storage_model": config.storage_model,
            "database_backend": null,
            "repository_root_count": config.repositories.len(),
            "repository_role_count": config.repository_role_count,
            "repositories": normalized_repositories,
            "template_catalog_root_count": config.template_catalog_root_count,
            "node_endpoint_count": config.node_endpoint_count,
        }),
    ))
}

fn load_validated(
    context: &CallContext,
    config_path: &Path,
) -> Result<ValidatedConfig, ConfigFailure> {
    let bound = read_bound_regular_file(context, config_path).map_err(exact_failure)?;
    let version: ConfigVersion = serde_json::from_slice(&bound.bytes)
        .map_err(|error| invalid(format!("invalid config file: {error}")))?;
    let config = match version.schema_version.as_str() {
        "gtkg.config/v1" => {
            let legacy: WorkspaceConfigV1 = serde_json::from_slice(&bound.bytes)
                .map_err(|error| invalid(format!("invalid v1 config file: {error}")))?;
            NormalizedConfig {
                schema_version: legacy.schema_version,
                workspace_root: legacy.workspace_root,
                storage_model: legacy.storage_model,
                database_backend: legacy.database_backend,
                repositories: legacy
                    .repository_roots
                    .into_iter()
                    .enumerate()
                    .map(|(index, path)| ConfiguredRepository {
                        repo_id: format!("repository-{:04}", index + 1),
                        path,
                        role: "default".to_owned(),
                        include: Vec::new(),
                        exclude: Vec::new(),
                    })
                    .collect(),
                template_catalog_roots: legacy.template_catalog_roots,
                node_endpoints: legacy.node_endpoints,
            }
        }
        "gtkg.config/v2" => {
            let current: WorkspaceConfigV2 = serde_json::from_slice(&bound.bytes)
                .map_err(|error| invalid(format!("invalid v2 config file: {error}")))?;
            NormalizedConfig {
                schema_version: current.schema_version,
                workspace_root: current.workspace_root,
                storage_model: current.storage_model,
                database_backend: current.database_backend,
                repositories: current.repositories,
                template_catalog_roots: current.template_catalog_roots,
                node_endpoints: current.node_endpoints,
            }
        }
        _ => return Err(invalid("unsupported config schema")),
    };
    if config.storage_model != "okf-and-ordinary-files" || config.database_backend.is_some() {
        return Err(ConfigFailure {
            code: ErrorCode::DatabaseForbidden,
            stage: "config.validate",
            message: "V0.1 config must use only OKF and ordinary files".to_owned(),
            recovery_hint: "remove database_backend and use storage_model okf-and-ordinary-files",
        });
    }
    let _workspace_root = context
        .authorize_read(&config.workspace_root)
        .map_err(path_failure)?;
    if config.repositories.is_empty() || config.template_catalog_roots.is_empty() {
        return Err(invalid(
            "config requires at least one configured repository and template catalog root",
        ));
    }
    let mut template_roots = BTreeSet::new();
    for root in &config.template_catalog_roots {
        let canonical = context.authorize_read(root).map_err(path_failure)?;
        if !canonical.is_dir() || !template_roots.insert(canonical) {
            return Err(invalid(
                "template catalog roots must be unique existing directories",
            ));
        }
    }
    let mut repo_ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut normalized_repositories = Vec::new();
    for repository in &config.repositories {
        validate_path_identifier("repo_id", &repository.repo_id)
            .map_err(|error| invalid(error.to_string()))?;
        validate_path_identifier("role", &repository.role)
            .map_err(|error| invalid(error.to_string()))?;
        if !repo_ids.insert(repository.repo_id.as_str()) {
            return Err(invalid("configured repository ids must be unique"));
        }
        let canonical = context
            .authorize_read(&repository.path)
            .map_err(path_failure)?;
        if !canonical.is_dir() {
            return Err(invalid("configured repository paths must be directories"));
        }
        validate_scopes("include", &repository.include)?;
        validate_scopes("exclude", &repository.exclude)?;
        roles.insert(repository.role.as_str());
        normalized_repositories.push(SourceRepositoryConfig {
            repo_id: repository.repo_id.clone(),
            path: canonical,
            role: repository.role.clone(),
            include: repository.include.clone(),
            exclude: repository.exclude.clone(),
        });
    }
    let mut node_ids = BTreeSet::new();
    for endpoint in &config.node_endpoints {
        validate_path_identifier("node_id", &endpoint.node_id)
            .map_err(|error| invalid(error.to_string()))?;
        if !node_ids.insert(endpoint.node_id.as_str()) {
            return Err(invalid("node endpoint ids must be unique"));
        }
        if !matches!(endpoint.transport.as_str(), "exec" | "mcp_stdio") {
            return Err(invalid("node endpoint transport must be exec or mcp_stdio"));
        }
        if endpoint.endpoint.trim().is_empty()
            || endpoint.endpoint.contains("http://")
            || endpoint.endpoint.contains("https://")
            || endpoint.endpoint.contains("ssh://")
            || endpoint.endpoint.contains("tcp://")
        {
            return Err(invalid("node endpoint must be a non-network local address"));
        }
    }
    Ok(ValidatedConfig {
        schema_version: config.schema_version,
        storage_model: config.storage_model,
        repositories: normalized_repositories,
        repository_role_count: roles.len(),
        template_catalog_root_count: config.template_catalog_roots.len(),
        node_endpoint_count: config.node_endpoints.len(),
        config_sha256: bound.sha256,
    })
}

fn validate_scopes(kind: &str, scopes: &[String]) -> Result<(), ConfigFailure> {
    let mut unique = BTreeSet::new();
    for scope in scopes {
        let trimmed = scope.trim_end_matches('/');
        let path = Path::new(trimmed);
        if trimmed.is_empty()
            || path.is_absolute()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            || !unique.insert(trimmed)
        {
            return Err(invalid(format!(
                "repository {kind} scopes must be unique safe relative prefixes"
            )));
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ConfigFailure {
    ConfigFailure {
        code: ErrorCode::InvalidRequest,
        stage: "config.validate",
        message: message.into(),
        recovery_hint: "repair the closed gtkg.config/v1 or gtkg.config/v2 file and retry",
    }
}

fn path_failure(error: crate::ContextError) -> ConfigFailure {
    ConfigFailure {
        code: ErrorCode::PathEscape,
        stage: "config.validate",
        message: error.to_string(),
        recovery_hint: "use only paths authorized by the current CallContext",
    }
}

fn exact_failure(error: ExactReadFailure) -> ConfigFailure {
    ConfigFailure {
        code: error.code,
        stage: "config.validate",
        message: format!("{}: {}", error.path.display(), error.message),
        recovery_hint: "provide an existing stable config file",
    }
}
