use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::v2::{OperationRequestV2, V2ErrorEnvelope, V2OperationId};
use gtkg_protocol::{ErrorCode, OperationId, OperationRequest, ShardResult, WorkUnit};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "gtkg",
    version,
    about = "Goal-Team Knowledge Graph",
    after_help = "Examples:\n  gtkg op system.describe --request - --output json\n  gtkg v2-op source.capture --request - --output json\n  gtkg v2-discover --profile graph\n  gtkg mcp serve --stdio\n  gtkg mcp serve --protocol v2 --profile graph --stdio\n  gtkg node serve --stdio"
)]
struct Cli {
    /// Exit non-zero when the operation produces an error envelope.
    ///
    /// GTKG reports a failed operation as a response envelope on stdout, so the
    /// exit code alone cannot tell a shell caller that it failed. The default
    /// stays compatible (exit 0 with the envelope); this flag makes `set -e` and
    /// `||` reliable.
    #[arg(long, global = true)]
    strict_exit: bool,
    #[command(subcommand)]
    command: Command,
}

/// The process outcome of one CLI invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitOutcome {
    Success,
    /// The operation ran and returned an error envelope that was already written.
    OperationFailed,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Execute one transport-neutral GTKG operation.
    #[command(
        after_help = "Read one OperationRequest JSON object from stdin with --request -, or from an exact file path.\n\nExample:\n  printf '%s\\n' '{\"protocol_version\":\"gtkg.protocol/v1\",\"operation_id\":\"system.describe\",\"request_id\":\"help-example\",\"locks\":{},\"payload\":{}}' | gtkg op system.describe --request - --output json"
    )]
    Op {
        /// Public operation ID; use system.describe or MCP tools/list for the current schema.
        operation_id: String,
        /// OperationRequest JSON path, or - for stdin.
        #[arg(long, default_value = "-")]
        request: String,
        /// Structured output format. V0.1 supports only --output json.
        #[arg(long, default_value = "json")]
        output: String,
    },
    /// Execute one explicit V0.2 transport-neutral GTKG operation.
    #[command(
        after_help = "Read one OperationRequestV2 JSON object from stdin with --request -, or from an exact file path. V2 must be selected explicitly and never falls back to v1."
    )]
    V2Op {
        /// V2 public operation ID; use `gtkg mcp serve --protocol v2 --stdio` for discovery.
        operation_id: String,
        /// Discovery profile; omission is the exact default `core` profile.
        #[arg(long)]
        profile: Option<String>,
        /// Optional caller-pinned profile digest; requires an explicit profile.
        #[arg(long, requires = "profile")]
        profile_digest: Option<String>,
        /// OperationRequestV2 JSON path, or - for stdin.
        #[arg(long, default_value = "-")]
        request: String,
        /// Structured output format. V0.2 supports only --output json.
        #[arg(long, default_value = "json")]
        output: String,
    },
    /// Discover the exact live v2 Tool projection for one V0.3 profile.
    V2Discover {
        /// Discovery profile. The exact default is core.
        #[arg(long, default_value = "core")]
        profile: String,
        /// Optional caller-pinned profile digest; drift fails closed.
        #[arg(long)]
        profile_digest: Option<String>,
        /// Structured output format. V0.3 supports only --output json.
        #[arg(long, default_value = "json")]
        output: String,
    },
    /// Run the MCP stdio adapter.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Run a local node adapter.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Serve MCP stdio with one JSON-RPC object per line; no network listener is opened.
    #[command(
        after_help = "MCP stdio exposes exactly the public GTKG Tools. Resources, Prompts, Sampling, Tasks, and network transports are not provided in V0.1."
    )]
    Serve {
        /// Explicitly select the frozen v1 or separately versioned v2 Tool surface.
        #[arg(long, default_value = "v1")]
        protocol: String,
        /// V0.3 v2 discovery profile. The exact default is core.
        #[arg(long, default_value = "core")]
        profile: String,
        /// Optional caller-pinned profile digest; drift fails closed.
        #[arg(long)]
        profile_digest: Option<String>,
        #[arg(long, default_value_t = true)]
        stdio: bool,
    },
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Serve the private Worker stdio frame for Coordinator-owned node.work.execute requests.
    #[command(
        after_help = "This private Worker endpoint is not an MCP Tool surface and never writes canonical knowledge."
    )]
    Serve {
        #[arg(long, default_value_t = true)]
        stdio: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(ExitOutcome::Success) => ExitCode::SUCCESS,
        Ok(ExitOutcome::OperationFailed) => ExitCode::from(1),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

/// Write one response envelope and decide the process outcome.
///
/// The envelope itself is always written so callers keep the full evidence and
/// recovery hint. Only `--strict-exit` turns a written error envelope into a
/// non-zero exit; without it the historical exit-0 behaviour is preserved.
fn report(value: &Value, strict_exit: bool) -> Result<ExitOutcome, String> {
    let failed = value.get("error").is_some();
    write_json_line(value)?;
    Ok(if strict_exit && failed {
        ExitOutcome::OperationFailed
    } else {
        ExitOutcome::Success
    })
}

fn run(cli: Cli) -> Result<ExitOutcome, String> {
    let strict_exit = cli.strict_exit;
    match cli.command {
        Command::Op {
            operation_id,
            request,
            output,
        } => run_operation(&operation_id, &request, &output, strict_exit),
        Command::V2Op {
            operation_id,
            profile,
            profile_digest,
            request,
            output,
        } => run_v2_operation(
            &operation_id,
            profile.as_deref(),
            profile_digest.as_deref(),
            &request,
            &output,
            strict_exit,
        ),
        Command::V2Discover {
            profile,
            profile_digest,
            output,
        } => run_v2_discovery(&profile, profile_digest.as_deref(), &output, strict_exit),
        Command::Mcp {
            command:
                McpCommand::Serve {
                    protocol,
                    profile,
                    profile_digest,
                    stdio,
                },
        } => {
            if !stdio {
                return Err("V0.1 only supports MCP over stdio".to_owned());
            }
            match protocol.as_str() {
                "v1" => serve_json_rpc(TransportKind::McpStdio),
                "v2" => {
                    serve_json_rpc_v2(TransportKind::McpStdio, &profile, profile_digest.as_deref())
                }
                _ => Err("MCP protocol must be exactly v1 or v2".to_owned()),
            }?;
            Ok(ExitOutcome::Success)
        }
        Command::Node {
            command: NodeCommand::Serve { stdio },
        } => {
            if !stdio {
                return Err("V0.1 only supports local node stdio".to_owned());
            }
            serve_node_stdio()?;
            Ok(ExitOutcome::Success)
        }
    }
}

fn run_v2_discovery(
    profile: &str,
    profile_digest: Option<&str>,
    output: &str,
    strict_exit: bool,
) -> Result<ExitOutcome, String> {
    if output != "json" {
        return Err("only --output json is supported".to_owned());
    }
    match gtkg_app::v2_profile_discovery(Some(profile), profile_digest) {
        Ok(discovery) => report(&discovery, strict_exit),
        Err(error) => Err(serde_json::to_string(&error)
            .unwrap_or_else(|encode_error| format!("profile discovery failed: {encode_error}"))),
    }
}

fn run_operation(
    operation_name: &str,
    request_source: &str,
    output: &str,
    strict_exit: bool,
) -> Result<ExitOutcome, String> {
    if output != "json" {
        return Err("only --output json is supported".to_owned());
    }
    let operation = OperationId::parse(operation_name)
        .ok_or_else(|| format!("unknown public operation: {operation_name}"))?;
    let request_bytes = if request_source == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        bytes
    } else {
        fs::read(PathBuf::from(request_source))
            .map_err(|error| format!("failed to read request file: {error}"))?
    };
    let request: OperationRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("invalid OperationRequest JSON: {error}"))?;
    if request.operation_id != operation {
        return Err(format!(
            "operation path {} does not match envelope {}",
            operation.as_str(),
            request.operation_id.as_str()
        ));
    }
    let dispatcher = Dispatcher;
    let context = adapter_context(TransportKind::Cli)?;
    let mut value = match dispatcher.execute(&context, request) {
        Ok(response) => serde_json::to_value(response),
        Err(error) => serde_json::to_value(error),
    }
    .map_err(|error| format!("failed to encode response: {error}"))?;
    if operation == OperationId::SystemDescribe {
        attach_runtime_identity(&mut value)?;
    }
    report(&value, strict_exit)
}

fn run_v2_operation(
    operation_name: &str,
    profile: Option<&str>,
    profile_digest: Option<&str>,
    request_source: &str,
    output: &str,
    strict_exit: bool,
) -> Result<ExitOutcome, String> {
    if output != "json" {
        return Err("only --output json is supported".to_owned());
    }
    let request_bytes = read_request_bytes(request_source)?;
    let request_value: Value = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("invalid OperationRequestV2 JSON: {error}"))?;
    let request = match parse_v2_request(request_value) {
        Ok(request) => request,
        Err(error) => return report(&encode_v2_error(*error)?, strict_exit),
    };
    if request.operation_id != operation_name {
        return Err(format!(
            "operation path {operation_name} does not match envelope {}",
            request.operation_id
        ));
    }
    let profile = profile.unwrap_or("core");
    let operation = match request.resolve_operation() {
        Ok(operation) => operation,
        Err(error) => return report(&encode_v2_error(error)?, strict_exit),
    };
    v2_profile_call_discovery(profile, profile_digest, operation)
        .map_err(|error| serde_json::to_string(&error).unwrap_or_else(|_| error.to_string()))?;
    let dispatcher = Dispatcher;
    let context = adapter_context(TransportKind::Cli)?;
    let mut value = match dispatcher.execute_v2(&context, request) {
        Ok(response) => serde_json::to_value(response),
        Err(error) => serde_json::to_value(error),
    }
    .map_err(|error| format!("failed to encode v2 response: {error}"))?;
    attach_runtime_identity_v2(&mut value, Some(profile), profile_digest)?;
    report(&value, strict_exit)
}

fn parse_v2_request(value: Value) -> Result<OperationRequestV2, Box<V2ErrorEnvelope>> {
    let request_id = value
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    serde_json::from_value(value).map_err(|error| {
        Box::new(V2ErrorEnvelope::invalid_request(
            request_id,
            error.to_string(),
        ))
    })
}

fn encode_v2_error(error: V2ErrorEnvelope) -> Result<Value, String> {
    serde_json::to_value(error).map_err(|error| format!("failed to encode v2 response: {error}"))
}

fn read_request_bytes(request_source: &str) -> Result<Vec<u8>, String> {
    if request_source == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        Ok(bytes)
    } else {
        fs::read(PathBuf::from(request_source))
            .map_err(|error| format!("failed to read request file: {error}"))
    }
}

fn serve_json_rpc(transport: TransportKind) -> Result<(), String> {
    let context = adapter_context(transport)?;
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("failed to read JSON-RPC input: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                write_json_line(&json_rpc_error(Value::Null, -32700, &error.to_string()))?;
                continue;
            }
        };
        if let Err(message) = validate_json_rpc_request(&request) {
            let id = request
                .get("id")
                .filter(|id| id.is_string() || id.is_number() || id.is_null())
                .cloned()
                .unwrap_or(Value::Null);
            write_json_line(&json_rpc_error(id, -32600, message))?;
            continue;
        }
        if request.get("method").and_then(Value::as_str) == Some("notifications/initialized") {
            continue;
        }
        let response = handle_json_rpc(request, &context);
        write_json_line(&response)?;
    }
    Ok(())
}

fn serve_json_rpc_v2(
    transport: TransportKind,
    profile: &str,
    profile_digest: Option<&str>,
) -> Result<(), String> {
    let context = adapter_context(transport)?;
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("failed to read JSON-RPC input: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                write_json_line(&json_rpc_error(Value::Null, -32700, &error.to_string()))?;
                continue;
            }
        };
        if let Err(message) = validate_json_rpc_request(&request) {
            let id = request
                .get("id")
                .filter(|id| id.is_string() || id.is_number() || id.is_null())
                .cloned()
                .unwrap_or(Value::Null);
            write_json_line(&json_rpc_error(id, -32600, message))?;
            continue;
        }
        if request.get("method").and_then(Value::as_str) == Some("notifications/initialized") {
            continue;
        }
        let response = handle_json_rpc_v2(request, &context, profile, profile_digest);
        write_json_line(&response)?;
    }
    Ok(())
}

fn validate_json_rpc_request(request: &Value) -> Result<(), &'static str> {
    let object = request
        .as_object()
        .ok_or("JSON-RPC frame must be an object")?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
    {
        return Err("JSON-RPC frame contains an unknown top-level field");
    }
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("JSON-RPC frame requires jsonrpc=2.0");
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())
        .ok_or("JSON-RPC frame requires a non-empty method")?;
    if object
        .get("params")
        .is_some_and(|params| !params.is_object())
    {
        return Err("MCP JSON-RPC params must be an object");
    }
    if object
        .get("id")
        .is_some_and(|id| !(id.is_string() || id.is_number() || id.is_null()))
    {
        return Err("JSON-RPC id must be a string, number, or null");
    }
    if method == "notifications/initialized" {
        if object.contains_key("id") {
            return Err("notifications/initialized must not contain an id");
        }
    } else if !object.contains_key("id") {
        return Err("JSON-RPC requests require an id");
    }
    Ok(())
}

fn serve_node_stdio() -> Result<(), String> {
    let context = adapter_context(TransportKind::NodeStdio)?;
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("failed to read node frame: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                write_json_line(&node_error(Value::Null, &error.to_string()))?;
                continue;
            }
        };
        write_json_line(&handle_node_frame(value, &context))?;
    }
    Ok(())
}

fn handle_node_frame(value: Value, context: &CallContext) -> Value {
    let request_id = value.get("request_id").cloned().unwrap_or(Value::Null);
    match execute_node_frame(value, context) {
        Ok(result) => json!({
            "schema_version": "gtkg.node-stdio-response/v1",
            "request_id": request_id,
            "result": result,
        }),
        Err(message) => node_error(request_id, &message),
    }
}

fn execute_node_frame(value: Value, context: &CallContext) -> Result<ShardResult, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "node frame must be an object".to_owned())?;
    const FIELDS: [&str; 6] = [
        "schema_version",
        "request_id",
        "operation",
        "node_id",
        "attempt",
        "work_unit",
    ];
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err("node frame has unknown or missing fields".to_owned());
    }
    if object.get("schema_version").and_then(Value::as_str) != Some("gtkg.node-stdio-request/v1")
        || object.get("operation").and_then(Value::as_str) != Some("node.work.execute")
    {
        return Err("node stdio accepts only private node.work.execute v1 frames".to_owned());
    }
    let request_id = object
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "request_id must be a string".to_owned())?;
    if request_id.is_empty() {
        return Err("request_id must not be empty".to_owned());
    }
    let node_id = object
        .get("node_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "node_id must be a string".to_owned())?;
    let attempt = object
        .get("attempt")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "attempt must be a positive u32".to_owned())?;
    let work: WorkUnit = serde_json::from_value(
        object
            .get("work_unit")
            .cloned()
            .ok_or_else(|| "work_unit is required".to_owned())?,
    )
    .map_err(|error| format!("invalid WorkUnit: {error}"))?;
    work.validate()
        .map_err(|error| format!("invalid WorkUnit: {error}"))?;
    if work.kind != "static_extract" {
        return Err("V0.1 private worker supports only static_extract".to_owned());
    }
    let payload = work
        .payload
        .as_object()
        .ok_or_else(|| "static_extract payload must be an object".to_owned())?;
    if payload.len() != 1 || !payload.contains_key("source_path") {
        return Err("static_extract payload accepts only source_path".to_owned());
    }
    let source = payload
        .get("source_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "source_path must be a string".to_owned())?;
    let source = context
        .authorize_read(&source)
        .map_err(|error| format!("source path is unauthorized: {error}"))?;
    let extracted = gtkg_extract::extract_path(&source)
        .map_err(|error| format!("static extraction failed: {error}"))?;
    if extracted.source_sha256 != work.input_sha256 {
        return Err("WorkUnit input_sha256 does not match the exact source".to_owned());
    }
    let output = serde_json::to_value(extracted)
        .map_err(|error| format!("cannot encode static extraction: {error}"))?;
    ShardResult::new(&work, node_id, attempt, output)
        .map_err(|error| format!("cannot create ShardResult: {error}"))
}

fn node_error(request_id: Value, message: &str) -> Value {
    json!({
        "schema_version": "gtkg.node-stdio-response/v1",
        "request_id": request_id,
        "error": {
            "code": ErrorCode::InvalidRequest,
            "message": message,
            "retryable": false,
        }
    })
}

fn handle_json_rpc(request: Value, context: &CallContext) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return json_rpc_error(id, -32600, "missing method");
    };
    match method {
        "initialize" => match gtkg_app::runtime_identity() {
            Ok(identity) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "gtkg", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"tools": {"listChanged": false}},
                    "x-gtkg-identity": identity
                }
            }),
            Err(message) => json_rpc_error(id, -32603, &message),
        },
        "tools/list" => {
            let tools = gtkg_app::mcp_tools();
            json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}})
        }
        "tools/call" => handle_tool_call(id, request.get("params"), context),
        _ => json_rpc_error(id, -32601, "method not found"),
    }
}

fn handle_json_rpc_v2(
    request: Value,
    context: &CallContext,
    profile: &str,
    profile_digest: Option<&str>,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return json_rpc_error(id, -32600, "missing method");
    };
    match method {
        "initialize" => {
            match gtkg_app::runtime_identity_v2_for_profile(Some(profile), profile_digest) {
                Ok(identity) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": "gtkg", "version": env!("CARGO_PKG_VERSION")},
                        "capabilities": {"tools": {"listChanged": false}},
                        "x-gtkg-identity": identity
                    }
                }),
                Err(message) => json_rpc_error(id, -32603, &message),
            }
        }
        "tools/list" => match gtkg_app::v2_profile_discovery(Some(profile), profile_digest) {
            Ok(discovery) => json!({"jsonrpc": "2.0", "id": id, "result": discovery}),
            Err(error) => {
                json_rpc_error_data(id, -32003, "GTKG v2 profile discovery failed closed", error)
            }
        },
        "tools/call" => {
            handle_tool_call_v2(id, request.get("params"), context, profile, profile_digest)
        }
        _ => json_rpc_error(id, -32601, "method not found"),
    }
}

fn handle_tool_call(id: Value, params: Option<&Value>, context: &CallContext) -> Value {
    let Some(params) = params else {
        return json_rpc_error(id, -32602, "missing params");
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return json_rpc_error(id, -32602, "missing tool name");
    };
    let Some(operation) = OperationId::from_mcp_tool_name(tool_name) else {
        return json_rpc_error(id, -32602, "unknown GTKG tool");
    };
    let Some(arguments) = params.get("arguments") else {
        return json_rpc_error(id, -32602, "missing OperationRequest arguments");
    };
    let request: OperationRequest = match serde_json::from_value(arguments.clone()) {
        Ok(request) => request,
        Err(error) => return json_rpc_error(id, -32602, &error.to_string()),
    };
    if request.operation_id != operation {
        return json_rpc_error(id, -32602, "tool name and operation_id do not match");
    }
    let dispatcher = Dispatcher;
    let (mut structured, is_error) = match dispatcher.execute(context, request) {
        Ok(response) => match serde_json::to_value(response) {
            Ok(value) => (value, false),
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        },
        Err(error) => match serde_json::to_value(error) {
            Ok(value) => (value, true),
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        },
    };
    if operation == OperationId::SystemDescribe
        && let Err(message) = attach_runtime_identity(&mut structured)
    {
        return json_rpc_error(id, -32603, &message);
    }
    let text = match serde_json::to_string(&structured) {
        Ok(text) => text,
        Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
    };
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
            "isError": is_error
        }
    })
}

fn handle_tool_call_v2(
    id: Value,
    params: Option<&Value>,
    context: &CallContext,
    profile: &str,
    profile_digest: Option<&str>,
) -> Value {
    let Some(params) = params else {
        return json_rpc_error(id, -32602, "missing params");
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return json_rpc_error(id, -32602, "missing tool name");
    };
    let Some(operation) = V2OperationId::from_mcp_tool_name(tool_name) else {
        return json_rpc_error(id, -32602, "unknown GTKG v2 tool");
    };
    let _discovery = match v2_profile_call_discovery(profile, profile_digest, operation) {
        Ok(discovery) => discovery,
        Err(error) => {
            let code = if error["code"] == "E_OPERATION_NOT_IN_PROFILE" {
                -32602
            } else {
                -32003
            };
            let message = if code == -32602 {
                "GTKG v2 tool is not exposed by the selected profile"
            } else {
                "GTKG v2 profile discovery failed closed"
            };
            return json_rpc_error_data(id, code, message, error);
        }
    };
    let Some(arguments) = params.get("arguments") else {
        return json_rpc_error(id, -32602, "missing OperationRequestV2 arguments");
    };
    let request = match parse_v2_request(arguments.clone()) {
        Ok(request) => request,
        Err(error) => match encode_v2_error(*error) {
            Ok(structured) => return mcp_v2_result(id, structured, true),
            Err(error) => return json_rpc_error(id, -32603, &error),
        },
    };
    if request.operation_id != operation.as_str() {
        return json_rpc_error(id, -32602, "tool name and operation_id do not match");
    }
    let dispatcher = Dispatcher;
    let (mut structured, is_error) = match dispatcher.execute_v2(context, request) {
        Ok(response) => match serde_json::to_value(response) {
            Ok(value) => (value, false),
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        },
        Err(error) => match serde_json::to_value(error) {
            Ok(value) => (value, true),
            Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
        },
    };
    if let Err(error) = attach_runtime_identity_v2(&mut structured, Some(profile), profile_digest) {
        return json_rpc_error(id, -32603, &error);
    }
    mcp_v2_result(id, structured, is_error)
}

fn v2_profile_call_discovery(
    profile: &str,
    profile_digest: Option<&str>,
    operation: V2OperationId,
) -> Result<Value, Value> {
    let discovery = gtkg_app::v2_profile_discovery(Some(profile), profile_digest)?;
    let operation_is_visible = discovery["tools"].as_array().is_some_and(|tools| {
        tools
            .iter()
            .any(|tool| tool["x-gtkg-operation-id"] == operation.as_str())
    });
    if operation_is_visible {
        return Ok(discovery);
    }
    Err(json!({
        "schema_version": "gtkg.profile-call-error/v1",
        "code": "E_OPERATION_NOT_IN_PROFILE",
        "profile_id": discovery["profile_id"],
        "profile_digest": discovery["profile_digest"],
        "operation_id": operation.as_str(),
        "tool_name": operation.mcp_tool_name(),
        "recovery_hint": "select a profile that explicitly contains this operation",
    }))
}

fn mcp_v2_result(id: Value, structured: Value, is_error: bool) -> Value {
    let text = match serde_json::to_string(&structured) {
        Ok(text) => text,
        Err(error) => return json_rpc_error(id, -32603, &error.to_string()),
    };
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
            "isError": is_error
        }
    })
}

fn attach_runtime_identity(response: &mut Value) -> Result<(), String> {
    if response.get("status").and_then(Value::as_str) != Some("completed") {
        return Ok(());
    }
    let result = response
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "system.describe response has no result object".to_owned())?;
    result.insert("identity".to_owned(), gtkg_app::runtime_identity()?);
    Ok(())
}

/// A successful v2 operation is bound to the executable and exact public
/// schema that processed it. Errors already contain closed transport evidence
/// and intentionally do not claim a result runtime receipt.
fn attach_runtime_identity_v2(
    response: &mut Value,
    profile: Option<&str>,
    profile_digest: Option<&str>,
) -> Result<(), String> {
    if response.get("error").is_some() {
        return Ok(());
    }
    let result = response
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "v2 response has no result object".to_owned())?;
    let runtime = gtkg_app::runtime_identity_v2_for_profile(profile, profile_digest)?;
    result.insert("runtime".to_owned(), runtime);
    Ok(())
}

fn adapter_context(transport: TransportKind) -> Result<CallContext, String> {
    let root = std::env::current_dir()
        .map_err(|error| format!("failed to resolve the authorized working directory: {error}"))?;
    CallContext::restricted(transport, vec![root], EffectPolicy::WorkspaceWrite)
        .map_err(|error| format!("invalid authorized working directory: {error}"))
}

fn json_rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn json_rpc_error_data(id: Value, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message, "data": data},
    })
}

fn write_json_line(value: &Value) -> Result<(), String> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)
        .map_err(|error| format!("failed to encode JSON output: {error}"))?;
    lock.write_all(b"\n")
        .map_err(|error| format!("failed to write JSON output: {error}"))?;
    lock.flush()
        .map_err(|error| format!("failed to flush JSON output: {error}"))
}
