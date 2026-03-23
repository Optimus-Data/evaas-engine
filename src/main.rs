use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod catalog;
mod engine;
mod models;
mod console;

use catalog::Catalog;
use engine::{validate_batch, validate_field};
use models::{
    BatchResult, CatalogIndex, CatalogRuleResponse, CatalogStats, ErrorItem, ValidateBatchRequest,
    ValidateBatchResponse, ValidateFieldRequest, ValidateFieldResponse,
};
use console::{
    ConsoleState, create_draft, dry_run_draft, export_version, get_draft, import_rule, list_ops,
    list_rules, list_versions, publish_draft, set_active, update_draft,
};

#[derive(Clone)]
struct AppState {
    catalog: Arc<RwLock<Catalog>>,
    catalog_root: Arc<String>,
    runtime_admin: Arc<RwLock<RuntimeAdminState>>,
    console: ConsoleState,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeAdminState {
    current_generation: Option<i64>,
    bundle_version: Option<String>,
    tenant_slug: Option<String>,
    environment: Option<String>,
    last_import_at: Option<String>,
    last_reload_at: Option<String>,
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let catalog_root = std::env::var("RUNTIME_RULES_DIR").unwrap_or_else(|_| ".".to_string());
    let catalog = match Catalog::load(&catalog_root) {
        Ok(c) => c,
        Err(err) => {
            error!(error = %err, catalog_root = %catalog_root, "failed to load catalog");
            std::process::exit(1);
        }
    };

    let state = AppState {
        catalog: Arc::new(RwLock::new(catalog)),
        catalog_root: Arc::new(catalog_root),
        runtime_admin: Arc::new(RwLock::new(RuntimeAdminState::default())),
        console: ConsoleState {
            store: Arc::new(std::sync::Mutex::new(console::ConsoleStore::default())),
        },
    };

    let app = Router::new()
        .route("/v1/validate/field", post(handle_validate_field))
        .route("/v1/validate/batch", post(handle_validate_batch))
        .route("/v1/public/catalog/rules", axum::routing::get(handle_list_public_rules))
        .route(
            "/v1/public/catalog/rules/:ruleId",
            axum::routing::get(handle_get_public_rule),
        )
        .route(
            "/v1/public/catalog/stats",
            axum::routing::get(handle_public_catalog_stats),
        )
        .route("/v1/catalog/rules", axum::routing::get(handle_list_rules))
        .route("/v1/catalog/rules/:ruleId", axum::routing::get(handle_get_rule))
        .route("/v1/catalog/stats", axum::routing::get(handle_catalog_stats))
        .route("/internal/import-bundle", post(handle_import_bundle))
        .route("/internal/reload", post(handle_reload_catalog))
        .route("/internal/status", axum::routing::get(handle_internal_status))
        .route("/console-api/v1/ops", axum::routing::get(list_ops))
        .route("/console-api/v1/rules", axum::routing::get(list_rules))
        .route("/console-api/v1/drafts", post(create_draft))
        .route(
            "/console-api/v1/drafts/:draftId",
            axum::routing::get(get_draft).put(update_draft),
        )
        .route("/console-api/v1/drafts/:draftId/dry-run", post(dry_run_draft))
        .route("/console-api/v1/drafts/:draftId/publish", post(publish_draft))
        .route(
            "/console-api/v1/rules/:ruleId/versions",
            axum::routing::get(list_versions),
        )
        .route("/console-api/v1/rules/:ruleId/active", post(set_active))
        .route(
            "/console-api/v1/rules/:ruleId/versions/:versionId/export",
            axum::routing::get(export_version),
        )
        .route("/console-api/v1/rules/import", post(import_rule))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:63342".parse().unwrap(),
                    "http://127.0.0.1:63342".parse().unwrap(),
                ])
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::HeaderName::from_static("x-tenant-id"),
                    axum::http::header::HeaderName::from_static("x-request-id"),
                ]),
        )
        .layer(TraceLayer::new_for_http());

    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(10002);
    let bind_ip = std::env::var("BIND_ADDR")
        .ok()
        .and_then(|v| v.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let addr = SocketAddr::new(bind_ip, port);
    info!(%addr, "server listening");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_validate_field(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ValidateFieldQuery>,
    Json(payload): Json<ValidateFieldRequest>,
) -> Result<Json<ValidateFieldResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = resolve_runtime_tenant(&headers, query.dry_run.unwrap_or(false))?;
    let version = payload.options.version.as_deref();
    let catalog = state.catalog.read().await;

    let response = if query.dry_run.unwrap_or(false) {
        if let Some(rule) = payload.rule {
            validate_field(&rule, payload.value, &payload.options)
        } else if let Some(rule_id) = payload.rule_id.as_deref() {
            match catalog.resolve_rule(tenant.as_deref(), rule_id, version) {
                Some(rule) => validate_field(&rule, payload.value, &payload.options),
                None => missing_rule_response(rule_id, payload.value),
            }
        } else {
            return Err(bad_request("RULE_OR_RULEID_REQUIRED", "rule or ruleId is required"));
        }
    } else {
        let rule_id = payload
            .rule_id
            .as_deref()
            .ok_or_else(|| bad_request("RULEID_REQUIRED", "ruleId is required"))?;
        if payload.rule.is_some() {
            return Err(bad_request(
                "RULE_NOT_ALLOWED",
                "rule is only allowed in dryRun mode",
            ));
        }
        match catalog.resolve_rule(tenant.as_deref(), rule_id, version) {
            Some(rule) => validate_field(&rule, payload.value, &payload.options),
            None => missing_rule_response(rule_id, payload.value),
        }
    };

    Ok(Json(response))
}

async fn handle_validate_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ValidateBatchRequest>,
) -> Result<Json<ValidateBatchResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = resolve_runtime_tenant(&headers, false)?;
    let version = payload.options.version.as_deref();
    let catalog = state.catalog.read().await;

    let mut results: Vec<BatchResult> = Vec::with_capacity(payload.items.len());
    for item in payload.items {
        let result = match catalog.resolve_rule(tenant.as_deref(), &item.rule_id, version) {
            Some(rule) => validate_batch(&rule, item.value, &payload.options, item.id),
            None => missing_rule_batch_result(item.id, &item.rule_id, item.value),
        };
        results.push(result);
    }

    let ok = results.iter().all(|r| r.ok);
    Ok(Json(ValidateBatchResponse { ok, results }))
}

async fn handle_list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CatalogIndex>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = resolve_runtime_tenant(&headers, false)?;
    let catalog = state.catalog.read().await;
    let rules = catalog.list_rules(tenant.as_deref());
    Ok(Json(CatalogIndex {
        rules,
        bundles: Vec::new(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleQuery {
    version: Option<String>,
}

async fn handle_get_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<RuleQuery>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Result<Json<CatalogRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = resolve_runtime_tenant(&headers, false)?;
    let catalog = state.catalog.read().await;
    let rule = catalog
        .resolve_rule(tenant.as_deref(), &rule_id, query.version.as_deref())
        .ok_or_else(|| not_found("RULE_NOT_FOUND", "rule not found"))?;
    Ok(Json(CatalogRuleResponse { rule }))
}

async fn handle_catalog_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CatalogStats>, (StatusCode, Json<ErrorResponse>)> {
    let tenant = resolve_runtime_tenant(&headers, false)?;
    let catalog = state.catalog.read().await;
    Ok(Json(catalog.stats(tenant.as_deref())))
}

async fn handle_list_public_rules(State(state): State<AppState>) -> Json<CatalogIndex> {
    let catalog = state.catalog.read().await;
    let rules = catalog.list_rules(None);
    Json(CatalogIndex {
        rules,
        bundles: Vec::new(),
    })
}

async fn handle_get_public_rule(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<RuleQuery>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Result<Json<CatalogRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let catalog = state.catalog.read().await;
    let rule = catalog
        .resolve_rule(None, &rule_id, query.version.as_deref())
        .ok_or_else(|| not_found("RULE_NOT_FOUND", "rule not found"))?;
    Ok(Json(CatalogRuleResponse { rule }))
}

async fn handle_public_catalog_stats(State(state): State<AppState>) -> Json<CatalogStats> {
    let catalog = state.catalog.read().await;
    Json(catalog.stats(None))
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReloadResponse {
    ok: bool,
    catalog_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportBundleRequest {
    manifest: BundleManifest,
    rules: Vec<models::RuleDefinition>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleManifest {
    tenant_slug: String,
    environment: String,
    generation: i64,
    bundle_version: String,
    #[serde(default)]
    rules: Vec<BundleManifestRule>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleManifestRule {
    rule_id: String,
    version: String,
    path: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportBundleResponse {
    ok: bool,
    imported_rules: usize,
    generation: i64,
    bundle_version: String,
    tenant_slug: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct InternalStatusResponse {
    ok: bool,
    catalog_root: String,
    current_generation: Option<i64>,
    bundle_version: Option<String>,
    tenant_slug: Option<String>,
    environment: Option<String>,
    last_import_at: Option<String>,
    last_reload_at: Option<String>,
    rules: usize,
    versions: usize,
}

async fn handle_reload_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReloadResponse>, (StatusCode, Json<ErrorResponse>)> {
    authorize_internal(&headers)?;
    let next_catalog = Catalog::load(state.catalog_root.as_str()).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: ErrorBody {
                    code: "CATALOG_RELOAD_FAILED".to_string(),
                    message: err.to_string(),
                },
            }),
        )
    })?;
    let mut catalog = state.catalog.write().await;
    *catalog = next_catalog;
    let mut runtime_admin = state.runtime_admin.write().await;
    runtime_admin.last_reload_at = Some(Utc::now().to_rfc3339());
    Ok(Json(ReloadResponse {
        ok: true,
        catalog_root: state.catalog_root.as_str().to_string(),
    }))
}

async fn handle_import_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportBundleRequest>,
) -> Result<Json<ImportBundleResponse>, (StatusCode, Json<ErrorResponse>)> {
    authorize_internal(&headers)?;
    validate_import_bundle(&payload)?;
    import_bundle_to_filesystem(state.catalog_root.as_str(), &payload)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: ErrorBody {
                        code: "BUNDLE_IMPORT_FAILED".to_string(),
                        message: err.to_string(),
                    },
                }),
            )
        })?;

    let mut runtime_admin = state.runtime_admin.write().await;
    runtime_admin.current_generation = Some(payload.manifest.generation);
    runtime_admin.bundle_version = Some(payload.manifest.bundle_version.clone());
    runtime_admin.tenant_slug = Some(payload.manifest.tenant_slug.clone());
    runtime_admin.environment = Some(payload.manifest.environment.clone());
    runtime_admin.last_import_at = Some(Utc::now().to_rfc3339());

    Ok(Json(ImportBundleResponse {
        ok: true,
        imported_rules: payload.rules.len(),
        generation: payload.manifest.generation,
        bundle_version: payload.manifest.bundle_version,
        tenant_slug: payload.manifest.tenant_slug,
    }))
}

async fn handle_internal_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InternalStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    authorize_internal(&headers)?;
    let catalog = state.catalog.read().await;
    let stats = catalog.stats(None);
    let runtime_admin = state.runtime_admin.read().await;
    Ok(Json(InternalStatusResponse {
        ok: true,
        catalog_root: state.catalog_root.as_str().to_string(),
        current_generation: runtime_admin.current_generation,
        bundle_version: runtime_admin.bundle_version.clone(),
        tenant_slug: runtime_admin.tenant_slug.clone(),
        environment: runtime_admin.environment.clone(),
        last_import_at: runtime_admin.last_import_at.clone(),
        last_reload_at: runtime_admin.last_reload_at.clone(),
        rules: stats.rules,
        versions: stats.versions,
    }))
}

impl axum::extract::FromRef<AppState> for ConsoleState {
    fn from_ref(state: &AppState) -> ConsoleState {
        state.console.clone()
    }
}

fn header_value(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn missing_rule_response(
    rule_id: &str,
    value: serde_json::Value,
) -> ValidateFieldResponse {
    let mut errors = Vec::new();
    errors.push(ErrorItem {
        code: "RULE_NOT_FOUND".to_string(),
        message: format!("Regra não encontrada: {rule_id}"),
        severity: "error".to_string(),
        path: "$".to_string(),
        hint: None,
    });

    ValidateFieldResponse {
        ok: false,
        rule_id: rule_id.to_string(),
        input: value,
        normalized: None,
        output: None,
        errors,
        warnings: Vec::new(),
        info: None,
        trace: None,
    }
}

fn missing_rule_batch_result(
    id: String,
    rule_id: &str,
    value: serde_json::Value,
) -> BatchResult {
    let response = missing_rule_response(rule_id, value);
    BatchResult {
        id,
        ok: response.ok,
        rule_id: response.rule_id,
        input: response.input,
        normalized: response.normalized,
        output: response.output,
        errors: response.errors,
        warnings: response.warnings,
        info: response.info,
        trace: response.trace,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateFieldQuery {
    dry_run: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, serde::Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

fn bad_request(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

fn not_found(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

fn unauthorized(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

fn authorize_internal(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let expected = match std::env::var("ENGINE_RELOAD_TOKEN") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(()),
    };
    let actual = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match actual {
        Some(token) if token == expected => Ok(()),
        _ => Err(unauthorized("RELOAD_UNAUTHORIZED", "invalid reload token")),
    }
}

fn validate_import_bundle(
    payload: &ImportBundleRequest,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if payload.manifest.tenant_slug.trim().is_empty() {
        return Err(bad_request("TENANT_SLUG_REQUIRED", "manifest tenantSlug is required"));
    }
    if payload.manifest.bundle_version.trim().is_empty() {
        return Err(bad_request(
            "BUNDLE_VERSION_REQUIRED",
            "manifest bundleVersion is required",
        ));
    }
    let manifest_rule_ids: HashSet<&str> = payload
        .manifest
        .rules
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect();
    for rule in &payload.rules {
        if rule.rule_id.trim().is_empty() {
            return Err(bad_request("RULE_ID_REQUIRED", "bundle ruleId is required"));
        }
        if !manifest_rule_ids.is_empty() && !manifest_rule_ids.contains(rule.rule_id.as_str()) {
            return Err(bad_request(
                "BUNDLE_RULE_MISMATCH",
                "rules payload does not match manifest",
            ));
        }
    }
    Ok(())
}

async fn import_bundle_to_filesystem(root: &str, payload: &ImportBundleRequest) -> anyhow::Result<()> {
    let tenant_dir = Path::new(root)
        .join("tenants")
        .join(payload.manifest.tenant_slug.trim());
    let active_dir = tenant_dir.join("active");
    fs::create_dir_all(&active_dir)?;

    let expected_files: HashSet<String> = payload
        .rules
        .iter()
        .map(|rule| format!("{}.json", encode_rule_id(&rule.rule_id)))
        .collect();

    for entry in fs::read_dir(&active_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() {
            let filename = entry.file_name().to_string_lossy().to_string();
            if filename.ends_with(".json") && !expected_files.contains(&filename) {
                fs::remove_file(path)?;
            }
        }
    }

    for rule in &payload.rules {
        let file_path = active_dir.join(format!("{}.json", encode_rule_id(&rule.rule_id)));
        write_json_atomic(&file_path, rule).await?;
    }

    write_json_atomic(&tenant_dir.join("bundle-manifest.json"), &payload.manifest).await?;
    Ok(())
}

fn encode_rule_id(rule_id: &str) -> String {
    rule_id.replace('%', "%25").replace(':', "%3A")
}

async fn write_json_atomic<T: serde::Serialize>(path: &PathBuf, value: &T) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid target path"))?;
    fs::create_dir_all(parent)?;
    let temp_path = path.with_extension(format!(
        "{}tmp-{}",
        path.extension().and_then(|v| v.to_str()).unwrap_or(""),
        std::process::id()
    ));
    let body = format!("{}\n", serde_json::to_string_pretty(value)?);
    fs::write(&temp_path, body)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

#[derive(Debug, Deserialize, Clone)]
struct RuntimeClaims {
    tenant_id: String,
}

fn resolve_runtime_tenant(
    headers: &HeaderMap,
    allow_unauthenticated: bool,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    if allow_unauthenticated {
        return Ok(header_value(headers, "X-Tenant-Id"));
    }

    let claims = decode_runtime_claims(headers)?;
    let header_tenant = header_value(headers, "X-Tenant-Id");
    if let Some(ref tenant) = header_tenant {
        if tenant != &claims.tenant_id {
            return Err(forbidden(
                "TENANT_MISMATCH",
                "token tenant_id does not match X-Tenant-Id",
            ));
        }
    }
    Ok(Some(claims.tenant_id))
}

fn decode_runtime_claims(headers: &HeaderMap) -> Result<RuntimeClaims, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| unauthorized("AUTH_REQUIRED", "missing Bearer token"))?;

    let secret = std::env::var("JWT_SECRET")
        .map_err(|_| unauthorized("JWT_SECRET_MISSING", "JWT_SECRET not configured"))?;
    let issuer = std::env::var("RUNTIME_JWT_ISSUER")
        .or_else(|_| std::env::var("JWT_ISSUER"))
        .unwrap_or_else(|_| "https://evaas.io/auth".to_string());
    let audience = std::env::var("RUNTIME_JWT_AUDIENCE")
        .unwrap_or_else(|_| "evaasio-runtime".to_string());

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.leeway = 60;

    let token_data = jsonwebtoken::decode::<RuntimeClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| unauthorized("JWT_INVALID", "invalid token"))?;

    Ok(token_data.claims)
}

fn forbidden(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}
