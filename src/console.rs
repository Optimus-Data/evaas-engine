use crate::engine::validate_field;
use crate::models::{Options, PipelineOp, RuleDefinition, ValidateFieldResponse};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct ConsoleState {
    pub store: Arc<Mutex<ConsoleStore>>,
}

#[derive(Default)]
pub struct ConsoleStore {
    pub drafts: HashMap<String, RuleDraft>,
    pub versions: HashMap<(String, String), Vec<RuleVersion>>,
    pub active: HashMap<(String, String), ActiveVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationDefinition {
    pub op_id: String,
    pub kind: String,
    pub title: String,
    pub description: String,
    pub input_type: String,
    pub output_type: String,
    #[serde(default)]
    pub args_schema: serde_json::Value,
    #[serde(default)]
    pub default_args: serde_json::Value,
    pub tags: Vec<String>,
    pub ui: OperationUi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationUi {
    pub group: String,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDraft {
    pub draft_id: String,
    pub tenant_id: String,
    pub rule_id: String,
    pub title: String,
    pub description: Option<String>,
    pub input_type: String,
    pub output_type: String,
    pub tags: Vec<String>,
    pub pipeline: Vec<DraftNode>,
    pub status: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftNode {
    pub node_id: String,
    pub op_id: String,
    #[serde(default)]
    pub args: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleVersion {
    pub rule_id: String,
    pub version: String,
    pub version_id: String,
    pub published_at: String,
    pub release_notes: Option<String>,
    pub rule_json: RuleDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveVersion {
    pub rule_id: String,
    pub version_id: String,
    pub version: String,
    pub activated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDraftRequest {
    pub rule_id: String,
    pub title: String,
    pub description: Option<String>,
    pub input_type: String,
    pub output_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub from_version: Option<String>,
    #[serde(default)]
    pub from_rule: Option<RuleDefinition>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftResponse {
    pub draft: RuleDraft,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDraftRequest {
    pub title: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub pipeline: Vec<DraftNode>,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRunRequest {
    pub value: serde_json::Value,
    #[serde(default)]
    pub options: Options,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRunResponse {
    pub result: ValidateFieldResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishRequest {
    pub version_bump: String,
    pub release_notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishResponse {
    pub version: RuleVersionSummary,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleVersionSummary {
    pub rule_id: String,
    pub version: String,
    pub version_id: String,
    pub published_at: String,
    pub release_notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRulesResponse {
    pub items: Vec<RuleListItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleListItem {
    pub rule_id: String,
    pub title: String,
    pub has_draft: bool,
    pub active_version: Option<String>,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListVersionsResponse {
    pub items: Vec<RuleVersionItem>,
    pub active_version_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleVersionItem {
    pub version_id: String,
    pub version: String,
    pub published_at: String,
    pub release_notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetActiveRequest {
    pub version_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetActiveResponse {
    pub active: ActiveVersion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResponse {
    pub rule: RuleDefinition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub rule: RuleDefinition,
    #[serde(default)]
    pub activate: bool,
    pub release_notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResponse {
    pub version: RuleVersionSummary,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpsResponse {
    pub items: Vec<OperationDefinition>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

pub async fn list_ops(
    headers: HeaderMap,
) -> Result<Json<OpsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_role(&headers, "viewer")?;
    Ok(Json(OpsResponse {
        items: default_ops(),
    }))
}

pub async fn list_rules(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
) -> Json<ListRulesResponse> {
    let claims = require_role(&headers, "viewer").ok();
    let tenant = claims
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let store = state.store.lock().unwrap();
    let mut items = Vec::new();

    let mut rule_map: HashMap<String, RuleListItem> = HashMap::new();
    for draft in store.drafts.values() {
        if draft.tenant_id != tenant {
            continue;
        }
        rule_map
            .entry(draft.rule_id.clone())
            .and_modify(|item| {
                item.has_draft = true;
                item.updated_at = draft.updated_at.clone();
                item.draft_id = Some(draft.draft_id.clone());
            })
            .or_insert(RuleListItem {
                rule_id: draft.rule_id.clone(),
                title: draft.title.clone(),
                has_draft: true,
                active_version: None,
                updated_at: draft.updated_at.clone(),
                draft_id: Some(draft.draft_id.clone()),
            });
    }

    for ((t, rule_id), versions) in store.versions.iter() {
        if t != &tenant {
            continue;
        }
        let title = versions
            .last()
            .map(|v| v.rule_json.title.clone())
            .unwrap_or_else(|| rule_id.clone());
        rule_map.entry(rule_id.clone()).or_insert(RuleListItem {
            rule_id: rule_id.clone(),
            title,
            has_draft: false,
            active_version: None,
            updated_at: versions
                .last()
                .map(|v| v.published_at.clone())
                .unwrap_or_else(now_iso),
            draft_id: None,
        });
    }

    for ((t, rule_id), active) in store.active.iter() {
        if t != &tenant {
            continue;
        }
        rule_map
            .entry(rule_id.clone())
            .and_modify(|item| item.active_version = Some(active.version.clone()));
    }

    items.extend(rule_map.into_values());

    Json(ListRulesResponse { items })
}

pub async fn create_draft(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(payload): Json<CreateDraftRequest>,
) -> Result<(StatusCode, Json<DraftResponse>), (StatusCode, Json<ErrorResponse>)> {
    let claims = require_role(&headers, "rule_editor")?;
    let tenant = claims.tenant_id;
    let mut store = state.store.lock().unwrap();

    let pipeline = if let Some(rule) = payload.from_rule.as_ref() {
        rule_json_to_draft_nodes(rule)
    } else if let Some(version) = payload.from_version.as_deref() {
        let key = (tenant.clone(), payload.rule_id.clone());
        let versions = store.versions.get(&key).ok_or_else(|| {
            bad_request("VERSION_NOT_FOUND", "version not found for rule")
        })?;
        let rule = versions
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| bad_request("VERSION_NOT_FOUND", "version not found for rule"))?;
        rule_json_to_draft_nodes(&rule.rule_json)
    } else {
        Vec::new()
    };

    let draft_id = format!("d_{}", Uuid::new_v4().simple());
    let draft = RuleDraft {
        draft_id: draft_id.clone(),
        tenant_id: tenant.clone(),
        rule_id: payload.rule_id,
        title: payload.title,
        description: payload.description,
        input_type: payload.input_type,
        output_type: payload.output_type,
        tags: payload.tags,
        pipeline,
        status: "draft".to_string(),
        updated_at: now_iso(),
    };

    store.drafts.insert(draft_id.clone(), draft.clone());
    Ok((StatusCode::CREATED, Json(DraftResponse { draft })))
}

pub async fn get_draft(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(draft_id): Path<String>,
) -> Result<Json<DraftResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_role(&headers, "viewer")?;
    let store = state.store.lock().unwrap();
    let draft = store.drafts.get(&draft_id).ok_or_else(|| {
        not_found("DRAFT_NOT_FOUND", "draft not found")
    })?;
    Ok(Json(DraftResponse { draft: draft.clone() }))
}

pub async fn update_draft(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(draft_id): Path<String>,
    Json(payload): Json<UpdateDraftRequest>,
) -> Result<Json<DraftResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_role(&headers, "rule_editor")?;
    let mut store = state.store.lock().unwrap();
    let draft = store.drafts.get_mut(&draft_id).ok_or_else(|| {
        not_found("DRAFT_NOT_FOUND", "draft not found")
    })?;

    if draft.updated_at != payload.updated_at {
        return Err(conflict("DRAFT_CONFLICT", "draft has been modified"));
    }

    draft.title = payload.title;
    draft.description = payload.description;
    draft.tags = payload.tags;
    draft.pipeline = payload.pipeline;
    draft.updated_at = now_iso();

    Ok(Json(DraftResponse { draft: draft.clone() }))
}

pub async fn dry_run_draft(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(draft_id): Path<String>,
    Json(payload): Json<DryRunRequest>,
) -> Result<Json<DryRunResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_role(&headers, "rule_editor")?;
    let store = state.store.lock().unwrap();
    let draft = store.drafts.get(&draft_id).ok_or_else(|| {
        not_found("DRAFT_NOT_FOUND", "draft not found")
    })?;

    let rule = compile_draft(draft);
    let result = validate_field(&rule, payload.value, &payload.options);
    Ok(Json(DryRunResponse { result }))
}

pub async fn publish_draft(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(draft_id): Path<String>,
    Json(payload): Json<PublishRequest>,
) -> Result<(StatusCode, Json<PublishResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_role(&headers, "publisher")?;
    let mut store = state.store.lock().unwrap();
    let draft = store.drafts.get(&draft_id).ok_or_else(|| {
        not_found("DRAFT_NOT_FOUND", "draft not found")
    })?;
    let draft_clone = draft.clone();

    let key = (draft_clone.tenant_id.clone(), draft_clone.rule_id.clone());
    let next_version = bump_version(
        store
            .versions
            .get(&key)
            .and_then(|v| v.last())
            .map(|v| v.version.as_str()),
        &payload.version_bump,
    )
    .ok_or_else(|| bad_request("VERSION_BUMP_INVALID", "invalid version bump"))?;

    let version_id = format!("v_{}", Uuid::new_v4().simple());
    let published_at = now_iso();
    let mut rule_json = compile_draft(&draft_clone);
    rule_json.version = next_version.clone();

    let version = RuleVersion {
        rule_id: draft_clone.rule_id.clone(),
        version: next_version.clone(),
        version_id: version_id.clone(),
        published_at: published_at.clone(),
        release_notes: payload.release_notes.clone(),
        rule_json,
    };

    store.versions.entry(key).or_default().push(version.clone());
    persist_rule(&draft_clone.tenant_id, &version.rule_id, &version.version, &version.rule_json)
        .map_err(|e| internal_error("PERSIST_FAILED", &e))?;

    Ok((
        StatusCode::CREATED,
        Json(PublishResponse {
            version: RuleVersionSummary {
                rule_id: version.rule_id,
                version: version.version,
                version_id: version.version_id,
                published_at: version.published_at,
                release_notes: version.release_notes,
            },
        }),
    ))
}

pub async fn list_versions(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(rule_id): Path<String>,
) -> Result<Json<ListVersionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = require_role(&headers, "viewer")?;
    let tenant = claims.tenant_id;
    let store = state.store.lock().unwrap();
    let key = (tenant.clone(), rule_id.clone());
    let versions = store.versions.get(&key).ok_or_else(|| {
        not_found("RULE_NOT_FOUND", "rule not found")
    })?;

    let items = versions
        .iter()
        .map(|v| RuleVersionItem {
            version_id: v.version_id.clone(),
            version: v.version.clone(),
            published_at: v.published_at.clone(),
            release_notes: v.release_notes.clone(),
        })
        .collect::<Vec<_>>();

    let active_version_id = store
        .active
        .get(&key)
        .map(|a| a.version_id.clone());

    Ok(Json(ListVersionsResponse {
        items,
        active_version_id,
    }))
}

pub async fn set_active(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(rule_id): Path<String>,
    Json(payload): Json<SetActiveRequest>,
) -> Result<Json<SetActiveResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = require_role(&headers, "publisher")?;
    let tenant = claims.tenant_id;
    let mut store = state.store.lock().unwrap();
    let key = (tenant.clone(), rule_id.clone());
    let versions = store.versions.get(&key).ok_or_else(|| {
        not_found("RULE_NOT_FOUND", "rule not found")
    })?;
    let version = versions
        .iter()
        .find(|v| v.version_id == payload.version_id)
        .ok_or_else(|| not_found("VERSION_NOT_FOUND", "version not found"))?;

    let active = ActiveVersion {
        rule_id: rule_id.clone(),
        version_id: version.version_id.clone(),
        version: version.version.clone(),
        activated_at: now_iso(),
    };

    store.active.insert(key, active.clone());

    Ok(Json(SetActiveResponse { active }))
}

pub async fn export_version(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path((rule_id, version_id)): Path<(String, String)>,
) -> Result<Json<ExportResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = require_role(&headers, "viewer")?;
    let tenant = claims.tenant_id;
    let store = state.store.lock().unwrap();
    let key = (tenant.clone(), rule_id.clone());
    let versions = store.versions.get(&key).ok_or_else(|| {
        not_found("RULE_NOT_FOUND", "rule not found")
    })?;
    let version = versions
        .iter()
        .find(|v| v.version_id == version_id)
        .ok_or_else(|| not_found("VERSION_NOT_FOUND", "version not found"))?;

    Ok(Json(ExportResponse {
        rule: version.rule_json.clone(),
    }))
}

pub async fn import_rule(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(payload): Json<ImportRequest>,
) -> Result<(StatusCode, Json<ImportResponse>), (StatusCode, Json<ErrorResponse>)> {
    let claims = require_role(&headers, "publisher")?;
    let tenant = claims.tenant_id;
    let mut store = state.store.lock().unwrap();

    let version_id = format!("v_{}", Uuid::new_v4().simple());
    let published_at = now_iso();

    let version = RuleVersion {
        rule_id: payload.rule.rule_id.clone(),
        version: payload.rule.version.clone(),
        version_id: version_id.clone(),
        published_at: published_at.clone(),
        release_notes: payload.release_notes.clone(),
        rule_json: payload.rule.clone(),
    };

    let key = (tenant.clone(), payload.rule.rule_id.clone());
    store.versions.entry(key.clone()).or_default().push(version.clone());
    persist_rule(&tenant, &version.rule_id, &version.version, &version.rule_json)
        .map_err(|e| internal_error("PERSIST_FAILED", &e))?;

    if payload.activate {
        let active = ActiveVersion {
            rule_id: version.rule_id.clone(),
            version_id: version.version_id.clone(),
            version: version.version.clone(),
            activated_at: now_iso(),
        };
        store.active.insert(key, active);
    }

    Ok((
        StatusCode::CREATED,
        Json(ImportResponse {
            version: RuleVersionSummary {
                rule_id: version.rule_id,
                version: version.version,
                version_id: version.version_id,
                published_at: version.published_at,
                release_notes: version.release_notes,
            },
        }),
    ))
}

fn compile_draft(draft: &RuleDraft) -> RuleDefinition {
    RuleDefinition {
        rule_id: draft.rule_id.clone(),
        title: draft.title.clone(),
        description: draft.description.clone(),
        input_type: draft.input_type.clone(),
        output_type: draft.output_type.clone(),
        tags: draft.tags.clone(),
        pipeline: draft
            .pipeline
            .iter()
            .filter(|n| n.enabled)
            .map(|n| PipelineOp {
                op: n.op_id.clone(),
                args: n.args.clone(),
                severity: None,
            })
            .collect(),
        on_fail: Some("keep_normalized".to_string()),
        version: "0.0.0".to_string(),
    }
}

fn rule_json_to_draft_nodes(rule: &RuleDefinition) -> Vec<DraftNode> {
    rule.pipeline
        .iter()
        .enumerate()
        .map(|(i, op)| DraftNode {
            node_id: format!("n{}", i + 1),
            op_id: op.op.clone(),
            args: op.args.clone(),
            enabled: true,
        })
        .collect()
}

fn bump_version(current: Option<&str>, bump: &str) -> Option<String> {
    let (mut major, mut minor, mut patch) = if let Some(v) = current {
        let parts: Vec<u64> = v
            .split('.')
            .filter_map(|p| p.parse::<u64>().ok())
            .collect();
        if parts.len() != 3 {
            return None;
        }
        (parts[0], parts[1], parts[2])
    } else {
        (1, 0, 0)
    };

    match bump {
        "major" => {
            major += 1;
            minor = 0;
            patch = 0;
        }
        "minor" => {
            minor += 1;
            patch = 0;
        }
        "patch" => {
            patch += 1;
        }
        _ => return None,
    }

    Some(format!("{}.{}.{}", major, minor, patch))
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Deserialize)]
struct Claims {
    tenant_id: String,
    #[serde(default)]
    roles: Vec<String>,
}

fn require_role(headers: &HeaderMap, required: &str) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_claims(headers)?;
    if has_required_role(&claims.roles, required) {
        Ok(claims)
    } else {
        Err(forbidden("RBAC_FORBIDDEN", "insufficient role"))
    }
}

fn decode_claims(headers: &HeaderMap) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").ok_or_else(|| {
        unauthorized("AUTH_REQUIRED", "missing Bearer token")
    })?;

    let secret = std::env::var("JWT_SECRET")
        .map_err(|_| unauthorized("JWT_SECRET_MISSING", "JWT_SECRET not configured"))?;
    let issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "https://evaas.io/auth".to_string());
    let audience = std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "evaasio-console".to_string());

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.leeway = 60;

    let token_data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| unauthorized("JWT_INVALID", "invalid token"))?;

    Ok(token_data.claims)
}

fn role_rank(role: &str) -> i32 {
    match role {
        "viewer" => 1,
        "rule_editor" => 2,
        "publisher" => 3,
        "tenant_admin" => 4,
        _ => 0,
    }
}

fn has_required_role(roles: &[String], required: &str) -> bool {
    let required_rank = role_rank(required);
    roles
        .iter()
        .map(|r| role_rank(r))
        .max()
        .unwrap_or(0)
        >= required_rank
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

fn conflict(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::CONFLICT,
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

fn internal_error(code: &str, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

fn persist_rule(
    tenant: &str,
    rule_id: &str,
    version: &str,
    rule: &RuleDefinition,
) -> Result<(), String> {
    let (path, scope) = rule_id_to_path(tenant, rule_id, version)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let data = serde_json::to_string_pretty(rule).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())?;
    match scope {
        RuleScope::Tenant => {
            update_tenant_indexes(tenant, rule_id, version, rule)?;
        }
        RuleScope::Catalog => {
            update_catalog_index(rule_id, version, &path)?;
        }
    }
    Ok(())
}

fn rule_id_to_path(
    tenant: &str,
    rule_id: &str,
    version: &str,
) -> Result<(PathBuf, RuleScope), String> {
    let parts: Vec<&str> = rule_id.split(':').collect();
    if parts.len() >= 4 && parts[0] == "t" {
        if parts[1] != tenant {
            return Err("tenant mismatch for ruleId".to_string());
        }
        let encoded_rule_id = encode_rule_id(rule_id);
        return Ok((
            PathBuf::from("tenants")
                .join(tenant)
                .join("versions")
                .join(encoded_rule_id)
                .join(format!("{}.json", version)),
            RuleScope::Tenant,
        ));
    }
    let rule_path = rule_id.replace('.', "/");
    Ok((
        PathBuf::from("catalog")
            .join("rules")
            .join(rule_path)
            .join(format!("{}.json", version)),
        RuleScope::Catalog,
    ))
}

enum RuleScope {
    Tenant,
    Catalog,
}

fn update_tenant_indexes(
    _tenant: &str,
    _rule_id: &str,
    _version: &str,
    _rule: &RuleDefinition,
) -> Result<(), String> {
    Ok(())
}

fn encode_rule_id(rule_id: &str) -> String {
    rule_id.replace('%', "%25").replace(':', "%3A")
}

fn update_catalog_index(rule_id: &str, version: &str, rule_path: &PathBuf) -> Result<(), String> {
    let catalog_index_path = PathBuf::from("catalog").join("index.json");
    let mut catalog_index: serde_json::Value = if catalog_index_path.exists() {
        serde_json::from_str(&fs::read_to_string(&catalog_index_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    } else {
        serde_json::json!({ "rules": [], "bundles": [] })
    };

    let rules = catalog_index
        .get_mut("rules")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "invalid catalog index rules".to_string())?;

    let rule_dir = rule_path
        .parent()
        .ok_or_else(|| "invalid rule path".to_string())?
        .to_string_lossy()
        .replace('\\', "/");

    if let Some(item) = rules
        .iter_mut()
        .find(|r| r.get("ruleId").and_then(|v| v.as_str()) == Some(rule_id))
    {
        let versions = item
            .get_mut("versions")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(|| "invalid versions array".to_string())?;
        if !versions.iter().any(|v| v.as_str() == Some(version)) {
            versions.push(serde_json::Value::String(version.to_string()));
        }
        versions.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        item["path"] = serde_json::Value::String(rule_dir);
    } else {
        rules.push(serde_json::json!({
            "ruleId": rule_id,
            "versions": [version],
            "path": rule_dir
        }));
    }

    fs::create_dir_all(catalog_index_path.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(
        &catalog_index_path,
        serde_json::to_string_pretty(&catalog_index).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

fn default_ops() -> Vec<OperationDefinition> {
    vec![
        OperationDefinition {
            op_id: "string.trim".to_string(),
            kind: "transform".to_string(),
            title: "Trim".to_string(),
            description: "Remove espaços no começo/fim".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "trim".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.alnum_only".to_string(),
            kind: "transform".to_string(),
            title: "Alfanumérico".to_string(),
            description: "Mantém apenas A-Z e 0-9".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "alnum".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.length".to_string(),
            kind: "validation".to_string(),
            title: "Tamanho (min/max)".to_string(),
            description: "Valida comprimento do valor normalizado".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "min": { "type": "number", "required": false, "min": 0 },
                "max": { "type": "number", "required": false, "min": 0 }
            }),
            default_args: serde_json::json!({ "min": 0, "max": 255 }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "ruler".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.required".to_string(),
            kind: "validation".to_string(),
            title: "Obrigatório".to_string(),
            description: "Campo obrigatório".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "required".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.cnpj.check_digit".to_string(),
            kind: "validation".to_string(),
            title: "CNPJ DV".to_string(),
            description: "Valida dígitos do CNPJ".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string(), "cnpj".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "cnpj".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.collapse_spaces".to_string(),
            kind: "transform".to_string(),
            title: "Collapse spaces".to_string(),
            description: "Colapsa múltiplos espaços".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "spaces".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.to_lower".to_string(),
            kind: "transform".to_string(),
            title: "Lowercase".to_string(),
            description: "Converte para minúsculas".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "lower".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.to_upper".to_string(),
            kind: "transform".to_string(),
            title: "Uppercase".to_string(),
            description: "Converte para maiúsculas".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "upper".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.title_case.ptbr".to_string(),
            kind: "transform".to_string(),
            title: "Title Case (PT-BR)".to_string(),
            description: "Capitalização PT-BR com exceções".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string(), "pt-br".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "title".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.remove_accents".to_string(),
            kind: "transform".to_string(),
            title: "Remove acentos".to_string(),
            description: "Remove acentos e diacríticos".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "accent".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.replace".to_string(),
            kind: "transform".to_string(),
            title: "Replace".to_string(),
            description: "Substitui texto".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "from": { "type": "string", "required": true },
                "to": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "from": "", "to": "" }),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "replace".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.map".to_string(),
            kind: "transform".to_string(),
            title: "Map (dicionário)".to_string(),
            description: "Mapeia valores por dicionário".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "map": { "type": "json", "required": true },
                "caseInsensitive": { "type": "boolean", "required": false },
                "onUnknown": { "type": "string", "required": false }
            }),
            default_args: serde_json::json!({
                "map": {},
                "caseInsensitive": true,
                "onUnknown": "error"
            }),
            tags: vec!["string".to_string(), "map".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "map".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.bimap".to_string(),
            kind: "transform".to_string(),
            title: "BiMap (pares)".to_string(),
            description: "Mapeia valores bidirecionais por pares".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "pairs": { "type": "json", "required": true },
                "caseInsensitive": { "type": "boolean", "required": false },
                "onUnknown": { "type": "string", "required": false }
            }),
            default_args: serde_json::json!({
                "pairs": [],
                "caseInsensitive": true,
                "onUnknown": "error"
            }),
            tags: vec!["string".to_string(), "map".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "bimap".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.remove_chars".to_string(),
            kind: "transform".to_string(),
            title: "Remove chars".to_string(),
            description: "Remove caracteres da lista".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "chars": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "chars": [] }),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "remove".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.keep_chars".to_string(),
            kind: "transform".to_string(),
            title: "Keep chars".to_string(),
            description: "Mantém apenas caracteres da lista".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "chars": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "chars": [] }),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "keep".to_string(),
            },
        },
        OperationDefinition {
            op_id: "string.slugify".to_string(),
            kind: "transform".to_string(),
            title: "Slugify".to_string(),
            description: "Gera slug".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["string".to_string()],
            ui: OperationUi {
                group: "Transformações".to_string(),
                icon: "slug".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.digits_only".to_string(),
            kind: "transform".to_string(),
            title: "Apenas dígitos".to_string(),
            description: "Remove tudo que não for dígito".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "digits".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.phone.digits_only".to_string(),
            kind: "transform".to_string(),
            title: "Telefone (digits only)".to_string(),
            description: "Remove máscara de telefone".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "phone".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.cep.normalize".to_string(),
            kind: "transform".to_string(),
            title: "CEP normalize".to_string(),
            description: "Normaliza CEP para 8 dígitos".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "cep".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.uf.normalize".to_string(),
            kind: "transform".to_string(),
            title: "UF normalize".to_string(),
            description: "Normaliza UF (SP/RJ etc)".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "uf".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.currency.normalize_brl".to_string(),
            kind: "transform".to_string(),
            title: "Moeda BRL".to_string(),
            description: "Normaliza moeda BRL".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "money".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.min_length".to_string(),
            kind: "validation".to_string(),
            title: "Tamanho mínimo".to_string(),
            description: "Valida tamanho mínimo".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "min": { "type": "number", "required": true, "min": 0 }
            }),
            default_args: serde_json::json!({ "min": 1 }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "min".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.max_length".to_string(),
            kind: "validation".to_string(),
            title: "Tamanho máximo".to_string(),
            description: "Valida tamanho máximo".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "max": { "type": "number", "required": true, "min": 0 }
            }),
            default_args: serde_json::json!({ "max": 255 }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "max".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.regex".to_string(),
            kind: "validation".to_string(),
            title: "Regex".to_string(),
            description: "Valida por regex".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "pattern": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "pattern": "" }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "regex".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.in_set".to_string(),
            kind: "validation".to_string(),
            title: "In set".to_string(),
            description: "Valida inclusão em conjunto".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "set": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "set": [] }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "list".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.not_in_set".to_string(),
            kind: "validation".to_string(),
            title: "Not in set".to_string(),
            description: "Valida exclusão de conjunto".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "set": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "set": [] }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "list-x".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.starts_with".to_string(),
            kind: "validation".to_string(),
            title: "Starts with".to_string(),
            description: "Valida prefixo".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({
                "prefix": { "type": "string", "required": true }
            }),
            default_args: serde_json::json!({ "prefix": "" }),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "start".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.email.simple".to_string(),
            kind: "validation".to_string(),
            title: "Email simples".to_string(),
            description: "Valida e-mail (regex simples)".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "email".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.numeric".to_string(),
            kind: "validation".to_string(),
            title: "Numérico".to_string(),
            description: "Valida string numérica".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "numeric".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.integer".to_string(),
            kind: "validation".to_string(),
            title: "Inteiro".to_string(),
            description: "Valida número inteiro".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "integer".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.decimal".to_string(),
            kind: "validation".to_string(),
            title: "Decimal".to_string(),
            description: "Valida número decimal".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "decimal".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.date.iso".to_string(),
            kind: "validation".to_string(),
            title: "Data ISO".to_string(),
            description: "Valida data ISO (YYYY-MM-DD)".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "date".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.uuid".to_string(),
            kind: "validation".to_string(),
            title: "UUID".to_string(),
            description: "Valida UUID".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string()],
            ui: OperationUi {
                group: "Validações".to_string(),
                icon: "uuid".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.cc.luhn".to_string(),
            kind: "validation".to_string(),
            title: "Cartão (Luhn)".to_string(),
            description: "Valida número de cartão pelo algoritmo Luhn".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string(), "payment".to_string()],
            ui: OperationUi {
                group: "Pagamentos".to_string(),
                icon: "card".to_string(),
            },
        },
        OperationDefinition {
            op_id: "validate.url".to_string(),
            kind: "validation".to_string(),
            title: "URL".to_string(),
            description: "Valida URL absoluta (http/https)".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["validate".to_string(), "url".to_string()],
            ui: OperationUi {
                group: "Net".to_string(),
                icon: "url".to_string(),
            },
        },
        OperationDefinition {
            op_id: "net.email".to_string(),
            kind: "validation".to_string(),
            title: "Email (pipeline)".to_string(),
            description: "Trim + lower + valida".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["net".to_string()],
            ui: OperationUi {
                group: "Contato".to_string(),
                icon: "email".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.phone.mobile".to_string(),
            kind: "validation".to_string(),
            title: "Telefone celular".to_string(),
            description: "Valida celular BR".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Contato".to_string(),
                icon: "phone".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.phone.any".to_string(),
            kind: "validation".to_string(),
            title: "Telefone (fixo/celular)".to_string(),
            description: "Valida telefone BR".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Contato".to_string(),
                icon: "phone".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.cpf.check_digit".to_string(),
            kind: "validation".to_string(),
            title: "CPF DV".to_string(),
            description: "Valida dígitos do CPF".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string(), "cpf".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "cpf".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.document".to_string(),
            kind: "validation".to_string(),
            title: "Documento (CPF/CNPJ)".to_string(),
            description: "Detecta CPF/CNPJ por tamanho e valida".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "doc".to_string(),
            },
        },
        OperationDefinition {
            op_id: "text.person_name.ptbr".to_string(),
            kind: "transform".to_string(),
            title: "Nome pessoa (PT-BR)".to_string(),
            description: "Trim + collapse + title case".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["text".to_string(), "pt-br".to_string()],
            ui: OperationUi {
                group: "Texto".to_string(),
                icon: "person".to_string(),
            },
        },
        OperationDefinition {
            op_id: "text.company_name.ptbr".to_string(),
            kind: "transform".to_string(),
            title: "Nome empresa (PT-BR)".to_string(),
            description: "Trim + collapse + normalizações".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["text".to_string(), "pt-br".to_string()],
            ui: OperationUi {
                group: "Texto".to_string(),
                icon: "company".to_string(),
            },
        },
        OperationDefinition {
            op_id: "text.no_double_spaces".to_string(),
            kind: "transform".to_string(),
            title: "Sem espaços duplos".to_string(),
            description: "Colapsa espaços duplos".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["text".to_string()],
            ui: OperationUi {
                group: "Texto".to_string(),
                icon: "spaces".to_string(),
            },
        },
        OperationDefinition {
            op_id: "text.abbrev.normalize.ptbr".to_string(),
            kind: "transform".to_string(),
            title: "Abreviações PT-BR".to_string(),
            description: "Normaliza abreviações comuns".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["text".to_string(), "pt-br".to_string()],
            ui: OperationUi {
                group: "Texto".to_string(),
                icon: "abbr".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.address.street.ptbr".to_string(),
            kind: "transform".to_string(),
            title: "Rua/logradouro".to_string(),
            description: "Normaliza logradouro PT-BR".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string(), "endereco".to_string()],
            ui: OperationUi {
                group: "Endereço".to_string(),
                icon: "street".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.address.number".to_string(),
            kind: "transform".to_string(),
            title: "Número (endereço)".to_string(),
            description: "Normaliza número do endereço".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string(), "endereco".to_string()],
            ui: OperationUi {
                group: "Endereço".to_string(),
                icon: "number".to_string(),
            },
        },
        OperationDefinition {
            op_id: "br.pix.key".to_string(),
            kind: "validation".to_string(),
            title: "PIX key".to_string(),
            description: "Valida e normaliza chave PIX".to_string(),
            input_type: "string".to_string(),
            output_type: "string".to_string(),
            args_schema: serde_json::json!({}),
            default_args: serde_json::json!({}),
            tags: vec!["brasil".to_string(), "pix".to_string(), "pagamento".to_string()],
            ui: OperationUi {
                group: "Brasil".to_string(),
                icon: "pix".to_string(),
            },
        },
    ]
}
