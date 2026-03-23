use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Strict,
    Lenient,
    NormalizeOnly,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub locale: Option<String>,
    pub mode: Option<Mode>,
    pub fail_fast: Option<bool>,
    pub debug: Option<bool>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub source: Option<String>,
    pub field_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateFieldRequest {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule: Option<RuleDefinition>,
    pub value: JsonValue,
    #[serde(default)]
    pub options: Options,
    #[serde(default)]
    pub meta: Meta,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateBatchRequest {
    pub items: Vec<BatchItem>,
    #[serde(default)]
    pub options: Options,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchItem {
    pub id: String,
    pub rule_id: String,
    pub value: JsonValue,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorItem {
    pub code: String,
    pub message: String,
    pub severity: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_steps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateFieldResponse {
    pub ok: bool,
    pub rule_id: String,
    pub input: JsonValue,
    pub normalized: Option<String>,
    pub output: Option<JsonValue>,
    pub errors: Vec<ErrorItem>,
    pub warnings: Vec<ErrorItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Info>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<TraceItem>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateBatchResponse {
    pub ok: bool,
    pub results: Vec<BatchResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    pub id: String,
    pub ok: bool,
    pub rule_id: String,
    pub input: JsonValue,
    pub normalized: Option<String>,
    pub output: Option<JsonValue>,
    pub errors: Vec<ErrorItem>,
    pub warnings: Vec<ErrorItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Info>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<TraceItem>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceItem {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default)]
    pub errors: Vec<ErrorItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDefinition {
    pub rule_id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub input_type: String,
    pub output_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub pipeline: Vec<PipelineOp>,
    #[serde(default)]
    pub on_fail: Option<String>,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PipelineOp {
    pub op: String,
    #[serde(default)]
    pub args: JsonValue,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleIndexItem {
    pub rule_id: String,
    pub versions: Vec<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleIndexItem {
    pub bundle_id: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogIndex {
    pub rules: Vec<RuleIndexItem>,
    pub bundles: Vec<BundleIndexItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogRuleResponse {
    pub rule: RuleDefinition,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogStats {
    pub rules: usize,
    pub versions: usize,
    pub approx_bytes: usize,
}
