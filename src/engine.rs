use crate::models::{
    BatchResult, ErrorItem, Info, Mode, Options, PipelineOp, RuleDefinition, TraceItem,
    ValidateFieldResponse,
};
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::fs;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

pub fn validate_field(
    rule: &RuleDefinition,
    input: JsonValue,
    options: &Options,
) -> ValidateFieldResponse {
    const ENGINE_VERSION: &str = "2026.02.0";
    let mode = options.mode.clone().unwrap_or(Mode::Strict);
    let fail_fast = options.fail_fast.unwrap_or(false);
    let debug = options.debug.unwrap_or(false);

    let mut current = json_value_to_string(&input);
    let mut errors: Vec<ErrorItem> = Vec::new();
    let mut warnings: Vec<ErrorItem> = Vec::new();
    let mut applied_steps: Vec<String> = Vec::new();
    let mut detected_type: Option<String> = None;
    let mut trace: Vec<TraceItem> = Vec::new();

    for op in &rule.pipeline {
        let before = current.clone();
        let err_len_before = errors.len();
        let warn_len_before = warnings.len();
        if debug {
            applied_steps.push(op.op.clone());
        }

        if is_validation_op(&op.op) && matches!(mode, Mode::NormalizeOnly) {
            continue;
        }

        let result = apply_op(
            op,
            &mut current,
            &mut detected_type,
            &mode,
            &mut errors,
            &mut warnings,
        );

        if debug {
            let mut op_errors = Vec::new();
            if errors.len() > err_len_before {
                op_errors.extend_from_slice(&errors[err_len_before..]);
            }
            if warnings.len() > warn_len_before {
                op_errors.extend_from_slice(&warnings[warn_len_before..]);
            }
            trace.push(TraceItem {
                op: op.op.clone(),
                before,
                after: current.clone(),
                errors: op_errors,
            });
        }

        if result.is_err() && fail_fast {
            break;
        }

        if fail_fast && !errors.is_empty() {
            break;
        }
    }

    let output = convert_output(&rule.output_type, current.as_deref(), &mode, &mut errors, &mut warnings);

    let ok = errors.is_empty();

    let info = if debug || detected_type.is_some() || !rule.version.is_empty() {
        Some(Info {
            detected_type,
            applied_steps: if debug { Some(applied_steps) } else { None },
            version: if rule.version.is_empty() { None } else { Some(rule.version.clone()) },
            engine_version: Some(ENGINE_VERSION.to_string()),
        })
    } else {
        None
    };

    ValidateFieldResponse {
        ok,
        rule_id: rule.rule_id.clone(),
        input,
        normalized: current,
        output,
        errors,
        warnings,
        info,
        trace: if debug { Some(trace) } else { None },
    }
}

pub fn validate_batch(
    rule: &RuleDefinition,
    input: JsonValue,
    options: &Options,
    id: String,
) -> BatchResult {
    let response = validate_field(rule, input.clone(), options);
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

fn json_value_to_string(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::Null => None,
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        other => Some(other.to_string()),
    }
}

fn is_validation_op(op: &str) -> bool {
    if op.starts_with("validate.") {
        return true;
    }
    matches!(op, "br.cpf.check_digit" | "br.cnpj.check_digit" | "br.document" | "br.phone.mobile" | "br.phone.any" | "br.uf.normalize" | "validate.cc.luhn" | "br.pix.key")
}

fn op_severity(op: &PipelineOp) -> Option<String> {
    op.severity.clone()
}

fn apply_op(
    op: &PipelineOp,
    current: &mut Option<String>,
    detected_type: &mut Option<String>,
    mode: &Mode,
    errors: &mut Vec<ErrorItem>,
    warnings: &mut Vec<ErrorItem>,
) -> Result<(), ()> {
    match op.op.as_str() {
        "string.trim" => {
            if let Some(val) = current {
                *val = val.trim().to_string();
            }
        }
        "string.collapse_spaces" => {
            if let Some(val) = current {
                let re = Regex::new(r"\s+").unwrap();
                *val = re.replace_all(val, " ").to_string();
            }
        }
        "string.to_lower" => {
            if let Some(val) = current {
                *val = val.to_lowercase();
            }
        }
        "string.to_upper" => {
            if let Some(val) = current {
                *val = val.to_uppercase();
            }
        }
        "string.title_case.ptbr" => {
            if let Some(val) = current {
                *val = title_case_ptbr(val);
            }
        }
        "string.remove_accents" => {
            if let Some(val) = current {
                *val = remove_accents(val);
            }
        }
        "string.replace" => {
            if let Some(val) = current {
                let from = op.args.get("from").and_then(|v| v.as_str()).unwrap_or("");
                let to = op.args.get("to").and_then(|v| v.as_str()).unwrap_or("");
                *val = val.replace(from, to);
            }
        }
        "string.remove_chars" => {
            if let Some(val) = current {
                let chars = args_string_list(&op.args, "chars");
                if !chars.is_empty() {
                    let set: HashSet<char> = chars.iter().filter_map(|s| s.chars().next()).collect();
                    *val = val.chars().filter(|c| !set.contains(c)).collect();
                }
            }
        }
        "string.keep_chars" => {
            if let Some(val) = current {
                let chars = args_string_list(&op.args, "chars");
                if !chars.is_empty() {
                    let set: HashSet<char> = chars.iter().filter_map(|s| s.chars().next()).collect();
                    *val = val.chars().filter(|c| set.contains(c)).collect();
                }
            }
        }
        "string.map" => {
            if let Some(val) = current {
                let case_insensitive = op
                    .args
                    .get("caseInsensitive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let on_unknown = op
                    .args
                    .get("onUnknown")
                    .and_then(|v| v.as_str())
                    .unwrap_or("error");
                let map = op.args.get("map").and_then(|v| v.as_object());
                let key = if case_insensitive {
                    val.to_lowercase()
                } else {
                    val.clone()
                };
                let mapped = map.and_then(|m| {
                    if case_insensitive {
                        m.iter()
                            .find(|(k, _)| k.to_lowercase() == key)
                            .map(|(_, v)| v)
                    } else {
                        m.get(&key)
                    }
                });
                if let Some(value) = mapped {
                    if let Some(s) = value.as_str() {
                        *val = s.to_string();
                    } else {
                        *val = value.to_string();
                    }
                } else {
                    match on_unknown {
                        "keep" => {}
                        "null" => {
                            *current = None;
                        }
                        _ => {
                            push_issue("MAP_UNKNOWN", "Valor fora do mapa", op_severity(op), mode, errors, warnings);
                            return Err(());
                        }
                    }
                }
            }
        }
        "string.bimap" => {
            if let Some(val) = current {
                let case_insensitive = op
                    .args
                    .get("caseInsensitive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let on_unknown = op
                    .args
                    .get("onUnknown")
                    .and_then(|v| v.as_str())
                    .unwrap_or("error");
                let pairs = op.args.get("pairs").and_then(|v| v.as_array());
                let key = if case_insensitive {
                    val.to_lowercase()
                } else {
                    val.clone()
                };
                let mut mapped: Option<String> = None;
                if let Some(pairs) = pairs {
                    for pair in pairs {
                        let arr = pair.as_array();
                        if arr.is_none() || arr.unwrap().len() != 2 {
                            continue;
                        }
                        let a = arr.unwrap()[0].as_str().unwrap_or("");
                        let b = arr.unwrap()[1].as_str().unwrap_or("");
                        let a_cmp = if case_insensitive { a.to_lowercase() } else { a.to_string() };
                        let b_cmp = if case_insensitive { b.to_lowercase() } else { b.to_string() };
                        if key == a_cmp {
                            mapped = Some(b.to_string());
                            break;
                        }
                        if key == b_cmp {
                            mapped = Some(a.to_string());
                            break;
                        }
                    }
                }
                if let Some(v) = mapped {
                    *val = v;
                } else {
                    match on_unknown {
                        "keep" => {}
                        "null" => *current = None,
                        _ => {
                            push_issue("MAP_UNKNOWN", "Valor fora do mapa", op_severity(op), mode, errors, warnings);
                            return Err(());
                        }
                    }
                }
            }
        }
        "string.slugify" => {
            if let Some(val) = current {
                *val = slugify(val);
            }
        }
        "validate.required" => {
            if is_empty(current) {
                push_issue("REQUIRED", "Campo obrigatório", op_severity(op), mode, errors, warnings);
                return Err(());
            }
        }
        "validate.min_length" => {
            if let Some(val) = current {
                let min = op.args.get("min").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if val.chars().count() < min {
                    push_issue("MIN_LENGTH", "Tamanho abaixo do mínimo", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.max_length" => {
            if let Some(val) = current {
                let max = op.args.get("max").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if val.chars().count() > max {
                    push_issue("MAX_LENGTH", "Tamanho acima do máximo", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.length" => {
            if let Some(val) = current {
                let min = op.args.get("min").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let max = op.args.get("max").and_then(|v| v.as_u64()).unwrap_or(usize::MAX as u64) as usize;
                let len = val.chars().count();
                if len < min || len > max {
                    push_issue("LENGTH_RANGE", "Tamanho fora do intervalo", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.regex" => {
            if let Some(val) = current {
                let pattern = op.args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                match Regex::new(pattern) {
                    Ok(re) => {
                        if !re.is_match(val) {
                            push_issue("REGEX_MISMATCH", "Regex não corresponde", op_severity(op), mode, errors, warnings);
                            return Err(());
                        }
                    }
                    Err(_) => {
                        push_issue("NORMALIZE_ERROR", "Regex inválida", Some("hard".to_string()), mode, errors, warnings);
                        return Err(());
                    }
                }
            }
        }
        "validate.in_set" => {
            if let Some(val) = current {
                let set = args_string_list(&op.args, "set");
                if !set.contains(val) {
                    push_issue("IN_SET", "Valor fora do conjunto", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.not_in_set" => {
            if let Some(val) = current {
                let set = args_string_list(&op.args, "set");
                if set.contains(val) {
                    push_issue("NOT_IN_SET", "Valor proibido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.starts_with" => {
            if let Some(val) = current {
                let prefix = op.args.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
                if !val.starts_with(prefix) {
                    push_issue("STARTS_WITH", "Prefixo inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.email.simple" => {
            if let Some(val) = current {
                let re = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
                if !re.is_match(val) {
                    push_issue("EMAIL_INVALID", "Email inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.numeric" => {
            if let Some(val) = current {
                let re = Regex::new(r"^\d+$").unwrap();
                if !re.is_match(val) {
                    push_issue("NUMERIC_INVALID", "Número inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.integer" => {
            if let Some(val) = current {
                let re = Regex::new(r"^-?\d+$").unwrap();
                if !re.is_match(val) {
                    push_issue("INTEGER_INVALID", "Inteiro inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.decimal" => {
            if let Some(val) = current {
                let re = Regex::new(r"^-?\d+(\.\d+)?$").unwrap();
                if !re.is_match(val) {
                    push_issue("DECIMAL_INVALID", "Decimal inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.date.iso" => {
            if let Some(val) = current {
                let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
                if !re.is_match(val) {
                    push_issue("DATE_ISO_INVALID", "Data ISO inválida", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.uuid" => {
            if let Some(val) = current {
                let re = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").unwrap();
                if !re.is_match(val) {
                    push_issue("UUID_INVALID", "UUID inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "validate.url" => {
            if let Some(val) = current {
                let mut url = val.trim().to_string();
                if !url.contains("://") {
                    url = format!("https://{}", url);
                }
                let parsed = url::Url::parse(&url);
                let parsed = match parsed {
                    Ok(u) => u,
                    Err(_) => {
                        push_issue("URL_INVALID", "URL inválida", op_severity(op), mode, errors, warnings);
                        return Err(());
                    }
                };
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    push_issue("URL_INVALID", "URL inválida", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
                let host = match parsed.host_str() {
                    Some(h) => h,
                    None => {
                        push_issue("URL_INVALID", "URL inválida", op_severity(op), mode, errors, warnings);
                        return Err(());
                    }
                };
                if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
                    push_issue("URL_INVALID", "Host não permitido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
                if let Some(tlds) = tld_list() {
                    if let Some(tld) = host.split('.').last() {
                        if !tlds.contains(&tld.to_lowercase()) {
                            push_issue("URL_INVALID", "TLD inválido", op_severity(op), mode, errors, warnings);
                            return Err(());
                        }
                    } else {
                        push_issue("URL_INVALID", "URL inválida", op_severity(op), mode, errors, warnings);
                        return Err(());
                    }
                }
                let mut normalized = parsed.to_string();
                if let Some(h) = parsed.host_str() {
                    normalized = normalized.replacen(h, &h.to_lowercase(), 1);
                }
                *val = normalized;
            }
        }
        "validate.cc.luhn" => {
            if let Some(val) = current {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.is_empty() || !luhn_is_valid(&digits) {
                    push_issue("CC_LUHN_INVALID", "Cartão inválido", op_severity(op), mode, errors, warnings);
                    return Err(());
                }
                *val = digits;
            }
        }
        "br.digits_only" => {
            if let Some(val) = current {
                *val = val.chars().filter(|c| c.is_ascii_digit()).collect();
            }
        }
        "br.alnum_only" => {
            if let Some(val) = current {
                *val = val
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
            }
        }
        "br.phone.digits_only" => {
            if let Some(val) = current {
                *val = val.chars().filter(|c| c.is_ascii_digit()).collect();
            }
        }
        "br.cep.normalize" => {
            if let Some(val) = current {
                *val = val.chars().filter(|c| c.is_ascii_digit()).collect();
            }
        }
        "br.uf.normalize" => {
            if let Some(val) = current {
                *val = val.to_uppercase();
                if !is_valid_uf(val) {
                    push_issue("UF_INVALID", "UF inválida", Some("hard".to_string()), mode, errors, warnings);
                    return Err(());
                }
            }
        }
        "br.currency.normalize_brl" => {
            if let Some(val) = current {
                let cleaned = val.replace('.', "").replace(',', ".").replace(' ', "");
                *val = cleaned;
            }
        }
        "br.cpf.check_digit" => {
            if let Some(val) = current {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                if !cpf_is_valid(&digits) {
                    push_issue("CPF_CHECK_DIGIT", "CPF inválido", Some("hard".to_string()), mode, errors, warnings);
                    return Err(());
                }
                *val = digits;
            }
        }
        "br.cnpj.check_digit" => {
            if let Some(val) = current {
                let normalized: String = val
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                if !cnpj_is_valid(&normalized) {
                    push_issue("CNPJ_CHECK_DIGIT", "CNPJ inválido", Some("hard".to_string()), mode, errors, warnings);
                    return Err(());
                }
                *val = normalized;
            }
        }
        "br.document" => {
            if let Some(val) = current {
                let normalized: String = val
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                match normalized.len() {
                    11 => {
                        *detected_type = Some("CPF".to_string());
                        if !normalized.chars().all(|c| c.is_ascii_digit()) || !cpf_is_valid(&normalized) {
                            push_issue("CPF_CHECK_DIGIT", "CPF inválido", Some("hard".to_string()), mode, errors, warnings);
                            return Err(());
                        }
                        *val = normalized;
                    }
                    14 => {
                        *detected_type = Some("CNPJ".to_string());
                        if !cnpj_is_valid(&normalized) {
                            push_issue("CNPJ_CHECK_DIGIT", "CNPJ inválido", Some("hard".to_string()), mode, errors, warnings);
                            return Err(());
                        }
                        *val = normalized;
                    }
                    _ => {
                        push_issue("DOCUMENT_INVALID", "Documento inválido", Some("hard".to_string()), mode, errors, warnings);
                        return Err(());
                    }
                }
            }
        }
        "br.phone.mobile" => {
            if let Some(val) = current {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                let ok = digits.len() == 11 && digits.chars().nth(2) == Some('9');
                if !ok {
                    push_issue("PHONE_INVALID", "Celular inválido", Some("hard".to_string()), mode, errors, warnings);
                    return Err(());
                }
                *val = digits;
            }
        }
        "br.phone.any" => {
            if let Some(val) = current {
                let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
                let ok = digits.len() == 10 || digits.len() == 11;
                if !ok {
                    push_issue("PHONE_INVALID", "Telefone inválido", Some("hard".to_string()), mode, errors, warnings);
                    return Err(());
                }
                *val = digits;
            }
        }
        "br.pix.key" => {
            if let Some(val) = current {
                let raw = val.trim();
                if raw.contains('@') {
                    let email = raw.to_lowercase();
                    let re = Regex::new(r"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$").unwrap();
                    if !re.is_match(&email) {
                        push_issue("PIX_KEY_INVALID", "Chave PIX inválida", Some("hard".to_string()), mode, errors, warnings);
                        return Err(());
                    }
                    *detected_type = Some("EMAIL".to_string());
                    *val = email;
                } else {
                    let mut digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() == 12 || digits.len() == 13 {
                        if digits.starts_with("55") {
                            digits = digits[2..].to_string();
                        }
                    }
                    if digits.len() == 11 {
                        if cpf_is_valid(&digits) {
                            *detected_type = Some("CPF".to_string());
                            *val = digits;
                        } else {
                            *detected_type = Some("PHONE".to_string());
                            *val = digits;
                        }
                    } else if digits.len() == 14 {
                        if cnpj_is_valid(&digits) {
                            *detected_type = Some("CNPJ".to_string());
                            *val = digits;
                        } else {
                            push_issue("PIX_KEY_INVALID", "Chave PIX inválida", Some("hard".to_string()), mode, errors, warnings);
                            return Err(());
                        }
                    } else if digits.len() == 10 {
                        *detected_type = Some("PHONE".to_string());
                        *val = digits;
                    } else if is_uuid(raw) {
                        *detected_type = Some("EVP".to_string());
                        *val = raw.to_lowercase();
                    } else {
                        push_issue("PIX_KEY_INVALID", "Chave PIX inválida", Some("hard".to_string()), mode, errors, warnings);
                        return Err(());
                    }
                }
            }
        }
        "text.person_name.ptbr" => {
            if let Some(val) = current {
                *val = title_case_ptbr(&collapse_spaces(val));
            }
        }
        "text.company_name.ptbr" => {
            if let Some(val) = current {
                *val = title_case_ptbr(&collapse_spaces(val));
            }
        }
        "text.no_double_spaces" => {
            if let Some(val) = current {
                *val = collapse_spaces(val);
            }
        }
        "text.abbrev.normalize.ptbr" => {
            // no-op placeholder for now
        }
        "br.address.street.ptbr" => {
            if let Some(val) = current {
                *val = collapse_spaces(val).trim().to_string();
            }
        }
        "br.address.number" => {
            if let Some(val) = current {
                *val = val.trim().to_string();
            }
        }
        _ => {
            push_issue(
                "UNKNOWN_OP",
                "Operação desconhecida",
                Some("hard".to_string()),
                mode,
                errors,
                warnings,
            );
            return Err(());
        }
    }

    Ok(())
}

fn push_issue(
    code: &str,
    message: &str,
    severity: Option<String>,
    mode: &Mode,
    errors: &mut Vec<ErrorItem>,
    warnings: &mut Vec<ErrorItem>,
) {
    let hard = matches!(severity.as_deref(), Some("hard")) || is_hard_code(code);
    let is_error = match mode {
        Mode::Strict => true,
        Mode::Lenient => hard,
        Mode::NormalizeOnly => false,
    };

    if !is_error && matches!(mode, Mode::NormalizeOnly) {
        return;
    }

    let item = ErrorItem {
        code: code.to_string(),
        message: message.to_string(),
        severity: if is_error { "error".to_string() } else { "warning".to_string() },
        path: "$".to_string(),
        hint: None,
    };

    if is_error {
        errors.push(item);
    } else {
        warnings.push(item);
    }
}

fn is_hard_code(code: &str) -> bool {
    matches!(
        code,
        "CPF_CHECK_DIGIT" | "CNPJ_CHECK_DIGIT" | "DOCUMENT_INVALID" | "PHONE_INVALID" | "UF_INVALID"
    )
}

fn args_string_list(args: &JsonValue, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn is_empty(current: &Option<String>) -> bool {
    match current {
        None => true,
        Some(val) => val.trim().is_empty(),
    }
}

fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in input.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

fn collapse_spaces(input: &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    re.replace_all(input, " ").to_string()
}

fn title_case_ptbr(input: &str) -> String {
    let exceptions = ["da", "de", "do", "das", "dos", "e"];
    input
        .split_whitespace()
        .enumerate()
        .map(|(i, word)| {
            let lower = word.to_lowercase();
            if i > 0 && exceptions.contains(&lower.as_str()) {
                lower
            } else {
                let mut chars = lower.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn remove_accents(input: &str) -> String {
    input
        .nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

fn is_valid_uf(val: &str) -> bool {
    matches!(
        val,
        "AC" | "AL" | "AP" | "AM" | "BA" | "CE" | "DF" | "ES" | "GO" | "MA" | "MT" | "MS" |
        "MG" | "PA" | "PB" | "PR" | "PE" | "PI" | "RJ" | "RN" | "RS" | "RO" | "RR" | "SC" |
        "SP" | "SE" | "TO"
    )
}

fn cpf_is_valid(digits: &str) -> bool {
    if digits.len() != 11 || digits.chars().all(|c| c == digits.chars().next().unwrap()) {
        return false;
    }
    let nums: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if nums.len() != 11 {
        return false;
    }
    let mut sum = 0;
    for i in 0..9 {
        sum += nums[i] * (10 - i as u32);
    }
    let mut dv1 = (sum * 10) % 11;
    if dv1 == 10 {
        dv1 = 0;
    }
    if dv1 != nums[9] {
        return false;
    }
    sum = 0;
    for i in 0..10 {
        sum += nums[i] * (11 - i as u32);
    }
    let mut dv2 = (sum * 10) % 11;
    if dv2 == 10 {
        dv2 = 0;
    }
    dv2 == nums[10]
}

fn cnpj_is_valid(digits: &str) -> bool {
    if digits.len() != 14 {
        return false;
    }
    let chars: Vec<char> = digits.chars().collect();
    if chars.len() != 14 {
        return false;
    }
    if !chars[..12].iter().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if !chars[12].is_ascii_digit() || !chars[13].is_ascii_digit() {
        return false;
    }

    let dv1 = cnpj_calc_dv(&chars[..12]);
    let dv1_char = std::char::from_digit(dv1, 10).unwrap();
    if dv1_char != chars[12] {
        return false;
    }
    let mut with_dv1 = chars[..12].to_vec();
    with_dv1.push(dv1_char);
    let dv2 = cnpj_calc_dv(&with_dv1);
    let dv2_char = std::char::from_digit(dv2, 10).unwrap();
    dv2_char == chars[13]
}

fn cnpj_calc_dv(chars: &[char]) -> u32 {
    let mut weight = 2u32;
    let mut sum = 0u32;
    for ch in chars.iter().rev() {
        let value = cnpj_char_value(*ch).unwrap_or(0);
        sum += value * weight;
        weight = if weight == 9 { 2 } else { weight + 1 };
    }
    let remainder = sum % 11;
    if remainder < 2 { 0 } else { 11 - remainder }
}

fn luhn_is_valid(digits: &str) -> bool {
    let mut sum = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let mut n = match ch.to_digit(10) {
            Some(v) => v,
            None => return false,
        };
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

fn is_uuid(value: &str) -> bool {
    let re = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").unwrap();
    re.is_match(value)
}

fn tld_list() -> Option<&'static HashSet<String>> {
    static TLD_SET: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    TLD_SET.get_or_init(|| {
        let path = std::env::var("TLD_LIST_PATH").unwrap_or_else(|_| "data/tlds.txt".to_string());
        let content = fs::read_to_string(path).ok()?;
        let mut set = HashSet::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            set.insert(line.to_lowercase());
        }
        Some(set)
    }).as_ref()
}

fn cnpj_char_value(ch: char) -> Option<u32> {
    if ch.is_ascii_digit() {
        Some(ch as u8 as u32 - 48)
    } else if ch.is_ascii_uppercase() {
        Some(ch as u8 as u32 - 48)
    } else {
        None
    }
}

fn convert_output(
    output_type: &str,
    normalized: Option<&str>,
    mode: &Mode,
    errors: &mut Vec<ErrorItem>,
    warnings: &mut Vec<ErrorItem>,
) -> Option<JsonValue> {
    if output_type == "string" {
        return None;
    }
    let value = match normalized {
        None => return None,
        Some(v) => v,
    };

    let converted = match output_type {
        "number" => value.parse::<f64>().ok().map(JsonValue::from),
        "integer" => value.parse::<i64>().ok().map(JsonValue::from),
        "boolean" => match value.to_lowercase().as_str() {
            "true" | "1" => Some(JsonValue::from(true)),
            "false" | "0" => Some(JsonValue::from(false)),
            _ => None,
        },
        "date" => {
            let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
            if re.is_match(value) {
                Some(JsonValue::from(value))
            } else {
                None
            }
        }
        "datetime" => {
            let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").unwrap();
            if re.is_match(value) {
                Some(JsonValue::from(value))
            } else {
                None
            }
        }
        _ => Some(JsonValue::from(value)),
    };

    if converted.is_none() {
        push_issue(
            "OUTPUT_CONVERSION",
            "Falha ao converter output",
            Some("hard".to_string()),
            mode,
            errors,
            warnings,
        );
    }

    converted
}
