use crate::models::RuleDefinition;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Catalog {
    base: HashMap<String, Vec<RuleDefinition>>,
    tenants: HashMap<String, TenantCatalog>,
}

#[derive(Debug, Clone, Default)]
struct TenantCatalog {
    active: HashMap<String, RuleDefinition>,
    versions: HashMap<String, Vec<RuleDefinition>>,
}

impl Catalog {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let mut base: HashMap<String, Vec<RuleDefinition>> = HashMap::new();
        let mut tenants: HashMap<String, TenantCatalog> = HashMap::new();

        let base_rules_dir = root.join("catalog").join("rules");
        if base_rules_dir.exists() {
            for path in collect_json_files(&base_rules_dir)? {
                let rule = load_rule(&path)?;
                base.entry(rule.rule_id.clone()).or_default().push(rule);
            }
        }

        let tenants_dir = root.join("tenants");
        if tenants_dir.exists() {
            for tenant_entry in fs::read_dir(&tenants_dir).context("read tenants dir")? {
                let tenant_entry = tenant_entry?;
                if !tenant_entry.file_type()?.is_dir() {
                    continue;
                }
                let tenant_name = tenant_entry.file_name().to_string_lossy().to_string();
                let mut tenant_catalog = TenantCatalog::default();

                let active_dir = tenant_entry.path().join("active");
                if active_dir.exists() {
                    for path in collect_json_files(&active_dir)? {
                        let rule = load_rule(&path)?;
                        tenant_catalog.active.insert(rule.rule_id.clone(), rule);
                    }
                }

                let versions_dir = tenant_entry.path().join("versions");
                if versions_dir.exists() {
                    for path in collect_json_files(&versions_dir)? {
                        let rule = load_rule(&path)?;
                        tenant_catalog
                            .versions
                            .entry(rule.rule_id.clone())
                            .or_default()
                            .push(rule);
                    }
                }

                if tenant_catalog.active.is_empty() && tenant_catalog.versions.is_empty() {
                    continue;
                }
                tenants.insert(tenant_name, tenant_catalog);
            }
        }

        Ok(Self { base, tenants })
    }

    pub fn list_rules(&self, tenant: Option<&str>) -> Vec<crate::models::RuleIndexItem> {
        use crate::models::RuleIndexItem;
        let mut map: HashMap<String, (Vec<String>, Option<String>)> = HashMap::new();

        for (rule_id, versions) in &self.base {
            let mut list = versions.iter().map(|v| v.version.clone()).collect::<Vec<_>>();
            list.sort();
            let description = select_version(versions, None).and_then(|rule| rule.description);
            map.insert(rule_id.clone(), (list, description));
        }

        if let Some(t) = tenant {
            if let Some(tenant_catalog) = self.tenants.get(t) {
                for (rule_id, versions) in &tenant_catalog.versions {
                    let mut list = versions.iter().map(|v| v.version.clone()).collect::<Vec<_>>();
                    list.sort();
                    let description = select_version(versions, None).and_then(|rule| rule.description);
                    map.insert(rule_id.clone(), (list, description));
                }
                for (rule_id, active_rule) in &tenant_catalog.active {
                    map.entry(rule_id.clone())
                        .or_insert_with(|| {
                            (
                                vec![active_rule.version.clone()],
                                active_rule.description.clone(),
                            )
                        });
                }
            }
        }

        let mut items = map
            .into_iter()
            .map(|(rule_id, (versions, description))| RuleIndexItem {
                path: rule_id_to_path(&rule_id),
                rule_id,
                versions,
                description,
            })
            .collect::<Vec<_>>();
        items.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        items
    }

    pub fn resolve_rule(
        &self,
        tenant: Option<&str>,
        rule_id: &str,
        version: Option<&str>,
    ) -> Option<RuleDefinition> {
        if let Some(t) = tenant {
            if let Some(rule) = self.resolve_from_tenant(t, rule_id, version) {
                return Some(rule);
            }
        }
        self.resolve_from_base(rule_id, version)
    }

    fn resolve_from_tenant(
        &self,
        tenant: &str,
        rule_id: &str,
        version: Option<&str>,
    ) -> Option<RuleDefinition> {
        let tenant_catalog = self.tenants.get(tenant)?;
        if let Some(version_value) = version {
            if let Some(rules) = tenant_catalog.versions.get(rule_id) {
                if let Some(rule) = select_version(rules, Some(version_value)) {
                    return Some(rule);
                }
            }
            if let Some(active_rule) = tenant_catalog.active.get(rule_id) {
                if active_rule.version == version_value {
                    return Some(active_rule.clone());
                }
            }
            return None;
        }

        if let Some(active_rule) = tenant_catalog.active.get(rule_id) {
            return Some(active_rule.clone());
        }

        let rules = tenant_catalog.versions.get(rule_id)?;
        select_version(rules, None)
    }

    fn resolve_from_base(&self, rule_id: &str, version: Option<&str>) -> Option<RuleDefinition> {
        let rules = self.base.get(rule_id)?;
        select_version(rules, version)
    }

    pub fn stats(&self, tenant: Option<&str>) -> crate::models::CatalogStats {
        use crate::models::CatalogStats;
        let mut rules_count = self.base.len();
        let mut versions_count: usize = self.base.values().map(|v| v.len()).sum();
        let mut approx_bytes: usize = estimate_map_bytes(&self.base);

        if let Some(t) = tenant {
            if let Some(tenant_catalog) = self.tenants.get(t) {
                rules_count += tenant_catalog.versions.len();
                versions_count += tenant_catalog.versions.values().map(|v| v.len()).sum::<usize>();
                approx_bytes += estimate_map_bytes(&tenant_catalog.versions);
                for (rule_id, active_rule) in &tenant_catalog.active {
                    if !tenant_catalog.versions.contains_key(rule_id) {
                        rules_count += 1;
                        versions_count += 1;
                    }
                    approx_bytes += estimate_rule_bytes(rule_id, active_rule);
                }
            }
        }

        CatalogStats {
            rules: rules_count,
            versions: versions_count,
            approx_bytes,
        }
    }
}

fn select_version(rules: &[RuleDefinition], version: Option<&str>) -> Option<RuleDefinition> {
    if rules.is_empty() {
        return None;
    }
    if let Some(v) = version {
        for rule in rules {
            if rule.version == v {
                return Some(rule.clone());
            }
        }
        return None;
    }
    let mut sorted = rules.to_vec();
    sorted.sort_by(|a, b| a.version.cmp(&b.version));
    sorted.last().cloned()
}

fn collect_json_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            files.extend(collect_json_files(&path)?);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(files)
}

fn load_rule(path: &Path) -> Result<RuleDefinition> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("read rule file {}", path.display()))?;
    let rule: RuleDefinition = serde_json::from_str(&data)
        .with_context(|| format!("parse rule file {}", path.display()))?;
    Ok(rule)
}

fn rule_id_to_path(rule_id: &str) -> String {
    if let Some(rest) = rule_id.strip_prefix("t:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() >= 3 {
            let tenant = parts[0];
            let encoded = rule_id.replace('%', "%25").replace(':', "%3A");
            return format!("tenants/{}/active/{}.json", tenant, encoded);
        }
    }
    format!("catalog/rules/{}", rule_id.replace('.', "/"))
}

fn estimate_map_bytes(map: &std::collections::HashMap<String, Vec<RuleDefinition>>) -> usize {
    let mut total = 0usize;
    for (k, versions) in map {
        total += k.len();
        for r in versions {
            total += estimate_rule_bytes("", r);
        }
    }
    total
}

fn estimate_rule_bytes(key: &str, rule: &RuleDefinition) -> usize {
    let mut total = key.len();
    total += rule.rule_id.len();
    total += rule.title.len();
    if let Some(d) = &rule.description {
        total += d.len();
    }
    total += rule.input_type.len();
    total += rule.output_type.len();
    total += rule.version.len();
    for t in &rule.tags {
        total += t.len();
    }
    for op in &rule.pipeline {
        total += op.op.len();
        total += op.args.to_string().len();
        if let Some(s) = &op.severity {
            total += s.len();
        }
    }
    if let Some(of) = &rule.on_fail {
        total += of.len();
    }
    total
}
