//! Pure policy parsing and validation. No privileged operations.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub zones: BTreeMap<String, Zone>,
    #[serde(default)]
    pub services: BTreeMap<String, Service>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub target: String,
    pub allow: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid policy: {0}")]
    Validation(String),
}

pub fn parse_and_validate(input: &str) -> Result<Config, PolicyError> {
    let cfg: Config = toml::from_str(input)?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &Config) -> Result<(), PolicyError> {
    if cfg.version != 1 {
        return Err(PolicyError::Validation(
            "only schema version 1 is supported".into(),
        ));
    }
    for (name, zone) in &cfg.zones {
        if zone.interfaces.is_empty() || zone.interfaces.iter().any(|s| s.trim().is_empty()) {
            return Err(PolicyError::Validation(format!(
                "zone {name}: interfaces must be nonempty"
            )));
        }
    }
    for (name, service) in &cfg.services {
        if service.target.trim().is_empty() || !service.target.starts_with("docker:") {
            return Err(PolicyError::Validation(format!(
                "service {name}: target must start with docker:"
            )));
        }
        if service.allow.is_empty() {
            return Err(PolicyError::Validation(format!(
                "service {name}: allow must not be empty"
            )));
        }
        for source in &service.allow {
            if !cfg.zones.contains_key(source) {
                return Err(PolicyError::Validation(format!(
                    "service {name}: unknown zone {source}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_valid_policy() {
        let cfg = parse_and_validate("version = 1\n[zones.vpn]\ninterfaces = [\"tailscale0\"]\n[services.db]\ntarget = \"docker:postgres\"\nallow = [\"vpn\"]").unwrap();
        assert_eq!(cfg.services.len(), 1);
    }
    #[test]
    fn rejects_unknown_zone() {
        assert!(
            parse_and_validate(
                "version = 1\n[services.db]\ntarget = \"docker:postgres\"\nallow = [\"missing\"]"
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_unsupported_schema() {
        assert!(parse_and_validate("version = 2").is_err());
    }
}
