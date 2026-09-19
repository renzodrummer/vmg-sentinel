use crate::seed_allowlist::merge_site_allow;
use crate::ttl::{is_expired, parse_issued_at};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Audit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMatchKind {
    Publisher,
    Hash,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDenyRule {
    pub kind: AppMatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteLists {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppLists {
    #[serde(default)]
    pub deny: Vec<AppDenyRule>,
}

/// Wire document. Signature is over compact `UnsignedPolicy` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: u64,
    pub issued_at: String,
    pub ttl_seconds: u64,
    pub mode: PolicyMode,
    pub signature: String,
    pub sites: SiteLists,
    pub apps: AppLists,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedPolicy {
    pub version: u64,
    pub issued_at: String,
    pub ttl_seconds: u64,
    pub mode: PolicyMode,
    pub sites: SiteLists,
    pub apps: AppLists,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid policy JSON")]
    Invalid,
    #[error("unsigned policy")]
    Unsigned,
    #[error("bad signature")]
    BadSignature,
    #[error("expired policy")]
    Expired,
    #[error("invalid app rule")]
    InvalidAppRule,
}

impl PolicyDocument {
    pub fn to_unsigned(&self) -> UnsignedPolicy {
        UnsignedPolicy {
            version: self.version,
            issued_at: self.issued_at.clone(),
            ttl_seconds: self.ttl_seconds,
            mode: self.mode,
            sites: self.sites.clone(),
            apps: self.apps.clone(),
        }
    }
}

pub fn serialize_unsigned(unsigned: &UnsignedPolicy) -> Result<Vec<u8>, PolicyError> {
    serde_json::to_vec(unsigned).map_err(|_| PolicyError::Invalid)
}

pub fn parse_document(raw: &str) -> Result<PolicyDocument, PolicyError> {
    serde_json::from_str(raw).map_err(|_| PolicyError::Invalid)
}

fn validate_rules(doc: &PolicyDocument) -> Result<(), PolicyError> {
    if doc.version < 1 {
        return Err(PolicyError::Invalid);
    }
    parse_issued_at(&doc.issued_at).map_err(|_| PolicyError::Invalid)?;
    for rule in &doc.apps.deny {
        if rule.value.trim().is_empty() {
            return Err(PolicyError::InvalidAppRule);
        }
        if matches!(rule.kind, AppMatchKind::Hash) {
            let alg = rule.alg.as_deref().unwrap_or("");
            if !alg.eq_ignore_ascii_case("sha256") {
                return Err(PolicyError::InvalidAppRule);
            }
        }
    }
    Ok(())
}

pub fn verify_signature(doc: &PolicyDocument, public_key_hex: &str) -> Result<(), PolicyError> {
    validate_rules(doc)?;
    if doc.signature.trim().is_empty() {
        return Err(PolicyError::Unsigned);
    }

    let pk_bytes = hex::decode(public_key_hex.trim()).map_err(|_| PolicyError::BadSignature)?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| PolicyError::BadSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| PolicyError::BadSignature)?;

    let sig_bytes = hex::decode(doc.signature.trim()).map_err(|_| PolicyError::BadSignature)?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| PolicyError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    let payload = serialize_unsigned(&doc.to_unsigned())?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| PolicyError::BadSignature)?;
    Ok(())
}

pub fn verify_and_normalize(
    mut doc: PolicyDocument,
    public_key_hex: &str,
    now: time::OffsetDateTime,
) -> Result<PolicyDocument, PolicyError> {
    verify_signature(&doc, public_key_hex)?;
    if is_expired(&doc, now) {
        return Err(PolicyError::Expired);
    }
    doc.sites.allow = merge_site_allow(&doc.sites.allow);
    Ok(doc)
}

/// Reload last-good after a helper restart. Signature must still verify; expiry is allowed.
pub fn restore_last_good(
    mut doc: PolicyDocument,
    public_key_hex: &str,
) -> Result<PolicyDocument, PolicyError> {
    verify_signature(&doc, public_key_hex)?;
    doc.sites.allow = merge_site_allow(&doc.sites.allow);
    Ok(doc)
}

pub fn sign_unsigned(
    unsigned: &UnsignedPolicy,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<PolicyDocument, PolicyError> {
    use ed25519_dalek::Signer;
    let payload = serialize_unsigned(unsigned)?;
    let signature = signing_key.sign(&payload);
    Ok(PolicyDocument {
        version: unsigned.version,
        issued_at: unsigned.issued_at.clone(),
        ttl_seconds: unsigned.ttl_seconds,
        mode: unsigned.mode,
        signature: hex::encode(signature.to_bytes()),
        sites: unsigned.sites.clone(),
        apps: unsigned.apps.clone(),
    })
}
