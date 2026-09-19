use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_FRAME_BYTES: u32 = 1_048_576;

/// Deny Anonymous + Network; allow SYSTEM, Administrators, Interactive users.
pub const PIPE_SDDL: &str = "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcMethod {
    ApplyPolicy,
    GetStatus,
    GetRecentBlocks,
    ReportTamper,
    SetSession,
    Forbidden,
}

impl IpcMethod {
    pub fn parse(name: &str) -> Self {
        match name {
            "ApplyPolicy" => Self::ApplyPolicy,
            "GetStatus" => Self::GetStatus,
            "GetRecentBlocks" => Self::GetRecentBlocks,
            "ReportTamper" => Self::ReportTamper,
            "SetSession" => Self::SetSession,
            _ => Self::Forbidden,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IpcRequest {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct IpcResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcErrorBody>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IpcError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    Policy(&'static str),
    #[error("{0}")]
    Internal(&'static str),
}

impl IpcError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::Forbidden => "FORBIDDEN",
            Self::Policy(code) => code,
            Self::Internal(_) => "INTERNAL",
        }
    }

    pub fn body(&self) -> IpcErrorBody {
        IpcErrorBody {
            code: self.code().to_string(),
            message: self.to_string(),
        }
    }
}

pub fn ok(id: u64, result: serde_json::Value) -> IpcResponse {
    IpcResponse {
        id,
        ok: true,
        result: Some(result),
        error: None,
    }
}

pub fn err(id: u64, error: IpcError) -> IpcResponse {
    IpcResponse {
        id,
        ok: false,
        result: None,
        error: Some(error.body()),
    }
}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, IpcError> {
    let len = u32::try_from(payload.len()).map_err(|_| IpcError::Internal("frame too large"))?;
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::Internal("frame too large"));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::PIPE_SDDL;

    #[test]
    fn sddl_denies_anonymous() {
        assert!(PIPE_SDDL.contains("(D;;GA;;;AN)"));
    }
}
