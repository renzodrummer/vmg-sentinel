use crate::policy::{PolicyDocument, PolicyMode};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub fn parse_issued_at(issued_at: &str) -> Result<OffsetDateTime, ()> {
    OffsetDateTime::parse(issued_at, &Rfc3339).map_err(|_| ())
}

pub fn expires_at(doc: &PolicyDocument) -> Result<OffsetDateTime, ()> {
    let issued = parse_issued_at(&doc.issued_at)?;
    let ttl = i64::try_from(doc.ttl_seconds).map_err(|_| ())?;
    Ok(issued + Duration::seconds(ttl))
}

pub fn is_expired(doc: &PolicyDocument, now: OffsetDateTime) -> bool {
    match expires_at(doc) {
        Ok(exp) => now >= exp,
        Err(()) => true,
    }
}

/// After TTL: keep last-good, report audit, never drop the seed allowlist.
pub fn effective_mode(doc: &PolicyDocument, now: OffsetDateTime) -> (PolicyMode, bool) {
    if is_expired(doc, now) {
        (PolicyMode::Audit, true)
    } else {
        (doc.mode, false)
    }
}

pub fn format_rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}
