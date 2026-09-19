use ed25519_dalek::SigningKey;
use time::{Duration, OffsetDateTime};
use vmg_sentinel_helper::policy::{
    restore_last_good, sign_unsigned, verify_and_normalize, AppDenyRule, AppLists, AppMatchKind,
    PolicyError, PolicyMode, SiteLists, UnsignedPolicy,
};
use vmg_sentinel_helper::seed_allowlist::SEED_SITE_ALLOW;
use vmg_sentinel_helper::ttl::effective_mode;
use vmg_sentinel_helper::DEV_PUBLIC_KEY_HEX;

const DEV_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn unsigned(issued: OffsetDateTime, ttl: u64, mode: PolicyMode) -> UnsignedPolicy {
    UnsignedPolicy {
        version: 1,
        issued_at: issued
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        ttl_seconds: ttl,
        mode,
        sites: SiteLists {
            allow: vec![],
            deny: vec!["facebook.com".into()],
        },
        apps: AppLists {
            deny: vec![AppDenyRule {
                kind: AppMatchKind::Publisher,
                alg: None,
                value: "O=Discord Inc.".into(),
            }],
        },
    }
}

#[test]
fn accepts_signed_unexpired() {
    let key = SigningKey::from_bytes(&DEV_SEED);
    let now = OffsetDateTime::now_utc();
    let doc = sign_unsigned(&unsigned(now, 3600, PolicyMode::Audit), &key).unwrap();
    let out = verify_and_normalize(doc, DEV_PUBLIC_KEY_HEX, now).unwrap();
    assert_eq!(out.mode, PolicyMode::Audit);
    assert!(out.sites.allow.iter().any(|h| h == SEED_SITE_ALLOW[0]));
}

#[test]
fn rejects_unsigned() {
    let now = OffsetDateTime::now_utc();
    let mut doc = sign_unsigned(
        &unsigned(now, 3600, PolicyMode::Audit),
        &SigningKey::from_bytes(&DEV_SEED),
    )
    .unwrap();
    doc.signature.clear();
    let err = verify_and_normalize(doc, DEV_PUBLIC_KEY_HEX, now).unwrap_err();
    assert_eq!(err, PolicyError::Unsigned);
}

#[test]
fn rejects_expired() {
    let key = SigningKey::from_bytes(&DEV_SEED);
    let now = OffsetDateTime::now_utc();
    let issued = now - Duration::seconds(7200);
    let doc = sign_unsigned(&unsigned(issued, 3600, PolicyMode::Block), &key).unwrap();
    let err = verify_and_normalize(doc, DEV_PUBLIC_KEY_HEX, now).unwrap_err();
    assert_eq!(err, PolicyError::Expired);
}

#[test]
fn audit_vs_block_is_a_flag() {
    let key = SigningKey::from_bytes(&DEV_SEED);
    let now = OffsetDateTime::now_utc();
    let audit = sign_unsigned(&unsigned(now, 3600, PolicyMode::Audit), &key).unwrap();
    let block = sign_unsigned(&unsigned(now, 3600, PolicyMode::Block), &key).unwrap();
    assert_eq!(
        verify_and_normalize(audit, DEV_PUBLIC_KEY_HEX, now)
            .unwrap()
            .mode,
        PolicyMode::Audit
    );
    assert_eq!(
        verify_and_normalize(block, DEV_PUBLIC_KEY_HEX, now)
            .unwrap()
            .mode,
        PolicyMode::Block
    );
}

#[test]
fn last_good_survives_ttl_but_downgrades_to_audit() {
    let key = SigningKey::from_bytes(&DEV_SEED);
    let now = OffsetDateTime::now_utc();
    let issued = now - Duration::seconds(7200);
    let doc = sign_unsigned(&unsigned(issued, 3600, PolicyMode::Block), &key).unwrap();
    let restored = restore_last_good(doc, DEV_PUBLIC_KEY_HEX).unwrap();
    let (mode, expired) = effective_mode(&restored, now);
    assert!(expired);
    assert_eq!(mode, PolicyMode::Audit);
    assert!(restored
        .sites
        .allow
        .iter()
        .any(|h| h == "login.microsoftonline.com"));
    assert!(restored
        .sites
        .allow
        .iter()
        .any(|h| h == "login.windows.net"));
}
