pub mod auth;
pub mod enforce;
pub mod ipc;
pub mod policy;
pub mod policy_store;
pub mod privilege;
pub mod runtime;
pub mod seed_allowlist;
pub mod state;
pub mod ttl;

#[cfg(windows)]
pub mod service;

/// Distinguishes this Windows Firewall build from older helpers on the same pipe.
pub const HELPER_BUILD: &str = "fw-4";

/// RFC 8032 test-vector 1 public key. Dev / unit tests only.
pub const DEV_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
