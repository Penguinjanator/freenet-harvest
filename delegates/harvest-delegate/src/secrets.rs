//! The delegate host's secret store, behind a trait the handlers can be tested
//! against.
//!
//! # Why the handlers do not take a `DelegateCtx`
//!
//! Off the `wasm32` target, `DelegateCtx::get_secret` answers `None` and
//! `set_secret` answers `false` (freenet-stdlib's `delegate_host.rs`,
//! `#[cfg(not(target_family = "wasm"))]` branch). A handler that takes a
//! `DelegateCtx` therefore cannot be exercised under `cargo test` at all: every
//! read misses and every write is refused, so a test can only ever observe the
//! failure path.
//!
//! That is not a cosmetic inconvenience. It is why the authorization hole this
//! module's sibling [`crate::origin`] closes was untestable before: the only
//! statement a test could make about `bitcoin::handle` was "it returned
//! something", never "the seller's payment key is still the seller's". Taking
//! `impl SecretStore` instead lets a test hold a real store, run a hostile
//! request against it, and assert on the bytes that are still in it afterwards.
//!
//! [`SecretStore`] is `freenet-migrate`'s trait rather than a new one, because
//! `crate::migration` and `crate::markers` already speak it. One vocabulary for
//! "the delegate's secret store" across the crate.

use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::DelegateCtx;

/// The host's secret store, with writes enabled.
///
/// Distinct from `migration::CtxStore`, whose `set_secret` is deliberately
/// inert because an export must never write.
pub(crate) struct CtxSecrets<'a>(pub(crate) &'a mut DelegateCtx);

impl SecretStore for CtxSecrets<'_> {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.0.list_secrets(prefix)
    }

    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get_secret(key)
    }

    fn has_secret(&self, key: &[u8]) -> bool {
        self.0.has_secret(key)
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.0.set_secret(key, value)
    }
}

/// An in-memory stand-in for the host's store, for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemSecrets {
    map: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    /// Set to make every write fail, standing in for a host that refuses.
    pub(crate) writes_fail: bool,
}

#[cfg(test)]
impl SecretStore for MemSecrets {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn has_secret(&self, key: &[u8]) -> bool {
        self.map.contains_key(key)
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        if self.writes_fail {
            return false;
        }
        self.map.insert(key.to_vec(), value.to_vec());
        true
    }
}

#[cfg(test)]
impl MemSecrets {
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
