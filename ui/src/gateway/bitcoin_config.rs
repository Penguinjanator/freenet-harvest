//! Well-known Bitcoin contract configuration.
//!
//! # Why this file exists and why it is empty today
//!
//! The first-run Bitcoin panel needs to subscribe to a network's
//! `BitcoinTipContract` before the user has watched anything or connected a
//! Ghost Key -- that is the whole point of showing live chain data with no
//! credential. Subscribing needs that contract's `ContractInstanceId`, which
//! is a hash over its WASM code plus its `BitcoinTipParameters` (network +
//! trusted bridge keys).
//!
//! A bridge now exists (`freenet-bitcoin/bridge`, deployed on nova against
//! signet), but its tip-contract id deliberately stays OUT of this file.
//!
//! A `BitcoinTipContract`'s id is a hash over its WASM plus its parameters,
//! and its parameters include `trusted_bridges`, which is per-deployment
//! rather than a fixed per-network constant. A compiled-in id would therefore
//! go stale on any re-key -- including a bare version bump -- and the failure
//! is silent: every read comes back looking like "this network has no data
//! yet". So the id is fetched at runtime from the bridge's unauthenticated
//! `GET /v1/status`, which reports it (see `bitcoin_bridge_http`).
//!
//! ## Why runtime discovery over HTTP does NOT work, and this file matters again
//!
//! The plan was for the browser to fetch `<bridge>/v1/status` and read the id
//! from there. **The gateway's Content-Security-Policy forbids it.** A webapp
//! is served with `connect-src http://127.0.0.1:7509 blob: data:`, so it may
//! talk to its own gateway and nothing else. The fetch is refused:
//!
//! ```text
//! Refused to connect to 'http://127.0.0.1:8431/v1/status' because it
//! violates the document's Content Security Policy.
//! ```
//!
//! That is not a bug to route around -- it is the sandbox doing its job. A
//! Freenet webapp reaches the network through its node, not through arbitrary
//! HTTP. So the values below are build-time configuration, and the HTTP path
//! is kept only for a non-gateway context (local `dx serve`) where CSP does
//! not apply.
//!
//! **This is a stopgap and it has the exact staleness problem the constant was
//! meant to avoid**: a contract rebuild re-keys the tip contract and this file
//! goes quietly wrong. The durable fix is a POINTER RECORD -- a fixed-address,
//! author-signed contract naming the current code hash, read over the
//! WebSocket like any other contract, which is what `freenet-migrate`'s
//! pointer mechanism exists for and what ghostkeys already does. Until that is
//! in place, treat the constants below as needing an update whenever
//! `legacy_contracts.toml` gains an entry.

use freenet_bitcoin_common::BitcoinNetwork;

/// bs58 `ContractInstanceId` of the network-wide `BitcoinTipContract`, or
/// `None` if no deployment is known for that network yet.
pub fn well_known_tip_contract_id(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Bitcoin => None,
        BitcoinNetwork::Testnet4 => None,
        // The bridge deployed on nova, observing signet. Derived from
        // BitcoinTipParameters { network: Signet, trusted_bridges: [that
        // bridge] } plus the tip contract's code hash.
        //
        // Re-derive with: curl -s <bridge>/v1/status
        BitcoinNetwork::Signet => Some("B24HMUFasG3Yd1EJxfzb3qTPos1tLMiKo5gYiKwaihqT"),
        BitcoinNetwork::Regtest => None,
    }
}

/// The network the first-run panel defaults to showing before the user has
/// picked one. Signet for the same reason as above: it's where a demo
/// deployment would live.
pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
}

/// The bridge to ask before the user has configured one.
///
/// # Why localhost, and not a freenet.org URL
///
/// Defaulting to the user's own machine matches what the architecture actually
/// recommends: running your own bridge is the real answer to bridge-operator
/// correlation, because an operator necessarily learns which scripts it has
/// been asked to synchronize. A default that points everyone at one operator
/// would quietly make the privacy-worst option the path of least resistance.
///
/// It also fails honestly. If no local bridge is running the fetch simply
/// fails and the UI says no bridge is configured, rather than showing data
/// from a service the user never chose.
///
/// A hosted freenet.org bridge is a genuine product decision that has not been
/// made: it needs a published URL, a decision about who signs for it, and --
/// because it would be internet-facing rather than loopback -- the Ghost Key
/// authorization policy switched on and rate limiting configured. Until then,
/// pointing the default at a URL that does not exist would be worse than
/// pointing it at one that might.
pub fn default_bridge_url() -> &'static str {
    "http://127.0.0.1:8431"
}

/// Signing key of the bridge whose observations this build accepts.
///
/// This is trust policy, not addressing: it says whose signature on a Bitcoin
/// fact this app will believe. It is deliberately a build-time constant
/// because changing it changes who you trust, which should never happen
/// silently at runtime.
pub const TRUSTED_BRIDGE_ID_BS58: &str = "4MZnDAQWccEWXBUb1wt4iTEkDi6Z2MCcZ9WQN1umRsVL";

/// Code hash of the `BitcoinAddressContract` build this app derives keys from.
///
/// Needed to compute a watched address's contract id locally, since the
/// gateway CSP rules out asking the bridge. Goes stale on any contract
/// rebuild -- see the module docs on the pointer-record fix.
pub const ADDRESS_CONTRACT_CODE_HASH_HEX: &str =
    "3b5f1df28497b1cfb365798cb86fc87a7e45480d47c79e22f09b9f801e95463f";

/// The bridge set a freshly-issued invoice names, as an `Order` carries it.
///
/// An `Order::trusted_bridges` that is empty can never be proven paid --
/// `verify_payment_proof` returns `NoTrustedBridges` outright -- so an invoice
/// issued without this would be unpayable from the moment it was signed, and
/// nothing about it would look wrong. That is exactly what happened while the
/// bridge list was a store parameter: every store the UI created was published
/// with an empty list and was permanently incapable of accepting a payment.
///
/// Returning a `Result` rather than defaulting to an empty list is the point:
/// a malformed constant must stop an invoice being issued, not quietly issue
/// one that cannot be settled.
pub fn default_trusted_bridges() -> Result<Vec<freenet_bitcoin_common::BridgeId>, String> {
    freenet_bitcoin_common::BridgeId::from_bs58(TRUSTED_BRIDGE_ID_BS58)
        .map(|id| vec![id])
        .map_err(|e| format!("the build's trusted bridge id is unusable: {e}"))
}

/// [`ADDRESS_CONTRACT_CODE_HASH_HEX`] as the 32 bytes an `Order` carries.
///
/// `None` for a malformed constant rather than an error, because this field is
/// genuinely optional: it drives only the store contract's additive-only
/// related-contract cross-check, and `None` skips that check and forfeits
/// nothing else (the embedded payment proof stays authoritative either way).
/// So an unusable constant must not block issuing an invoice -- unlike the
/// bridge list above, which decides whether the invoice can ever be settled.
pub fn address_contract_code_hash() -> Option<[u8; 32]> {
    let bytes = hex::decode(ADDRESS_CONTRACT_CODE_HASH_HEX).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both constants are hand-maintained (see the module docs on why they
    /// cannot be discovered at runtime), so a typo in either is a real
    /// possibility -- and the consequence of a bad bridge id is an invoice
    /// that can never be proven paid.
    #[test]
    fn the_builds_bitcoin_constants_parse() {
        let bridges = default_trusted_bridges().expect("the trusted bridge id must parse");
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].to_bs58(), TRUSTED_BRIDGE_ID_BS58);

        assert!(
            address_contract_code_hash().is_some(),
            "the address contract code hash must be 32 hex-encoded bytes"
        );
    }
}
