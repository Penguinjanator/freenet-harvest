//! The delegate-migration envelope.
//!
//! # What this is for
//!
//! A delegate's secrets live at `secrets_dir/<delegate-key>/` on the node, and
//! that key is `BLAKE3(BLAKE3(wasm) || params)`. So every rebuild of the
//! delegate strands everything it holds -- the RSA reputation keypairs, the
//! transaction records, the per-identity store registry, the Bitcoin watch list
//! -- at an address the new delegate never looks at. None of it is on the
//! network, so nothing else can recover it.
//!
//! `freenet-migrate` carries it forward by having the SUCCESSOR ask each
//! PREDECESSOR to export. That means the old delegate has to have shipped with
//! a handler for the request, which is the property this type exists to give
//! Harvest.
//!
//! # It is forward-looking, and that is the point
//!
//! Generations V1 to V4 (see `legacy/harvest_delegate.toml`) have no export
//! handler: their `handle_request` rejects any payload that is neither a
//! `HarvestDelegateRequest` nor a `BitcoinDelegateRequest`. Nothing added later
//! can change that -- the code that would have to answer is already deployed.
//! Secrets held under those four generations are not recoverable.
//!
//! Which is exactly the argument for adopting this now rather than at the next
//! re-key: every release that ships without an export handler adds one more
//! generation whose secrets can never be carried forward.
//!
//! # Why a separate enum
//!
//! `handle_request` picks between `HarvestDelegateRequest` and
//! `BitcoinDelegateRequest` by trying each decode in turn, which is sound only
//! because they share no variant name -- a payload for one fails to decode as
//! the other with "unknown variant" rather than silently misparsing. This enum
//! keeps that property: `ExportSecrets` appears in neither of the others, and
//! externally-tagged CBOR puts the variant name in the encoding.
//!
//! Adding a variant to one of those enums instead would have been the smaller
//! diff and the worse one: both are `#[non_exhaustive]` wire types read by
//! deployed delegates, and this is a request no deployed delegate can answer.

use serde::{Deserialize, Serialize};

/// A request from a successor delegate's web app to a predecessor delegate.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum HarvestMigrationRequest {
    /// Export every secret under the `harvest:` prefix so the successor can
    /// import it.
    ///
    /// `source_generation` is echoed back in the reply so the successor can
    /// tell which predecessor answered; it is the `generation` field of the
    /// row in `legacy/harvest_delegate.toml`.
    ExportSecrets { source_generation: u32 },
}

/// The key prefix an export covers.
///
/// Every secret the harvest delegate writes begins with this: `harvest:rsa_sk:`,
/// `harvest:rsa_pk:`, `harvest:tx:`, `harvest:tx_index`, `harvest:stores:` and
/// `harvest:bitcoin:`. Exporting by prefix rather than exporting the whole
/// delegate scope is the safer of the two options `freenet-migrate` offers: a
/// whole-scope export hands the requesting origin every secret in the
/// namespace, and is sound only for a delegate that serves exactly one web app.
/// Harvest's does today -- but the prefix costs nothing, needs no
/// acknowledgement token, and stays correct if that ever stops being true.
///
/// A key written outside this prefix would be silently left behind, so this
/// constant and the key builders in the delegate's `handlers` module have to
/// stay in step. `harvest-delegate`'s tests assert that they do.
pub const SECRET_KEY_PREFIX: &[u8] = b"harvest:";
