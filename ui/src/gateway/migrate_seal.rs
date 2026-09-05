//! When a migration may declare itself done.
//!
//! Split out of `migrate_ops` because that module is wasm-only
//! (`gateway/mod.rs` gates it on `target_arch = "wasm32"`, since it exists to
//! drive the gateway's shared response handler, which has no native
//! counterpart). Nothing in it is reachable from `cargo test`, so the one
//! decision in it that loses data when it is wrong lives here instead, where
//! the host can run it -- the same split `crate::migrate` already makes
//! against the rest of the probe.

use crate::migrate::Seal;

/// Whether the recovered state actually reached the successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForwardPut {
    /// The node answered `PutResponse` for the successor instance. This is the
    /// only signal that establishes the write landed.
    Acknowledged,
    /// The send failed, or the deadline expired with no answer. Both say the
    /// same thing: nothing is known about whether the state arrived.
    ///
    /// `put_contract` resolving is NOT this or the other -- it reports that
    /// the WebSocket accepted the bytes, which is not a claim about the
    /// contract at all.
    Unconfirmed,
}

/// Whether the durable pointers a later load follows name the successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuccessorReference {
    /// They do. A later load that skips the probe still reaches the migrated
    /// data.
    Durable,
    /// They do not: the delegate's registry still names the predecessor, so a
    /// later load would restore the old ids, find the marker, skip the probe,
    /// and quietly go back to the superseded generation.
    Stale,
}

/// What to do with a migration whose forward PUT has settled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// Repoint this session at the successor, tell the seller, and write the
    /// durable marker so no later load repeats the walk.
    AdoptAndSeal,
    /// Repoint this session and tell the seller, but leave the lineage
    /// unsealed: the next load walks it again, re-PUTs a state the contracts
    /// merge idempotently, and re-adopts.
    AdoptWithoutSealing,
    /// Do neither. The write was never confirmed, so there is nothing to adopt
    /// and nothing to tell the seller about.
    Discard,
}

/// The sealing rule, in one place.
///
/// The marker is not a note about what happened; it is a claim that nothing
/// needs to run again, which every later load believes without checking. Two
/// facts have to hold before that claim is true, and both of them are things
/// that can silently not happen:
///
/// 1. the recovered state reached the successor, and
/// 2. every durable pointer a later load follows already names it.
///
/// Anything short of a fact resolves the same way: do not seal, walk again
/// next load. That is wasteful and correct, and it is the direction every
/// other uncertainty in the migration resolves in.
pub fn disposition(put: ForwardPut, reference: SuccessorReference, seal: Seal) -> Disposition {
    match put {
        // Nothing is known to have landed, so there is nothing to adopt, and
        // telling the seller their data was recovered would be a claim this
        // code cannot support.
        ForwardPut::Unconfirmed => Disposition::Discard,
        ForwardPut::Acknowledged => match (reference, seal) {
            (SuccessorReference::Durable, Seal::Seal) => Disposition::AdoptAndSeal,
            // Adopting without sealing is the safe half of every remaining
            // case: this session uses the successor, and the next load checks
            // again rather than trusting a claim that was never established.
            _ => Disposition::AdoptWithoutSealing,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUTS: [ForwardPut; 2] = [ForwardPut::Acknowledged, ForwardPut::Unconfirmed];
    const REFERENCES: [SuccessorReference; 2] =
        [SuccessorReference::Durable, SuccessorReference::Stale];
    const SEALS: [Seal; 2] = [Seal::Seal, Seal::Retry];

    /// Defect 1. The forward PUT used to be `spawn_local`'d fire-and-forget
    /// with the marker written on the next line, so a PUT the node rejected,
    /// or never received, still sealed -- and every later load skipped the
    /// migration for a recovery that had not landed. The state was orphaned
    /// permanently and silently.
    #[test]
    fn an_unconfirmed_forward_put_neither_adopts_nor_seals() {
        for reference in REFERENCES {
            for seal in SEALS {
                assert_eq!(
                    disposition(ForwardPut::Unconfirmed, reference, seal),
                    Disposition::Discard,
                    "an unconfirmed PUT must not adopt or seal ({reference:?}, {seal:?})"
                );
            }
        }
    }

    /// Defect 2. Sealing over a registry that still names the predecessor is
    /// worse than not sealing at all: the next load restores the old ids,
    /// finds the marker, skips the probe, and returns to the superseded
    /// generation with the migrated instances sitting unreferenced beside it.
    /// The migration appears to succeed and then undoes itself on reload.
    #[test]
    fn a_stale_successor_reference_blocks_the_seal() {
        for seal in SEALS {
            assert_ne!(
                disposition(ForwardPut::Acknowledged, SuccessorReference::Stale, seal),
                Disposition::AdoptAndSeal,
                "a stale successor reference must not seal ({seal:?})"
            );
        }
    }

    /// The positive half, so the rule cannot be satisfied by refusing to seal
    /// anything at all.
    #[test]
    fn an_acknowledged_put_with_a_durable_reference_seals() {
        assert_eq!(
            disposition(
                ForwardPut::Acknowledged,
                SuccessorReference::Durable,
                Seal::Seal
            ),
            Disposition::AdoptAndSeal
        );
    }

    /// `migrate::seal_decision` still has the final say: an outcome it typed
    /// as `Retry` is adopted but never sealed, however well the write went.
    #[test]
    fn a_retry_outcome_never_seals() {
        for put in PUTS {
            for reference in REFERENCES {
                assert_ne!(
                    disposition(put, reference, Seal::Retry),
                    Disposition::AdoptAndSeal,
                    "Retry must never seal ({put:?}, {reference:?})"
                );
            }
        }
    }

    /// Stated as an implication over the whole input space rather than as
    /// three separate cases, so a future input added to `disposition` cannot
    /// open a fourth way to seal without failing here.
    #[test]
    fn nothing_else_seals() {
        for put in PUTS {
            for reference in REFERENCES {
                for seal in SEALS {
                    if disposition(put, reference, seal) == Disposition::AdoptAndSeal {
                        assert_eq!(put, ForwardPut::Acknowledged);
                        assert_eq!(reference, SuccessorReference::Durable);
                        assert_eq!(seal, Seal::Seal);
                    }
                }
            }
        }
    }
}
