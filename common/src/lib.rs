//! Shared types for Harvest, the decentralized marketplace on Freenet.
//!
//! This crate defines the wire-format schemas used by the Harvest contracts,
//! delegate, and UI: store listings, feedback-token protocol messages, and
//! reputation contract state.
//!
//! See the design document in `docs/design.md` for the overall architecture.

#![deny(unsafe_code)]

// TODO: store / listing / mailbox / reputation schemas, feedback-token
// protocol messages. Schemas will be added as each subsystem is designed
// in isolation.
