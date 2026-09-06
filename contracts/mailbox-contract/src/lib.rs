#![allow(unexpected_cfgs)]

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use harvest_common::mailbox::{MailboxDelta, MailboxParameters, MailboxStateV1, MailboxSummaryV2};

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }

        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        mailbox_state
            .verify()
            .map(|_| ValidateResult::Valid)
            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("State verification failed: {e}"),
            })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let mut mailbox_state = if state.as_ref().is_empty() {
            MailboxStateV1::default()
        } else {
            from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let new_state = from_reader::<MailboxStateV1, &[u8]>(new_state.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    // Everything, and `apply_delta` decides what is already
                    // held.
                    //
                    // # This arm used to answer that question itself, and got
                    // it wrong
                    //
                    // It filtered on `existing.nonce == m.nonce`, which was
                    // right while the nonce WAS the identity and silently
                    // wrong after `verify`, `summarize`, `delta` and the dedup
                    // moved to `entry_digest`. A PUT or a resync arrives here,
                    // so a peer merging a full state discarded a message
                    // because something else shared its nonce -- which is the
                    // retraction the re-key exists to prevent, by a different
                    // door.
                    //
                    // The fix is not a corrected comparison. It is that this
                    // arm no longer HAS a comparison: `apply_delta` dedups by
                    // `entry_digest`, so handing it everything is both correct
                    // and idempotent, and there is one definition of "the same
                    // message" rather than two that can drift apart.
                    // `no_production_code_compares_message_nonces_for_identity`
                    // fails if a fourth site starts answering it again.
                    mailbox_state
                        .apply_delta(&Some(new_state.messages))
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        })?;
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<MailboxDelta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    mailbox_state.apply_delta(&Some(delta)).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
                        }
                    })?;
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }

        let mut updated_state = vec![];
        into_writer(&mailbox_state, &mut updated_state)
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        Ok(UpdateModification::valid(updated_state.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(vec![]));
        }
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

        let summary = mailbox_state.summarize();
        let mut summary_bytes = vec![];
        into_writer(&summary, &mut summary_bytes)
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(summary_bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _parameters = from_reader::<MailboxParameters, &[u8]>(parameters.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        // Both empties are the SAME convention `summarize_state` above uses
        // and `validate_state` uses: zero bytes means "there is no state
        // here yet", not a malformed encoding. Decoding either as CBOR gives
        // `UnexpectedEof`, so before this the very first exchange a new
        // subscriber makes -- it summarizes its absent state, which is zero
        // bytes, and asks a holder for the difference -- was answered with a
        // decode error rather than the mailbox.
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(vec![]));
        }
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old_summary = if summary.as_ref().is_empty() {
            MailboxSummaryV2::default()
        } else {
            from_reader::<MailboxSummaryV2, &[u8]>(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };

        match mailbox_state.delta(&old_summary) {
            Some(delta) => {
                let mut delta_bytes = vec![];
                into_writer(&delta, &mut delta_bytes)
                    .map_err(|e| ContractError::Deser(e.to_string()))?;
                Ok(StateDelta::from(delta_bytes))
            }
            None => Ok(StateDelta::from(vec![])),
        }
    }
}

/// The contract's own entry points, which had no tests until 2026-09-05.
///
/// That absence is why the state-merge arm below kept deciding "already
/// held" by nonce for a whole review round after `verify`, `summarize`,
/// `delta` and the dedup had all moved to `entry_digest`: nothing exercised
/// it.
#[cfg(test)]
mod tests {
    use super::*;
    use harvest_common::mailbox::{ConversationId, EncryptedMessage};

    fn message(nonce: [u8; 24], ciphertext: &[u8], seconds: i64) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![2u8; 32],
            ciphertext: ciphertext.to_vec(),
            timestamp: chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp"),
            nonce,
        }
    }

    fn encoded(state: &MailboxStateV1) -> Vec<u8> {
        let mut bytes = vec![];
        into_writer(state, &mut bytes).expect("encode");
        bytes
    }

    fn parameters() -> Parameters<'static> {
        let mut bytes = vec![];
        let owner = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        into_writer(&MailboxParameters::new(owner), &mut bytes).expect("encode");
        Parameters::from(bytes)
    }

    /// Put `data` through the contract and read back the state it produced.
    fn update(state: &MailboxStateV1, data: Vec<UpdateData<'static>>) -> MailboxStateV1 {
        let modification = <Contract as ContractInterface>::update_state(
            parameters(),
            State::from(encoded(state)),
            data,
        )
        .expect("the contract must accept this update");
        let bytes = match modification {
            UpdateModification {
                new_state: Some(s), ..
            } => s.as_ref().to_vec(),
            other => panic!("expected a new state, got {other:?}"),
        };
        from_reader::<MailboxStateV1, &[u8]>(bytes.as_ref()).expect("decode")
    }

    /// **A whole-state merge must not drop a message because something else
    /// shares its nonce.**
    ///
    /// This is the same defect as the one the re-key fixed, at the one site
    /// the re-key missed. A PUT and a resync both arrive as
    /// `UpdateData::State`, so a peer merging a full state would silently
    /// discard the confession and keep the retraction -- the contract's
    /// identity rule says they are two messages, and this arm said they were
    /// one.
    #[test]
    fn a_state_merge_keeps_a_message_whose_nonce_something_else_shares() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        // A peer that already holds the retraction merges a state carrying
        // the confession.
        let held = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };
        let incoming = MailboxStateV1 {
            messages: vec![confession.clone()],
        };

        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );

        assert!(
            merged.messages.contains(&confession),
            "a whole-state merge dropped a message because another shared its nonce"
        );
        assert!(merged.messages.contains(&retraction));
        merged
            .verify()
            .expect("the contract must accept its own result");
    }

    /// And the same in the other direction, since a merge is not symmetric in
    /// its inputs.
    #[test]
    fn a_state_merge_keeps_the_held_message_too() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let held = MailboxStateV1 {
            messages: vec![confession.clone()],
        };
        let incoming = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };

        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );
        assert!(merged.messages.contains(&confession));
        assert!(merged.messages.contains(&retraction));
    }

    /// A merge of a state this peer already holds entirely changes nothing,
    /// and in particular does not duplicate anything.
    #[test]
    fn merging_a_state_already_held_changes_nothing() {
        let held = MailboxStateV1 {
            messages: vec![
                message([7u8; 24], b"one", 1_700_000_000),
                message([8u8; 24], b"two", 1_700_000_001),
            ],
        };

        let merged = update(&held, vec![UpdateData::State(State::from(encoded(&held)))]);
        assert_eq!(merged.messages.len(), 2);
        merged.verify().expect("valid");
    }

    /// The delta arm carries whole messages and always did; this is here so
    /// the two arms are covered by the same fixture rather than one of them
    /// being assumed.
    #[test]
    fn a_delta_keeps_a_message_whose_nonce_something_else_shares() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let held = MailboxStateV1 {
            messages: vec![retraction.clone()],
        };
        let mut delta_bytes = vec![];
        into_writer(&vec![confession.clone()], &mut delta_bytes).expect("encode");

        let merged = update(
            &held,
            vec![UpdateData::Delta(StateDelta::from(delta_bytes))],
        );
        assert!(merged.messages.contains(&confession));
        assert!(merged.messages.contains(&retraction));
    }

    /// The state the contract hands back is one it would itself accept.
    #[test]
    fn a_merged_state_validates() {
        let held = MailboxStateV1 {
            messages: vec![message([7u8; 24], b"one", 1_700_000_000)],
        };
        let incoming = MailboxStateV1 {
            messages: vec![message([7u8; 24], b"two", 1_700_000_001)],
        };
        let merged = update(
            &held,
            vec![UpdateData::State(State::from(encoded(&incoming)))],
        );

        let verdict = <Contract as ContractInterface>::validate_state(
            parameters(),
            State::from(encoded(&merged)),
            RelatedContracts::default(),
        )
        .expect("validate");
        assert!(matches!(verdict, ValidateResult::Valid));
    }

    /// **A peer that holds nothing yet can still be sent everything.**
    ///
    /// `summarize_state` answers a zero-byte state with a zero-byte summary
    /// -- that is the "I have nothing" summary, and it is the FIRST thing a
    /// new subscriber sends. If the holder cannot decode it, the new
    /// subscriber is answered with an error instead of the mailbox, and it
    /// never bootstraps at all.
    #[test]
    fn a_holder_answers_the_empty_summary_with_everything_it_has() {
        let held = MailboxStateV1 {
            messages: vec![
                message([7u8; 24], b"one", 1_700_000_000),
                message([8u8; 24], b"two", 1_700_000_001),
            ],
        };
        let empty_summary = <Contract as ContractInterface>::summarize_state(
            parameters(),
            State::from(Vec::<u8>::new()),
        )
        .expect("summarizing an absent state must succeed");

        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(encoded(&held)),
            empty_summary,
        )
        .expect("a holder must answer the empty summary rather than erroring");

        let carried = from_reader::<MailboxDelta, &[u8]>(delta.as_ref())
            .expect("the delta must be a decodable message list");
        assert_eq!(
            carried.len(),
            2,
            "the empty summary means 'I have nothing', so the answer is everything"
        );
    }

    /// The mirror: a peer that holds nothing has nothing to send, which is an
    /// empty delta and not an error.
    #[test]
    fn a_holder_of_nothing_answers_with_an_empty_delta() {
        let delta = <Contract as ContractInterface>::get_state_delta(
            parameters(),
            State::from(Vec::<u8>::new()),
            StateSummary::from(Vec::<u8>::new()),
        )
        .expect("a peer holding no state must answer, not error");
        assert!(delta.as_ref().is_empty());
    }

    /// **No production code decides "the same message" by comparing nonces.**
    ///
    /// A source scrape, because the three call sites that drifted did so one
    /// at a time over three separate changes -- `dedupe_by_nonce`,
    /// `summarize`, and this contract's state-merge arm -- and each was found
    /// by a person rather than by the suite. `entry_digest` is the one
    /// definition of identity; this fails when a fourth site starts answering
    /// the question for itself.
    ///
    /// Scoped to the part of each file before its `#[cfg(test)]`, because
    /// tests compare nonces legitimately (to assert that two entries collide,
    /// which is the precondition of half these tests).
    #[test]
    fn no_production_code_compares_message_nonces_for_identity() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();

        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let crates = [
            "common/src",
            "contracts/mailbox-contract/src",
            "contracts/store-contract/src",
            "contracts/reputation-contract/src",
            "ui/src",
            "delegates/harvest-delegate/src",
        ];
        for dir in crates {
            for path in rust_files(&root.join(dir)) {
                let text = std::fs::read_to_string(&path).expect("read");
                let production = match text.find("#[cfg(test)]") {
                    Some(at) => &text[..at],
                    None => &text[..],
                };
                scanned += 1;
                for (number, line) in production.lines().enumerate() {
                    let line = line.trim();
                    if line.starts_with("//") || line.starts_with("///") {
                        continue;
                    }
                    if line.contains(".nonce ==") || line.contains("== m.nonce") {
                        offenders.push(format!("{}:{}: {line}", path.display(), number + 1));
                    }
                }
            }
        }

        assert!(scanned > 10, "the scrape found almost no files: {scanned}");
        assert!(
            offenders.is_empty(),
            "these decide message identity by nonce rather than by `entry_digest`:\n{}",
            offenders.join("\n")
        );
    }

    fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(rust_files(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
        found
    }
}
