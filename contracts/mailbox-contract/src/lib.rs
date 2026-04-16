#![allow(unexpected_cfgs)]

use chrono::Utc;
use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use harvest_common::mailbox::{
    MailboxDelta, MailboxParameters, MailboxStateV1, MailboxSummary,
};

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
            .verify(Utc::now())
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

        let now = Utc::now();

        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    let new_state =
                        from_reader::<MailboxStateV1, &[u8]>(new_state.as_ref())
                            .map_err(|e| ContractError::Deser(e.to_string()))?;
                    // Merge: add messages we don't have
                    let delta: MailboxDelta = new_state
                        .messages
                        .into_iter()
                        .filter(|m| {
                            !mailbox_state
                                .messages
                                .iter()
                                .any(|existing| existing.nonce == m.nonce)
                        })
                        .collect();
                    if !delta.is_empty() {
                        mailbox_state
                            .apply_delta(&Some(delta), now)
                            .map_err(|e| ContractError::InvalidUpdateWithInfo {
                                reason: e.to_string(),
                            })?;
                    }
                }
                UpdateData::Delta(d) => {
                    if d.as_ref().is_empty() {
                        continue;
                    }
                    let delta = from_reader::<MailboxDelta, &[u8]>(d.as_ref())
                        .map_err(|e| ContractError::Deser(e.to_string()))?;
                    mailbox_state
                        .apply_delta(&Some(delta), now)
                        .map_err(|e| ContractError::InvalidUpdateWithInfo {
                            reason: e.to_string(),
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
        let mailbox_state = from_reader::<MailboxStateV1, &[u8]>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;
        let old_summary = from_reader::<MailboxSummary, &[u8]>(summary.as_ref())
            .map_err(|e| ContractError::Deser(e.to_string()))?;

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
