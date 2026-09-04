#![allow(unexpected_cfgs)]

mod bitcoin;
mod handlers;
mod markers;
mod migration;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use harvest_common::migration::HarvestMigrationRequest;
use harvest_common::{
    from_cbor, to_cbor, BitcoinDelegateRequest, HarvestDelegateRequest, HarvestDelegateResponse,
};

// RSA key generation (`InitReputationKeys`) and blind signing
// (`BlindSignFeedbackToken`) need real randomness, via `rsa::rand_core::OsRng`.
// `getrandom` (which `OsRng` sits on) has no OS backend on
// `wasm32-unknown-unknown`, so the workspace enables its "custom" feature --
// but that feature only *allows* registering a source, it doesn't provide
// one. Without this registration the crate fails to LINK (missing
// `__getrandom_custom` symbol), not merely to produce bad randomness at
// runtime, so this was a pre-existing latent build break, independent of
// anything Bitcoin-related, that just hadn't been exercised by a fresh
// `cargo build --target wasm32-unknown-unknown` in this checkout.
//
// The entropy source is the delegate host's own RNG
// (`freenet_stdlib::rand::rand_bytes`, backed by `__frnt__rand__rand_bytes`),
// never a JS/browser API -- a delegate does not run in a browser. Per
// `getrandom::register_custom_getrandom!`'s docs, registration must happen in
// the root binary crate; this delegate IS that root (compiled directly to a
// `cdylib`, no separate `main.rs`), so registering here is correct. The
// registration is a no-op on every other target (native `cargo test` keeps
// using the OS RNG), so this cannot change test behavior.
fn harvest_delegate_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let bytes = freenet_stdlib::rand::rand_bytes(buf.len() as u32);
    buf.copy_from_slice(&bytes);
    Ok(())
}
getrandom::register_custom_getrandom!(harvest_delegate_getrandom);

pub struct HarvestDelegate;

#[delegate]
impl DelegateInterface for HarvestDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                // Application messages require a valid origin
                match origin {
                    Some(MessageOrigin::WebApp(_)) => {}
                    Some(MessageOrigin::Delegate(_)) => {
                        return Err(DelegateError::Other(
                            "harvest delegate does not accept inter-delegate calls".into(),
                        ));
                    }
                    None => {
                        return Err(DelegateError::Other("missing message origin".into()));
                    }
                    Some(_) => {
                        return Err(DelegateError::Other(
                            "unsupported message origin kind".into(),
                        ));
                    }
                }

                if app_msg.processed {
                    return Err(DelegateError::Other(
                        "cannot process an already processed message".into(),
                    ));
                }
                handle_request(ctx, origin.as_ref(), &app_msg.payload)
            }

            // Contract notifications are delivered when a subscribed contract's
            // state changes. This is how the delegate learns about new mailbox
            // messages, reputation entries, etc.
            InboundDelegateMsg::ContractNotification(notification) => {
                handle_contract_notification(ctx, &notification)
            }

            // Responses to contract operations the delegate initiated
            InboundDelegateMsg::GetContractResponse(response) => {
                handle_get_contract_response(ctx, &response)
            }

            InboundDelegateMsg::SubscribeContractResponse(key) => {
                // Subscription confirmed -- nothing to do for now
                let _ = key;
                Ok(vec![])
            }

            other => {
                let msg_type = match &other {
                    InboundDelegateMsg::UserResponse(_) => "UserResponse",
                    InboundDelegateMsg::PutContractResponse(_) => "PutContractResponse",
                    InboundDelegateMsg::UpdateContractResponse(_) => "UpdateContractResponse",
                    InboundDelegateMsg::DelegateMessage(_) => "DelegateMessage",
                    _ => "Unknown",
                };
                Err(DelegateError::Other(format!(
                    "unexpected message type: {msg_type}"
                )))
            }
        }
    }
}

fn handle_request(
    ctx: &mut DelegateCtx,
    origin: Option<&MessageOrigin>,
    payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // A migration export is tried FIRST, and it is the one branch that must
    // not fall through to the others. It is the only request whose answer is
    // this delegate's private keys, so it is the only one whose authorization
    // matters -- and `migration::handle` is where that check lives. Trying it
    // after a failed decode of something else would still be correct, but
    // putting it first keeps the security-relevant path at the top rather than
    // reached by exhaustion.
    //
    // The trial decode is sound for the same reason the two below are: all
    // three enums are externally-tagged, so the variant name is part of the
    // encoding, and `ExportSecrets` appears in none of the others. A payload
    // for one fails to decode as another with "unknown variant" rather than
    // misparsing into the wrong shape. Add a colliding variant name and this
    // stops being true.
    if let Ok(request) = from_cbor::<HarvestMigrationRequest>(payload) {
        return migration::handle(ctx, origin, request);
    }

    // The Bitcoin payment surface (`harvest_common::bitcoin_delegate`) is
    // deliberately NOT folded into `HarvestDelegateRequest`/`Response` as new
    // variants -- that enum is owned by a different, concurrently-edited
    // workstream, and adding variants there would mean editing a file this
    // change doesn't need to touch. Instead we dispatch on which request
    // enum the payload actually decodes as. Both enums use externally-tagged
    // CBOR (the variant name is part of the encoding), so a
    // `BitcoinDelegateRequest` payload fails to decode as a
    // `HarvestDelegateRequest` with an "unknown variant" error rather than
    // silently misparsing into the wrong shape, which is what makes this
    // fallback safe rather than ambiguous.
    match from_cbor::<HarvestDelegateRequest>(payload) {
        Ok(request) => {
            let response = handlers::handle(ctx, request);

            let response_bytes = to_cbor(&response)
                .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

            Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(response_bytes),
            )])
        }
        Err(harvest_decode_err) => {
            let request: BitcoinDelegateRequest =
                from_cbor(payload).map_err(|bitcoin_decode_err| {
                    DelegateError::Other(format!(
                        "payload is neither a HarvestDelegateRequest ({harvest_decode_err}) nor a \
                     BitcoinDelegateRequest ({bitcoin_decode_err})"
                    ))
                })?;

            let response = bitcoin::handle(ctx, request)?;

            let response_bytes = to_cbor(&response)
                .map_err(|e| DelegateError::Other(format!("serialize bitcoin response: {e}")))?;

            Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(response_bytes),
            )])
        }
    }
}

/// Handle a contract state change notification.
///
/// The delegate subscribes to mailbox and reputation contracts. When new
/// messages or feedback entries arrive, this handler processes them.
fn handle_contract_notification(
    _ctx: &mut DelegateCtx,
    notification: &freenet_stdlib::prelude::ContractNotification,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // The notification contains the contract key and the update data.
    // We need to determine which contract type this is and handle accordingly.
    //
    // For now, forward the notification to the UI as an application message
    // so the UI can update its view. The delegate will eventually handle
    // auto-responses (e.g., auto-signing feedback tokens) here.

    let notification_msg = HarvestDelegateResponse::ContractUpdate {
        contract_key: notification.contract_id.as_bytes().to_vec(),
        update_data: notification.new_state.as_ref().to_vec(),
    };

    let response_bytes = to_cbor(&notification_msg)
        .map_err(|e| DelegateError::Other(format!("serialize notification: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// Handle a response to a contract GET the delegate initiated.
fn handle_get_contract_response(
    _ctx: &mut DelegateCtx,
    response: &freenet_stdlib::prelude::GetContractResponse,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // Forward contract state to the UI
    let state_bytes = response
        .state
        .as_ref()
        .map(|s| s.as_ref().to_vec())
        .unwrap_or_default();
    let contract_key = response.contract_id.as_bytes().to_vec();

    let response_msg = HarvestDelegateResponse::ContractState {
        contract_key,
        state: state_bytes,
    };

    let response_bytes = to_cbor(&response_msg)
        .map_err(|e| DelegateError::Other(format!("serialize contract state: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}
