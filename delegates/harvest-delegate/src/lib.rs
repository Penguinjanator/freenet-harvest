#![allow(unexpected_cfgs)]

mod handlers;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use harvest_common::{from_cbor, to_cbor, HarvestDelegateRequest, HarvestDelegateResponse};

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
                handle_request(ctx, &app_msg.payload)
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
    payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let request: HarvestDelegateRequest = from_cbor(payload)
        .map_err(|e| DelegateError::Other(format!("deserialize request: {e}")))?;

    let response = handlers::handle(ctx, request);

    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
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
