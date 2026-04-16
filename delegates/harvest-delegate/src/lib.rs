#![allow(unexpected_cfgs)]

mod handlers;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use harvest_common::{from_cbor, to_cbor, HarvestDelegateRequest};

pub struct HarvestDelegate;

#[delegate]
impl DelegateInterface for HarvestDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        // Validate origin -- only accept messages from web apps
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

        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                if app_msg.processed {
                    return Err(DelegateError::Other(
                        "cannot process an already processed message".into(),
                    ));
                }
                handle_request(ctx, &app_msg.payload)
            }
            other => {
                let msg_type = match &other {
                    InboundDelegateMsg::UserResponse(_) => "UserResponse",
                    InboundDelegateMsg::GetContractResponse(_) => "GetContractResponse",
                    InboundDelegateMsg::PutContractResponse(_) => "PutContractResponse",
                    InboundDelegateMsg::UpdateContractResponse(_) => "UpdateContractResponse",
                    InboundDelegateMsg::SubscribeContractResponse(_) => "SubscribeContractResponse",
                    InboundDelegateMsg::ContractNotification(_) => "ContractNotification",
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
