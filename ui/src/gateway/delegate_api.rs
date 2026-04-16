use dioxus::logger::tracing::info;
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, DelegateRequest};
use freenet_stdlib::prelude::*;

use super::WEB_API;

/// Send a request to a delegate (harvest or ghostkey).
///
/// The payload is CBOR-encoded request bytes. The delegate key identifies
/// which delegate receives the message.
pub async fn send_delegate_message(
    delegate_key: &DelegateKey,
    payload: Vec<u8>,
) -> Result<(), String> {
    let request = ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
        key: delegate_key.clone(),
        params: Parameters::from(Vec::<u8>::new()),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(payload),
        )],
    });

    let mut api = WEB_API.write();
    let web_api = api.as_mut().ok_or("not connected to gateway")?;
    web_api
        .send(request)
        .await
        .map_err(|e| format!("send delegate message: {e}"))?;
    Ok(())
}

/// GET a contract's state, optionally subscribing to updates.
pub async fn get_contract(
    contract_key: &ContractInstanceId,
    subscribe: bool,
) -> Result<(), String> {
    info!("GET contract (subscribe={subscribe}): {:?}", contract_key);

    let request = ClientRequest::ContractOp(ContractRequest::Get {
        key: contract_key.clone(),
        return_contract_code: false,
        subscribe,
        blocking_subscribe: false,
    });

    let mut api = WEB_API.write();
    let web_api = api.as_mut().ok_or("not connected to gateway")?;
    web_api
        .send(request)
        .await
        .map_err(|e| format!("get contract: {e}"))?;
    Ok(())
}

/// Send a contract update (delta or full state).
pub async fn update_contract(
    contract_key: &ContractKey,
    data: UpdateData<'static>,
) -> Result<(), String> {
    let request = ClientRequest::ContractOp(ContractRequest::Update {
        key: contract_key.clone(),
        data,
    });

    let mut api = WEB_API.write();
    let web_api = api.as_mut().ok_or("not connected to gateway")?;
    web_api
        .send(request)
        .await
        .map_err(|e| format!("update contract: {e}"))?;
    Ok(())
}

/// PUT a new contract onto the network and subscribe to it.
pub async fn put_contract(contract: ContractContainer, state: WrappedState) -> Result<(), String> {
    let request = ClientRequest::ContractOp(ContractRequest::Put {
        contract,
        state,
        related_contracts: RelatedContracts::new(),
        subscribe: true,
        blocking_subscribe: false,
    });

    let mut api = WEB_API.write();
    let web_api = api.as_mut().ok_or("not connected to gateway")?;
    web_api
        .send(request)
        .await
        .map_err(|e| format!("put contract: {e}"))?;
    Ok(())
}

/// Register a delegate with the Freenet node.
///
/// Returns the delegate key. The WASM bytes are the compiled delegate binary.
pub async fn register_delegate(delegate_wasm: &[u8]) -> Result<DelegateKey, String> {
    let delegate_code = DelegateCode::from(delegate_wasm.to_vec());
    let params = Parameters::from(Vec::<u8>::new());
    let delegate = Delegate::from((&delegate_code, &params));
    let container = DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate));
    let key = container.key().clone();

    let request = ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
        delegate: container,
        cipher: DelegateRequest::DEFAULT_CIPHER,
        nonce: DelegateRequest::DEFAULT_NONCE,
    });

    let mut api = WEB_API.write();
    let web_api = api.as_mut().ok_or("not connected to gateway")?;
    web_api
        .send(request)
        .await
        .map_err(|e| format!("register delegate: {e}"))?;

    info!("Registered delegate: {:?}", key);
    Ok(key)
}
