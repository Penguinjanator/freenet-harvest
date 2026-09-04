//! API for communicating with delegates and contracts via the Freenet gateway.
//!
//! All functions require an active WebSocket connection (WEB_API must be Some).
//! These are only usable in WASM builds -- native stubs return errors.

#[cfg(target_arch = "wasm32")]
use dioxus::logger::tracing::info;
#[cfg(target_arch = "wasm32")]
use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, DelegateRequest};
use freenet_stdlib::prelude::*;

/// Send a request to a delegate (harvest or ghostkey).
pub async fn send_delegate_message(
    delegate_key: &DelegateKey,
    payload: Vec<u8>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
            key: delegate_key.clone(),
            params: Parameters::from(Vec::<u8>::new()),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(payload),
            )],
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("send delegate message: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (delegate_key, payload);
        Err("delegate messaging requires WASM".into())
    }
}

/// GET a contract's state, optionally subscribing to updates.
pub async fn get_contract(
    contract_key: &ContractInstanceId,
    subscribe: bool,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        info!("GET contract (subscribe={subscribe}): {:?}", contract_key);

        let request = ClientRequest::ContractOp(ContractRequest::Get {
            key: *contract_key,
            return_contract_code: false,
            subscribe,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("get contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, subscribe);
        Err("contract operations require WASM".into())
    }
}

/// GET-and-subscribe a contract by its raw 32-byte instance id.
///
/// Contract ids reach the UI as `Vec<u8>` -- from delegate registrations and
/// from other contracts' state -- so this is the one place that checks the
/// length before turning them into a `ContractInstanceId`.
pub async fn get_contract_by_id(contract_id: &[u8]) -> Result<(), String> {
    let id_bytes: [u8; 32] = contract_id
        .try_into()
        .map_err(|_| "contract id must be 32 bytes".to_string())?;
    get_contract(&ContractInstanceId::new(id_bytes), true).await
}

/// Send a contract update (delta or full state).
pub async fn update_contract(
    contract_key: &ContractKey,
    data: UpdateData<'static>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Update {
            key: *contract_key,
            data,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("update contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, data);
        Err("contract operations require WASM".into())
    }
}

/// PUT a new contract onto the network and subscribe to it.
pub async fn put_contract(contract: ContractContainer, state: WrappedState) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state,
            related_contracts: RelatedContracts::new(),
            subscribe: true,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("put contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract, state);
        Err("contract operations require WASM".into())
    }
}

/// Register a delegate with the Freenet node.
pub async fn register_delegate(delegate_wasm: &[u8]) -> Result<DelegateKey, String> {
    #[cfg(target_arch = "wasm32")]
    {
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

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("register delegate: {e}"))?;

        info!("Registered delegate: {:?}", key);
        Ok(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = delegate_wasm;
        Err("delegate registration requires WASM".into())
    }
}
