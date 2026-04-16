//! Gateway connection layer for communicating with the Freenet node.
//!
//! Handles WebSocket connection, delegate registration, and contract operations.

mod connection;
mod delegate_api;

pub use connection::{connect, ConnectionStatus};
pub use delegate_api::{
    get_contract, put_contract, register_delegate, send_delegate_message, update_contract,
};

use dioxus::prelude::*;
use freenet_stdlib::client_api::WebApi;

/// Global WebSocket connection to the Freenet node.
pub static WEB_API: GlobalSignal<Option<WebApi>> = GlobalSignal::new(|| None);

/// Current connection status.
pub static CONNECTION_STATUS: GlobalSignal<ConnectionStatus> =
    GlobalSignal::new(|| ConnectionStatus::Disconnected);
