//! Gateway connection layer for communicating with the Freenet node.
//!
//! Handles WebSocket connection, delegate registration, and contract operations.

mod connection;
mod delegate_api;
pub mod response_handler;

pub use connection::{connect, ConnectionStatus};
pub use delegate_api::{
    get_contract, put_contract, register_delegate, send_delegate_message, update_contract,
};

use dioxus::prelude::*;

use crate::state::AppState;

/// Global WebSocket connection to the Freenet node.
#[cfg(target_arch = "wasm32")]
pub static WEB_API: GlobalSignal<Option<freenet_stdlib::client_api::WebApi>> =
    GlobalSignal::new(|| None);

/// Current connection status.
pub static CONNECTION_STATUS: GlobalSignal<ConnectionStatus> =
    GlobalSignal::new(|| ConnectionStatus::Disconnected);

/// Application state -- updated by the response handler, read by UI components.
pub static APP_STATE: GlobalSignal<AppState> = GlobalSignal::new(AppState::default);
