use dioxus::prelude::*;

use super::my_store::MyStore;
use super::reputation_view::ReputationView;
use super::store_view::StoreView;
use crate::gateway::{ConnectionStatus, CONNECTION_STATUS};

/// Top-level navigation route.
#[derive(Clone, PartialEq)]
enum Route {
    Browse,
    MyStore,
    Reputation,
}

#[component]
pub fn App() -> Element {
    let mut current_route = use_signal(|| Route::Browse);
    let connection_status = CONNECTION_STATUS.read().clone();

    // Connect to gateway, register delegates, and spawn response handler loop
    #[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
    {
        use futures::StreamExt;

        use_effect(|| {
            wasm_bindgen_futures::spawn_local(async {
                // Step 1: Connect to the Freenet gateway
                let mut rx = match crate::gateway::connect().await {
                    Ok(rx) => rx,
                    Err(e) => {
                        dioxus::logger::tracing::error!("Failed to connect: {}", e);
                        *CONNECTION_STATUS.write() = ConnectionStatus::Error(e);
                        return;
                    }
                };

                dioxus::logger::tracing::info!("Connected -- registering delegates");

                // Step 2: Register the harvest delegate
                let harvest_wasm = include_bytes!("../../public/contracts/harvest_delegate.wasm");
                match crate::gateway::register_delegate(harvest_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Harvest delegate registered: {:?}", key);
                        crate::gateway::APP_STATE.write().harvest_delegate_key = Some(key);
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register harvest delegate: {}",
                            e
                        );
                    }
                }

                // Step 3: The ghostkey delegate should already be registered
                // by the ghostkey management UI. We need its key to communicate
                // with it. The key is determined by BLAKE3(BLAKE3(wasm) || params).
                // For now, we request the list of ghostkeys once we know the key.
                // This will be wired up when we have the ghostkey delegate WASM
                // available or a way to discover the key at runtime.

                // Step 5: Start the response processing loop
                dioxus::logger::tracing::info!("Starting response loop");
                while let Some(response) = rx.next().await {
                    crate::gateway::response_handler::handle_response(response);
                }

                dioxus::logger::tracing::warn!("Response loop ended (connection lost)");
                *CONNECTION_STATUS.write() = ConnectionStatus::Disconnected;
            });
        });
    }

    rsx! {
        div { class: "harvest-app",
            style: "font-family: system-ui, sans-serif; max-width: 960px; margin: 0 auto; padding: 1rem;",

            // Header
            header {
                style: "display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid #2d5016; padding-bottom: 0.5rem; margin-bottom: 1rem;",
                h1 {
                    style: "margin: 0; color: #2d5016;",
                    "Harvest"
                }
                nav {
                    style: "display: flex; gap: 1rem; align-items: center;",
                    // Connection status indicator
                    span {
                        style: "font-size: 0.75rem; color: {status_color(&connection_status)};",
                        "{connection_status}"
                    }
                    button {
                        style: nav_button_style(&current_route(), &Route::Browse),
                        onclick: move |_| current_route.set(Route::Browse),
                        "Browse"
                    }
                    button {
                        style: nav_button_style(&current_route(), &Route::MyStore),
                        onclick: move |_| current_route.set(Route::MyStore),
                        "My Store"
                    }
                    button {
                        style: nav_button_style(&current_route(), &Route::Reputation),
                        onclick: move |_| current_route.set(Route::Reputation),
                        "Reputation"
                    }
                }
            }

            // Notifications
            {notification_bar()}

            // Main content
            match current_route() {
                Route::Browse => rsx! { StoreView {} },
                Route::MyStore => rsx! { MyStore {} },
                Route::Reputation => rsx! { ReputationView {} },
            }
        }
    }
}

fn notification_bar() -> Element {
    let app_state = crate::gateway::APP_STATE.read();
    if app_state.notifications.is_empty() {
        return rsx! {};
    }

    rsx! {
        div {
            style: "background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 0.5rem 1rem; margin-bottom: 1rem;",
            for notification in &app_state.notifications {
                p {
                    style: "margin: 0.25rem 0; color: #856404;",
                    "{notification}"
                }
            }
        }
    }
}

fn status_color(status: &ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Connected => "#2d5016",
        ConnectionStatus::Connecting => "#c4a000",
        ConnectionStatus::Disconnected => "#888",
        ConnectionStatus::Error(_) => "#cc0000",
    }
}

fn nav_button_style(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "background: #2d5016; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-weight: bold;"
    } else {
        "background: transparent; color: #2d5016; border: 1px solid #2d5016; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;"
    }
}
