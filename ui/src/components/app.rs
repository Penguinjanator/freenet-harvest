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

    // Connect to gateway and spawn response handler loop
    #[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
    {
        use futures::StreamExt;

        use_effect(|| {
            wasm_bindgen_futures::spawn_local(async {
                match crate::gateway::connect().await {
                    Ok(mut rx) => {
                        dioxus::logger::tracing::info!("Connected -- starting response loop");

                        // Process responses until the connection drops
                        while let Some(response) = rx.next().await {
                            crate::gateway::response_handler::handle_response(response);
                        }

                        dioxus::logger::tracing::warn!("Response loop ended (connection lost)");
                        *CONNECTION_STATUS.write() = ConnectionStatus::Disconnected;
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!("Failed to connect: {}", e);
                        *CONNECTION_STATUS.write() = ConnectionStatus::Error(e);
                    }
                }
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
