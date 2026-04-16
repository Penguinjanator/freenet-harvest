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

    // Attempt to connect on first render (only in WASM, skipped in no-sync mode)
    #[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
    {
        use_effect(|| {
            wasm_bindgen_futures::spawn_local(async {
                match crate::gateway::connect().await {
                    Ok(_rx) => {
                        dioxus::logger::tracing::info!("Connected to Freenet gateway");
                        // TODO: spawn response handler loop with rx
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!("Failed to connect: {}", e);
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

            // Main content
            match current_route() {
                Route::Browse => rsx! { StoreView {} },
                Route::MyStore => rsx! { MyStore {} },
                Route::Reputation => rsx! { ReputationView {} },
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
