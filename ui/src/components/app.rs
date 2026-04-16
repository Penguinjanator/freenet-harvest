use dioxus::prelude::*;

use super::my_store::MyStore;
use super::reputation_view::ReputationView;
use super::store_view::StoreView;

/// Top-level navigation route.
#[derive(Clone, PartialEq)]
enum Route {
    /// Browse a store (default landing page).
    Browse,
    /// Manage your own store.
    MyStore,
    /// View a seller's reputation.
    Reputation,
}

#[component]
pub fn App() -> Element {
    let mut current_route = use_signal(|| Route::Browse);

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
                    style: "display: flex; gap: 1rem;",
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

fn nav_button_style(current: &Route, target: &Route) -> &'static str {
    if current == target {
        "background: #2d5016; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-weight: bold;"
    } else {
        "background: transparent; color: #2d5016; border: 1px solid #2d5016; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;"
    }
}
