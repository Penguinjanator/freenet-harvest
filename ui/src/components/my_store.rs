use dioxus::prelude::*;

/// Manage your own store: create listings, view your reputation.
#[component]
pub fn MyStore() -> Element {
    rsx! {
        div {
            h2 { "My Store" }
            p {
                style: "color: #666;",
                "Create and manage your store. You'll need a ghostkey identity to get started."
            }

            div {
                style: "border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; margin-top: 1rem; text-align: center;",
                p {
                    style: "font-size: 1.1rem;",
                    "To create a store, you need:"
                }
                ol {
                    style: "text-align: left; max-width: 400px; margin: 1rem auto;",
                    li { "A ghostkey identity (via Freenet donation)" }
                    li { "An RSA keypair for feedback tokens (generated automatically)" }
                }
                button {
                    style: "background: #2d5016; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem;",
                    disabled: true,
                    "Create Store (coming soon)"
                }
            }
        }
    }
}
