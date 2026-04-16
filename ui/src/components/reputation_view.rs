use dioxus::prelude::*;

/// View a seller's reputation (negative feedback history).
#[component]
pub fn ReputationView() -> Element {
    rsx! {
        div {
            h2 { "Reputation" }
            p {
                style: "color: #666;",
                "View a seller's reputation. A clean record (zero negatives, old ghostkey, high donation tier) is the best possible reputation."
            }

            div {
                style: "border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; margin-top: 1rem;",
                h3 { "How Reputation Works" }
                ul {
                    style: "line-height: 1.8;",
                    li { "Only negative feedback exists. Positive feedback would be meaningless (sellers could fake it)." }
                    li { "Feedback is anonymous: blind signatures prevent sellers from identifying who left feedback." }
                    li { "Each feedback entry is cryptographically verified against the seller's RSA public key." }
                    li { "A seller's ghostkey donation tier signals how much they have at stake." }
                }
            }
        }
    }
}
