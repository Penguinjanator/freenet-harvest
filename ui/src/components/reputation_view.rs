use dioxus::prelude::*;
use harvest_common::feedback::FeedbackCategory;
use harvest_common::reputation::FeedbackEntry;

use crate::gateway::APP_STATE;

/// View a seller's reputation (negative feedback history).
#[component]
pub fn ReputationView() -> Element {
    let app_state = APP_STATE.read();

    // Collect all feedback from browsed stores
    let all_feedback: Vec<(&FeedbackEntry, Option<&str>)> = app_state
        .browsing_stores
        .values()
        .flat_map(|store| {
            let store_name = store.info.as_ref().map(|i| i.store_name.as_str());
            store.feedback.iter().map(move |f| (f, store_name))
        })
        .collect();

    rsx! {
        div {
            h2 { "Reputation" }

            // Explainer
            div {
                style: "background: #f5f5f0; border-radius: 8px; padding: 1rem; margin-bottom: 1rem;",
                p {
                    style: "margin: 0; color: #555;",
                    "Only negative feedback exists. Positive feedback would be meaningless \
                     since sellers could fake it via blind signatures. A clean record with an \
                     old, high-tier ghostkey is the best possible reputation."
                }
            }

            if all_feedback.is_empty() {
                p {
                    style: "color: #666; font-style: italic;",
                    "No feedback entries loaded. Browse a store to see its reputation."
                }
            } else {
                h3 { "{all_feedback.len()} negative feedback entry/entries" }
                for (entry, store_name) in &all_feedback {
                    FeedbackCard { entry: (*entry).clone(), store_name: store_name.map(String::from) }
                }
            }
        }
    }
}

#[component]
fn FeedbackCard(entry: FeedbackEntry, store_name: Option<String>) -> Element {
    rsx! {
        div {
            style: "border: 1px solid #e0c0c0; border-left: 4px solid #cc0000; border-radius: 4px; padding: 1rem; margin-bottom: 0.75rem;",
            div {
                style: "display: flex; justify-content: space-between; align-items: center;",
                span {
                    style: "font-weight: bold; color: #cc0000;",
                    "{category_label(&entry.category)}"
                }
                {
                    let ts = entry.submitted_at.format("%Y-%m-%d %H:%M UTC").to_string();
                    rsx! {
                        span {
                            style: "font-size: 0.75rem; color: #999;",
                            "{ts}"
                        }
                    }
                }
            }
            if !entry.comment.is_empty() {
                p { style: "margin: 0.5rem 0 0 0; color: #333;", "{entry.comment}" }
            }
            if let Some(ref name) = store_name {
                p {
                    style: "margin: 0.25rem 0 0 0; font-size: 0.8rem; color: #888;",
                    "Store: {name}"
                }
            }
        }
    }
}

fn category_label(category: &FeedbackCategory) -> &str {
    match category {
        FeedbackCategory::NonDelivery => "Non-delivery",
        FeedbackCategory::Misrepresented => "Misrepresented",
        FeedbackCategory::Counterfeit => "Counterfeit",
        FeedbackCategory::Other(s) => s.as_str(),
    }
}
