use dioxus::prelude::*;
use harvest_common::feedback::FeedbackCategory;
use harvest_common::reputation::FeedbackEntry;

use crate::gateway::APP_STATE;

#[component]
pub fn ReputationView() -> Element {
    let app_state = APP_STATE.read();

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

            div { class: "info-box",
                p {
                    "Only negative feedback exists. Positive feedback would be meaningless "
                    "since sellers could fake it via blind signatures. A clean record with an "
                    "old, high-tier ghostkey is the best possible reputation."
                }
            }

            if all_feedback.is_empty() {
                p { class: "text-muted text-italic",
                    "No feedback entries loaded. Browse a store to see its reputation."
                }
            } else {
                p { class: "section-count",
                    "{all_feedback.len()} negative feedback entry/entries"
                }
                for (entry, store_name) in &all_feedback {
                    FeedbackCard {
                        entry: (*entry).clone(),
                        store_name: store_name.map(String::from),
                    }
                }
            }
        }
    }
}

#[component]
fn FeedbackCard(entry: FeedbackEntry, store_name: Option<String>) -> Element {
    rsx! {
        div { class: "feedback-card",
            div { class: "feedback-header",
                span { class: "feedback-category",
                    "{category_label(&entry.category)}"
                }
                {
                    let ts = entry.submitted_at.format("%Y-%m-%d %H:%M UTC").to_string();
                    rsx! { span { class: "feedback-time", "{ts}" } }
                }
            }
            if !entry.comment.is_empty() {
                p { class: "feedback-comment", "{entry.comment}" }
            }
            if let Some(ref name) = store_name {
                p { class: "feedback-store", "Store: {name}" }
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
