use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingKind, PriceInfo};

use crate::gateway::APP_STATE;

#[component]
pub fn StoreView() -> Element {
    let app_state = APP_STATE.read();
    let store_entry = app_state.browsing_stores.values().next();

    rsx! {
        div {
            h2 { "Store" }

            match store_entry {
                Some(store) if store.info.is_some() => {
                    rsx! { LoadedStore { store: store.clone() } }
                }
                _ => {
                    rsx! {
                        p { class: "text-muted text-italic",
                            "No store loaded. Share a store link to browse listings."
                        }
                        {example_listings_section()}
                    }
                }
            }
        }
    }
}

#[component]
fn LoadedStore(store: crate::state::BrowsingStore) -> Element {
    let info = store.info.as_ref().unwrap();

    rsx! {
        div {
            div { class: "store-header",
                div { class: "store-header-inner",
                    div {
                        h3 { class: "store-name", "{info.store_name}" }
                        p { class: "store-desc", "{info.description}" }
                    }
                    div { class: "store-meta",
                        if store.feedback.is_empty() {
                            span { class: "reputation-clean", "Clean record" }
                        } else {
                            span { class: "reputation-negative",
                                "{store.feedback.len()} negative"
                            }
                        }
                        p { class: "seller-id",
                            "Seller: {truncate_fingerprint(&info.seller_fingerprint)}"
                        }
                    }
                }
                if !info.payment_instructions.is_empty() {
                    p { class: "payment-info",
                        strong { "Payment: " }
                        "{info.payment_instructions}"
                    }
                }
            }

            if store.listings.is_empty() {
                p { class: "text-muted text-italic", "No listings yet." }
            } else {
                p { class: "section-count", "{store.listings.len()} listing(s)" }
                for listing in &store.listings {
                    ListingCard { listing: listing.clone() }
                }
            }
        }
    }
}

#[component]
fn ListingCard(listing: AuthorizedListing) -> Element {
    let l = &listing.listing;

    rsx! {
        div { class: "listing-card",
            div { class: "listing-header",
                h4 { "{l.title}" }
                span { class: "badge {kind_badge_class(&l.kind)}",
                    "{kind_label(&l.kind)}"
                }
            }
            p { class: "listing-desc", "{l.description}" }
            div { class: "listing-footer",
                if let Some(ref price) = l.price {
                    span { class: "listing-price", "{price.amount} {price.currency}" }
                }
                {
                    let date = l.created_at.format("%Y-%m-%d").to_string();
                    rsx! {
                        span { class: "listing-date", "Listed {date}" }
                    }
                }
            }
        }
    }
}

fn truncate_fingerprint(fp: &str) -> String {
    if fp.len() > 12 {
        format!("{}...", &fp[..12])
    } else {
        fp.to_string()
    }
}

fn kind_badge_class(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "badge-sale",
        ListingKind::Gift => "badge-gift",
        ListingKind::Request => "badge-request",
    }
}

fn kind_label(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "Sale",
        ListingKind::Gift => "Gift",
        ListingKind::Request => "Request",
    }
}

fn example_listings_section() -> Element {
    #[cfg(not(feature = "example-data"))]
    {
        rsx! {}
    }

    #[cfg(feature = "example-data")]
    {
        let examples = vec![
            (
                "Handmade Ceramic Mug",
                "Beautiful hand-thrown stoneware mug, holds 12oz.",
                ListingKind::Sale,
                Some(PriceInfo {
                    amount: "0.001".into(),
                    currency: "BTC".into(),
                }),
            ),
            (
                "Sourdough Starter",
                "Active 3-year-old starter, ready to bake.",
                ListingKind::Gift,
                None,
            ),
            (
                "Looking for: Bicycle Parts",
                "Need a rear derailleur, Shimano compatible.",
                ListingKind::Request,
                None,
            ),
        ];

        rsx! {
            div {
                h3 { "Example Listings" }
                for (title, desc, kind, price) in examples {
                    div { class: "listing-card",
                        div { class: "listing-header",
                            h4 { "{title}" }
                            span { class: "badge {kind_badge_class(&kind)}", "{kind_label(&kind)}" }
                        }
                        p { class: "listing-desc", "{desc}" }
                        if let Some(ref p) = price {
                            p { class: "listing-price", "{p.amount} {p.currency}" }
                        }
                    }
                }
            }
        }
    }
}
