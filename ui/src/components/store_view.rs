use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingKind, PriceInfo};

use crate::gateway::APP_STATE;

/// Browse a store's listings.
#[component]
pub fn StoreView() -> Element {
    let app_state = APP_STATE.read();

    // Find the first browsing store (for now -- later we'll support URL-based store selection)
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
                        p {
                            style: "color: #666;",
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
            // Store header
            div {
                style: "background: #f5f5f0; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem;",
                div {
                    style: "display: flex; justify-content: space-between; align-items: flex-start;",
                    div {
                        h3 { style: "margin: 0 0 0.5rem 0;", "{info.store_name}" }
                        p { style: "color: #555; margin: 0;", "{info.description}" }
                    }
                    div {
                        style: "text-align: right;",
                        // Reputation summary
                        if store.feedback.is_empty() {
                            span {
                                style: "color: #2d5016; font-weight: bold;",
                                "Clean record"
                            }
                        } else {
                            span {
                                style: "color: #cc0000; font-weight: bold;",
                                "{store.feedback.len()} negative"
                            }
                        }
                        br {}
                        span {
                            style: "font-size: 0.8rem; color: #888;",
                            "Seller: {truncate_fingerprint(&info.seller_fingerprint)}"
                        }
                    }
                }
                if !info.payment_instructions.is_empty() {
                    p {
                        style: "margin: 0.75rem 0 0 0; font-size: 0.85rem; color: #666;",
                        strong { "Payment: " }
                        "{info.payment_instructions}"
                    }
                }
            }

            // Listings
            if store.listings.is_empty() {
                p { style: "color: #888; font-style: italic;", "No listings yet." }
            } else {
                h3 { "{store.listings.len()} listing(s)" }
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
        div {
            style: "border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;",
            div {
                style: "display: flex; justify-content: space-between; align-items: center;",
                h4 { style: "margin: 0;", "{l.title}" }
                span {
                    style: "background: {kind_color(&l.kind)}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;",
                    "{kind_label(&l.kind)}"
                }
            }
            p { style: "color: #555; margin: 0.5rem 0;", "{l.description}" }
            div {
                style: "display: flex; justify-content: space-between; align-items: center;",
                if let Some(ref price) = l.price {
                    span {
                        style: "font-weight: bold; color: #2d5016;",
                        "{price.amount} {price.currency}"
                    }
                }
                {
                    let date = l.created_at.format("%Y-%m-%d").to_string();
                    rsx! {
                        span {
                            style: "font-size: 0.75rem; color: #999;",
                            "Listed {date}"
                        }
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

fn kind_color(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "#2d5016",
        ListingKind::Gift => "#6b4c9a",
        ListingKind::Request => "#8b6914",
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
                style: "margin-top: 1rem;",
                h3 { "Example Listings" }
                for (title, desc, kind, price) in examples {
                    div {
                        style: "border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;",
                        div {
                            style: "display: flex; justify-content: space-between; align-items: center;",
                            h4 { style: "margin: 0;", "{title}" }
                            span {
                                style: "background: {kind_color(&kind)}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;",
                                "{kind_label(&kind)}"
                            }
                        }
                        p { style: "color: #555; margin: 0.5rem 0;", "{desc}" }
                        if let Some(ref p) = price {
                            p {
                                style: "font-weight: bold; color: #2d5016;",
                                "{p.amount} {p.currency}"
                            }
                        }
                    }
                }
            }
        }
    }
}
