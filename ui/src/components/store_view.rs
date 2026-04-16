use dioxus::prelude::*;

/// Browse a store's listings.
#[component]
pub fn StoreView() -> Element {
    rsx! {
        div {
            h2 { "Store" }
            p {
                style: "color: #666;",
                "No store loaded. Share a store link to browse listings."
            }

            {example_listings_section()}
        }
    }
}

fn example_listings_section() -> Element {
    #[cfg(not(feature = "example-data"))]
    {
        rsx! {}
    }

    #[cfg(feature = "example-data")]
    {
        use harvest_common::listing::{ListingKind, PriceInfo};

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
                            h4 {
                                style: "margin: 0;",
                                "{title}"
                            }
                            span {
                                style: "background: {kind_color(&kind)}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;",
                                "{kind_label(&kind)}"
                            }
                        }
                        p {
                            style: "color: #555; margin: 0.5rem 0;",
                            "{desc}"
                        }
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

#[cfg(feature = "example-data")]
fn kind_color(kind: &harvest_common::listing::ListingKind) -> &'static str {
    match kind {
        harvest_common::listing::ListingKind::Sale => "#2d5016",
        harvest_common::listing::ListingKind::Gift => "#6b4c9a",
        harvest_common::listing::ListingKind::Request => "#8b6914",
    }
}

#[cfg(feature = "example-data")]
fn kind_label(kind: &harvest_common::listing::ListingKind) -> &'static str {
    match kind {
        harvest_common::listing::ListingKind::Sale => "Sale",
        harvest_common::listing::ListingKind::Gift => "Gift",
        harvest_common::listing::ListingKind::Request => "Request",
    }
}
