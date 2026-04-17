use chrono::Utc;
use dioxus::prelude::*;
use harvest_common::listing::{Listing, ListingId, ListingKind, PriceInfo};

/// Form for creating a new listing.
#[component]
pub fn ListingForm(seller_fingerprint: String, on_submit: EventHandler<Listing>) -> Element {
    let mut title = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut kind = use_signal(|| ListingKind::Sale);
    let mut price_amount = use_signal(String::new);
    let mut price_currency = use_signal(|| "BTC".to_string());

    let fp = seller_fingerprint.clone();

    rsx! {
        div {
            style: "border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; margin-top: 1rem;",
            h3 { "New Listing" }

            div { style: "margin-bottom: 1rem;",
                label { style: "display: block; font-weight: bold; margin-bottom: 0.25rem;", "Title" }
                input {
                    style: "width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;",
                    r#type: "text",
                    placeholder: "What are you offering?",
                    value: "{title}",
                    oninput: move |e| title.set(e.value()),
                }
            }

            div { style: "margin-bottom: 1rem;",
                label { style: "display: block; font-weight: bold; margin-bottom: 0.25rem;", "Description" }
                textarea {
                    style: "width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; min-height: 80px; box-sizing: border-box;",
                    placeholder: "Describe your item or service...",
                    value: "{description}",
                    oninput: move |e| description.set(e.value()),
                }
            }

            div { style: "margin-bottom: 1rem;",
                label { style: "display: block; font-weight: bold; margin-bottom: 0.25rem;", "Type" }
                select {
                    style: "padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px;",
                    value: kind_value(&kind()),
                    onchange: move |e| {
                        kind.set(match e.value().as_str() {
                            "gift" => ListingKind::Gift,
                            "request" => ListingKind::Request,
                            _ => ListingKind::Sale,
                        });
                    },
                    option { value: "sale", "For Sale" }
                    option { value: "gift", "Gift / Free" }
                    option { value: "request", "Request / Wanted" }
                }
            }

            if matches!(kind(), ListingKind::Sale) {
                div { style: "margin-bottom: 1rem; display: flex; gap: 0.5rem;",
                    div { style: "flex: 1;",
                        label { style: "display: block; font-weight: bold; margin-bottom: 0.25rem;", "Price" }
                        input {
                            style: "width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;",
                            r#type: "text",
                            placeholder: "0.001",
                            value: "{price_amount}",
                            oninput: move |e| price_amount.set(e.value()),
                        }
                    }
                    div { style: "width: 100px;",
                        label { style: "display: block; font-weight: bold; margin-bottom: 0.25rem;", "Currency" }
                        input {
                            style: "width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;",
                            r#type: "text",
                            placeholder: "BTC",
                            value: "{price_currency}",
                            oninput: move |e| price_currency.set(e.value()),
                        }
                    }
                }
            }

            button {
                style: "background: #2d5016; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem;",
                disabled: title().trim().is_empty(),
                onclick: {
                    let fp = fp.clone();
                    move |_| {
                        let now = Utc::now();
                        let listing_title = title().trim().to_string();
                        let listing = Listing {
                            id: ListingId::new(&fp, &now, &listing_title),
                            title: listing_title,
                            description: description().trim().to_string(),
                            kind: kind(),
                            price: if matches!(kind(), ListingKind::Sale)
                                && !price_amount().trim().is_empty()
                            {
                                Some(PriceInfo {
                                    amount: price_amount().trim().to_string(),
                                    currency: price_currency().trim().to_string(),
                                })
                            } else {
                                None
                            },
                            created_at: now,
                        };

                        // Clear form
                        title.set(String::new());
                        description.set(String::new());
                        price_amount.set(String::new());

                        on_submit.call(listing);
                    }
                },
                "Create Listing"
            }
        }
    }
}

fn kind_value(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "sale",
        ListingKind::Gift => "gift",
        ListingKind::Request => "request",
    }
}
