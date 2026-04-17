use chrono::Utc;
use dioxus::prelude::*;
use harvest_common::listing::{Listing, ListingId, ListingKind, PriceInfo};

#[component]
pub fn ListingForm(seller_fingerprint: String, on_submit: EventHandler<Listing>) -> Element {
    let mut title = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut kind = use_signal(|| ListingKind::Sale);
    let mut price_amount = use_signal(String::new);
    let mut price_currency = use_signal(|| "BTC".to_string());

    let fp = seller_fingerprint.clone();

    rsx! {
        div { class: "card",
            h3 { "New Listing" }

            div { class: "form-group",
                label { class: "form-label", "Title" }
                input {
                    class: "form-input",
                    r#type: "text",
                    placeholder: "What are you offering?",
                    value: "{title}",
                    oninput: move |e| title.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Description" }
                textarea {
                    class: "form-textarea",
                    placeholder: "Describe your item or service...",
                    value: "{description}",
                    oninput: move |e| description.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Type" }
                select {
                    class: "form-select",
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
                div { class: "form-group form-row",
                    div {
                        label { class: "form-label", "Price" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "0.001",
                            value: "{price_amount}",
                            oninput: move |e| price_amount.set(e.value()),
                        }
                    }
                    div { class: "form-narrow",
                        label { class: "form-label", "Currency" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "BTC",
                            value: "{price_currency}",
                            oninput: move |e| price_currency.set(e.value()),
                        }
                    }
                }
            }

            button {
                class: "btn btn-primary",
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
