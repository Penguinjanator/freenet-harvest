use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingKind, PriceInfo};

use crate::gateway::APP_STATE;

#[component]
pub fn StoreView() -> Element {
    let app_state = APP_STATE.read();

    // `AppState::displayed_store` owns this choice, so the document title
    // (see `components::App`) cannot answer it differently.
    let store_entry = app_state
        .displayed_store()
        .map(|(id, store)| (id.clone(), store.clone()));

    // A link was followed but the store's state hasn't come back yet. Once
    // `store_link_error` is set the wait is over and the message changes --
    // otherwise this reads "Loading store..." for the rest of the session.
    let link_error = app_state.store_link_error.clone();
    let awaiting_link =
        store_entry.is_none() && app_state.active_store_id.is_some() && link_error.is_none();

    rsx! {
        div {
            h2 { "Store" }

            match store_entry {
                Some((contract_id, store)) => {
                    rsx! { LoadedStore { store: store, contract_id: contract_id } }
                }
                None if awaiting_link => {
                    rsx! {
                        p { class: "text-muted text-italic", "Loading store..." }
                    }
                }
                None if link_error.is_some() => {
                    let message = link_error.clone().unwrap_or_default();
                    rsx! {
                        p { class: "text-warning", "{message}" }
                    }
                }
                None => {
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
fn LoadedStore(store: crate::state::BrowsingStore, contract_id: Vec<u8>) -> Element {
    let info = store.info.as_ref().unwrap();
    let mut show_messages = use_signal(|| false);

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
                        p {
                            class: if store.certificate_status.is_verified() { "cert-verified" } else { "cert-unverified" },
                            "{store.certificate_status.label()}"
                        }
                    }
                }

                // The verdict, spelled out. A badge alone tells a buyer that
                // something is wrong without telling them what it costs them,
                // and this is the one line on the page that decides whether
                // the seller has anything at stake.
                if !store.certificate_status.is_verified() {
                    p { class: "text-warning",
                        "{certificate_warning(&store.certificate_status)}"
                    }
                }
                if !info.payment_instructions.is_empty() {
                    p { class: "payment-info",
                        strong { "Payment: " }
                        "{info.payment_instructions}"
                    }
                }
            }

            // Contact seller button
            div {
                style: "margin-bottom: 1.5rem;",
                button {
                    class: if show_messages() { "btn btn-sm btn-outline" } else { "btn btn-primary" },
                    onclick: move |_| show_messages.toggle(),
                    if show_messages() { "Hide Messages" } else { "Contact Seller" }
                }
            }

            if show_messages() {
                super::message_view::MessageView { store_contract_id: contract_id.clone() }
            }

            if store.listings.is_empty() {
                p { class: "text-muted text-italic", "No listings yet." }
            } else {
                p { class: "section-count", "{store.listings.len()} listing(s)" }
                for listing in &store.listings {
                    ListingCard {
                        listing: listing.clone(),
                        // Only when it adds something. If the store's own
                        // certificate failed, the warning above already
                        // covers everything under it, and repeating it on
                        // every card is the kind of noise that teaches a
                        // reader to skip warnings.
                        certificate_mismatch: store.certificate_status.is_verified()
                            && store.unverified_listings.contains(&listing.listing.id),
                    }
                }
            }

            StoreInvoices { orders: store.orders.clone() }
        }
    }
}

/// The invoices a store has issued, as a buyer sees them.
///
/// They are on the store contract and public, which is not an oversight:
/// decentralized payment verification is impossible unless everyone can see
/// what was owed and where it was to be paid. That is application semantics
/// requiring publication, and quite different from publishing a user's private
/// list of addresses they happen to be interested in -- which Harvest refuses
/// to do anywhere (see `harvest_common::bitcoin_delegate`).
///
/// Every invoice goes through the SAME `OrderCard` the seller's own payments
/// panel uses, so the per-invoice bridge check travels with it. That check is
/// the one a buyer most needs and is easiest to leave out of a second copy:
/// the trusted-bridge set moved onto the order to make rotation possible, so
/// two invoices from one store may name different observers, and an invoice
/// whose "Paid" verdict would rest on a stranger's signature has to say so
/// before the buyer sends anything.
#[component]
fn StoreInvoices(orders: Vec<harvest_common::payment::AuthorizedOrder>) -> Element {
    if orders.is_empty() {
        return rsx! {};
    }
    let mut sorted = orders;
    sorted.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    let bitcoin = crate::gateway::APP_STATE.read().bitcoin.clone();

    rsx! {
        div { style: "margin-top: 24px;",
            h4 { "Invoices" }
            p { class: "text-muted",
                "Pay the address shown on an invoice for the exact amount. Anyone can "
                "check the evidence that settles it, so neither you nor the seller has to "
                "be taken at their word about the payment."
            }
            super::invoice_form::PaymentWatchNote {}
            for order in sorted.iter() {
                super::bitcoin_view::OrderCard {
                    key: "{order.order.id}",
                    order: order.clone(),
                    live: super::bitcoin_view::live_address_for_order(&bitcoin, &order.order),
                }
            }
        }
    }
}

/// What an unverified certificate means for the person reading the page.
///
/// The two cases are genuinely different and must not be collapsed. A store
/// with no certificate is claiming nothing; a store whose certificate fails
/// is claiming a bond it does not have, which is worse than claiming none.
fn certificate_warning(status: &crate::ghostkey_cert::CertificateStatus) -> String {
    use crate::ghostkey_cert::CertificateStatus;
    match status {
        CertificateStatus::Verified => String::new(),
        CertificateStatus::Absent => "This store publishes no ghostkey certificate, so nothing \
             here shows that the seller's identity cost anything to create. They can abandon it \
             and start again for free."
            .to_string(),
        CertificateStatus::Invalid(why) => format!(
            "This store's ghostkey certificate does not check out ({why}). Treat the seller as \
             anonymous: nothing here shows they have staked anything they would lose."
        ),
    }
}

#[component]
fn ListingCard(listing: AuthorizedListing, certificate_mismatch: bool) -> Element {
    let l = &listing.listing;

    rsx! {
        div { class: "listing-card",
            div { class: "listing-header",
                h4 { "{l.title}" }
                span { class: "badge {kind_badge_class(&l.kind)}",
                    "{kind_label(&l.kind)}"
                }
            }
            // The store verified, and this listing did not: it carries a
            // certificate that is not the seller's. Worth saying loudly,
            // precisely because everything around it checks out.
            if certificate_mismatch {
                p { class: "text-warning",
                    "This listing's ghostkey certificate is not this seller's."
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
