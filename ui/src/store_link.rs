//! Opening a store from a shared link, and building the link to share.
//!
//! Harvest has no discovery: a buyer reaches a seller's store because the
//! seller sent them a link (docs/design.md, "No built-in discovery"). The link
//! is the page's own URL with the store's contract id attached.
//!
//! # Why the fragment
//!
//! The canonical form puts the id in the fragment (`#store=<bs58 id>`) rather
//! than in the query string, for two reasons:
//!
//! * A fragment is never sent to the server. The gateway therefore never
//!   learns which store a visitor opened, and the id never lands in an access
//!   log. Harvest is careful about exactly this class of leak everywhere else
//!   (see docs/design/privacy-analysis.html), and which store you are looking
//!   at is the one part of a browsing session that a query string would put in
//!   plain view.
//! * Freenet's web server normalizes webapp URLs -- a missing trailing slash
//!   is redirected. Browsers carry a fragment across a redirect on their own;
//!   a query string survives only if the server deliberately re-attaches it.
//!
//! A query string is still *accepted* on the way in, because a hand-written or
//! hand-edited `?store=...` is an easy mistake to make and there's no reason
//! to punish it.

use freenet_stdlib::prelude::ContractInstanceId;

/// The parameter naming the store to open.
const STORE_PARAM: &str = "store";

/// Look up `name` in an `a=1&b=2` parameter string, tolerating the leading
/// `#` or `?` that `location.hash()` / `location.search()` include.
fn param<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.trim_start_matches(['#', '?'])
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
}

/// Parse the store contract id out of a URL fragment or query string.
///
/// Returns `None` for anything that isn't a well-formed 32-byte bs58 id.
/// The explicit length check is not redundant with `ContractInstanceId`'s own
/// `FromStr`: that decodes into a fixed 32-byte buffer and discards the
/// written length, so a truncated id decodes to a *different*, zero-padded
/// contract id instead of failing. A typo in a shared link should open
/// nothing, not something else.
pub fn parse_store_id(raw: &str) -> Option<ContractInstanceId> {
    let encoded = param(raw, STORE_PARAM)?;
    let bytes: [u8; 32] = bs58::decode(encoded).into_vec().ok()?.try_into().ok()?;
    Some(ContractInstanceId::new(bytes))
}

/// Build the link a seller shares for one of their stores: the page they are
/// on, with the store id in the fragment.
///
/// Any existing fragment is replaced; an existing query string is kept, since
/// the gateway may have put it there.
pub fn store_link(page_url: &str, store: &ContractInstanceId) -> String {
    let base = page_url.split('#').next().unwrap_or(page_url);
    format!("{base}#{STORE_PARAM}={store}")
}

/// The link to share for a store, given its raw contract id, or `None` if the
/// id is malformed or there's no page URL to build on (native builds).
pub fn share_link(store_contract_id: &[u8]) -> Option<String> {
    let bytes: [u8; 32] = store_contract_id.try_into().ok()?;
    Some(store_link(
        &current_page_url()?,
        &ContractInstanceId::new(bytes),
    ))
}

#[cfg(target_arch = "wasm32")]
fn current_page_url() -> Option<String> {
    web_sys::window()?.location().href().ok()
}

#[cfg(not(target_arch = "wasm32"))]
fn current_page_url() -> Option<String> {
    None
}

/// If this page was opened with a store link, start browsing that store.
///
/// Called once the websocket is up. It deliberately does not wait for the
/// delegates: fetching and subscribing to a store contract needs nothing from
/// them, and a buyer following a link has no reason to hold a ghostkey.
#[cfg(target_arch = "wasm32")]
pub fn open_store_from_url() {
    use dioxus::prelude::WritableExt;

    let Some(location) = web_sys::window().map(|window| window.location()) else {
        return;
    };
    let hash = location.hash().unwrap_or_default();
    let search = location.search().unwrap_or_default();
    let Some(store_id) = parse_store_id(&hash).or_else(|| parse_store_id(&search)) else {
        return;
    };

    dioxus::logger::tracing::info!("Opening store from link: {store_id}");
    crate::gateway::APP_STATE
        .write()
        .begin_browsing(store_id.as_bytes().to_vec());

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::get_contract(&store_id, true).await {
            dioxus::logger::tracing::error!("Failed to open store from link: {e}");
            crate::gateway::APP_STATE
                .write()
                .notifications
                .push(format!("Couldn't open that store link: {e}"));
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn open_store_from_url() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ContractInstanceId {
        ContractInstanceId::new([byte; 32])
    }

    #[test]
    fn parses_a_fragment_link() {
        let store = id(7);
        let parsed = parse_store_id(&format!("#store={store}")).expect("should parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn parses_a_query_string_link() {
        let store = id(3);
        let parsed = parse_store_id(&format!("?store={store}")).expect("should parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn finds_the_store_among_other_parameters() {
        let store = id(9);
        let parsed =
            parse_store_id(&format!("#tab=browse&store={store}&x=1")).expect("should parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn ignores_a_url_with_no_store_parameter() {
        assert!(parse_store_id("").is_none());
        assert!(parse_store_id("#").is_none());
        assert!(parse_store_id("#tab=browse").is_none());
        assert!(parse_store_id("#store").is_none());
    }

    #[test]
    fn rejects_an_id_that_is_not_bs58() {
        assert!(parse_store_id("#store=not a contract id").is_none());
        assert!(parse_store_id("#store=0OIl").is_none());
    }

    /// A truncated id must fail rather than decode to a zero-padded
    /// *different* contract -- see `parse_store_id`.
    #[test]
    fn rejects_an_id_of_the_wrong_length() {
        let store = id(5).encode();
        assert!(parse_store_id(&format!("#store={}", &store[..store.len() - 2])).is_none());
        assert!(parse_store_id(&format!("#store={store}{store}")).is_none());
    }

    #[test]
    fn a_shared_link_parses_back_to_the_same_store() {
        let store = id(11);
        let link = store_link("http://127.0.0.1:50509/v1/contract/web/abc/", &store);
        let fragment = link.split_once('#').expect("link should have a fragment").1;
        assert_eq!(parse_store_id(fragment), Some(store));
    }

    #[test]
    fn building_a_link_replaces_any_existing_fragment_and_keeps_the_query() {
        let store = id(2);
        let link = store_link("http://host/app/?authToken=abc#store=stale", &store);
        assert_eq!(
            link,
            format!("http://host/app/?authToken=abc#store={store}")
        );
    }
}
