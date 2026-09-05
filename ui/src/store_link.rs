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

/// bs58 of 32 bytes is 43 or 44 characters. Anything longer cannot be a
/// contract id, and refusing it before decoding keeps a pathological link
/// from spending quadratic time in `bs58::decode`.
const MAX_ENCODED_LEN: usize = 44;

/// How long a linked store has to arrive before the user is told it could not
/// be opened. `get_contract` reports only failures to *send* the GET; one that
/// errors in the network, or that names a contract nobody holds, produces no
/// response at all, so a timeout is the only thing that ever ends the Browse
/// tab's "Loading store..." message.
///
/// Shared with `state::subscribe_to_own_store`, which needs the same
/// deadline for the same reason: a store whose state never arrives has to
/// become a known fact eventually, or "still loading" and "nothing there"
/// stay indistinguishable forever.
#[cfg(target_arch = "wasm32")]
pub(crate) const LINK_LOAD_TIMEOUT_MS: u32 = 30_000;

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
    if encoded.len() > MAX_ENCODED_LEN {
        return None;
    }
    let bytes: [u8; 32] = bs58::decode(encoded).into_vec().ok()?.try_into().ok()?;
    Some(ContractInstanceId::new(bytes))
}

/// Build the link a seller shares for one of their stores: the page they are
/// on, with the store id in the fragment.
///
/// Everything from the first `#` or `?` onwards is dropped. The query string
/// in particular must go: Harvest runs inside the shell's sandboxed iframe,
/// whose src carries `__sandbox=1`, so `window.location.href` inside the app
/// always has it. That parameter is interpreted by Freenet's web server --
/// it makes the gateway serve the raw contract HTML with no shell, no bridge
/// and no websocket -- so a shared link that kept it would load a dead page
/// for the buyer. freenet-core strips it from its own redirects for the same
/// reason. Nothing else the gateway puts in the query string belongs in a
/// link handed to someone else either (`authToken` is the obvious one), and
/// the store id itself travels in the fragment.
pub fn store_link(page_url: &str, store: &ContractInstanceId) -> String {
    let base = page_url.split(['#', '?']).next().unwrap_or(page_url);
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

/// The label shown beside a store's share link.
///
/// A seller with more than one store gets one link per store, and the links
/// are 44 random-looking characters apart -- without a label there is no way
/// to tell which is which. Prefer the store's own name; fall back to a short
/// prefix of its contract id, which is what the seller sees elsewhere in the
/// UI. The fallback is not a rare path today: a store's state may not have
/// arrived yet, and stores currently carry an empty name.
pub fn store_label(store_contract_id: &[u8], store_name: Option<&str>) -> String {
    match store_name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => name.to_string(),
        None => {
            let encoded = bs58::encode(store_contract_id).into_string();
            let prefix: String = encoded.chars().take(8).collect();
            format!("Store {prefix}...")
        }
    }
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
        let contract_id = store_id.as_bytes().to_vec();
        if let Err(e) = crate::gateway::get_contract(&store_id, true).await {
            crate::gateway::APP_STATE.write().note_store_link_failed(
                &contract_id,
                &format!("Couldn't open that store link: {e}"),
            );
            return;
        }

        // The GET is out. Nothing will report back if it dead-ends -- a
        // contract nobody holds simply never answers -- so give it a
        // deadline and say so if it passes.
        gloo_timers::future::TimeoutFuture::new(LINK_LOAD_TIMEOUT_MS).await;
        crate::gateway::APP_STATE.write().note_store_link_failed(
            &contract_id,
            "That store didn't load. The link may be wrong, or the store may \
             not be reachable right now.",
        );
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
    fn a_store_is_labelled_by_its_name_when_it_has_one() {
        assert_eq!(store_label(&[1u8; 32], Some("Bean Shop")), "Bean Shop");
    }

    /// Store names are empty today, so this is the path the seller actually
    /// sees -- it has to identify the store, not read as a bug.
    #[test]
    fn a_nameless_store_is_labelled_by_its_id() {
        let label = store_label(&[1u8; 32], None);
        let encoded = ContractInstanceId::new([1u8; 32]).encode();
        assert_eq!(label, format!("Store {}...", &encoded[..8]));

        // Whitespace is not a name either.
        assert_eq!(store_label(&[1u8; 32], Some("   ")), label);
        assert_eq!(store_label(&[1u8; 32], Some("")), label);
    }

    /// Two stores must not get the same label, or labelling them was
    /// pointless.
    #[test]
    fn two_nameless_stores_get_different_labels() {
        assert_ne!(store_label(&[1u8; 32], None), store_label(&[2u8; 32], None));
    }

    /// A link long enough to be a denial of service is refused before it
    /// reaches `bs58::decode`, which is quadratic in the input length.
    #[test]
    fn rejects_an_absurdly_long_id_without_decoding_it() {
        let padding = "1".repeat(100_000);
        assert!(parse_store_id(&format!("#store={padding}")).is_none());
        // The longest id that is still worth decoding is accepted.
        let store = id(1);
        assert!(store.encode().len() <= MAX_ENCODED_LEN);
        assert_eq!(parse_store_id(&format!("#store={store}")), Some(store));
    }

    #[test]
    fn a_shared_link_parses_back_to_the_same_store() {
        let store = id(11);
        let link = store_link("http://127.0.0.1:50509/v1/contract/web/abc/", &store);
        let fragment = link.split_once('#').expect("link should have a fragment").1;
        assert_eq!(parse_store_id(fragment), Some(store));
    }

    /// The query string must not survive into a shared link: inside the
    /// shell's iframe it carries `__sandbox=1`, which makes the gateway serve
    /// the buyer a shell-less page that can never connect. See `store_link`.
    #[test]
    fn building_a_link_replaces_the_fragment_and_drops_the_query() {
        let store = id(2);
        let link = store_link("http://host/app/?__sandbox=1#store=stale", &store);
        assert_eq!(link, format!("http://host/app/#store={store}"));

        // A credential is not in the shell's iframe URL today, but if one
        // ever were, sharing it would be worse than a broken link.
        let link = store_link("http://host/app/?authToken=abc", &store);
        assert_eq!(link, format!("http://host/app/#store={store}"));
    }
}
