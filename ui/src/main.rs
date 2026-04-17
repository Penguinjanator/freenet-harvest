// Gateway module items are only used in WASM builds; native cargo check
// reports them as unused, which is expected.
#![allow(dead_code, unused_imports)]

mod components;
mod document_title;
mod gateway;
mod messaging;
mod state;

fn main() {
    dioxus::logger::initialize_default();
    dioxus::launch(components::App);
}
