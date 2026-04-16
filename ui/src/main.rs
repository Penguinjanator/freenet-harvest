mod components;

fn main() {
    dioxus::logger::initialize_default();
    dioxus::launch(components::App);
}
