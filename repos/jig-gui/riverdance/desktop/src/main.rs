use dioxus::prelude::*;
use ui::{ChatView, RiverdanceLayout};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(DesktopRiverdanceLayout)]
    #[route("/")]
    Chat {},
    #[route("/dms")]
    DirectMessages {},
    #[route("/threads")]
    Threads {},
    #[route("/saved")]
    SavedItems {},
    #[route("/drafts")]
    Drafts {},
    #[route("/notifications")]
    Notifications {},
    #[route("/settings")]
    Settings {},
}

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        // Global app resources
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        Router::<Route> {}
    }
}

#[component]
fn Chat() -> Element {
    rsx! {
        ChatView {}
    }
}

#[component]
fn DirectMessages() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Direct Messages" }
            p { "Your direct message conversations will appear here." }
        }
    }
}

#[component]
fn Threads() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Threads" }
            p { "Your thread conversations will appear here." }
        }
    }
}

#[component]
fn SavedItems() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Saved Items" }
            p { "Messages and items you've saved will appear here." }
        }
    }
}

#[component]
fn Drafts() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Drafts" }
            p { "Your draft messages will appear here." }
        }
    }
}

#[component]
fn Notifications() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Notifications" }
            p { "Your notifications and alerts will appear here." }
        }
    }
}

#[component]
fn Settings() -> Element {
    rsx! {
        div { style: "padding: 20px;",
            h2 { "Settings" }
            p { "Configuration options will appear here." }
        }
    }
}

#[component]
fn DesktopRiverdanceLayout() -> Element {
    rsx! {
        RiverdanceLayout {
            Outlet::<Route> {}
        }
    }
}
