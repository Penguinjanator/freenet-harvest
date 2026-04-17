fn main() {
    let now = chrono::Utc::now();
    let timestamp = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    println!("cargo:rustc-env=BUILD_TIMESTAMP_ISO={}", timestamp);

    // Always re-run so the timestamp updates on each build
    println!("cargo:rerun-if-changed=build.rs");
}
