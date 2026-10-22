fn main() {
    println!("cargo:rerun-if-changed=native/protocol.m");
    let protocol = "../../macos/Security/Sources/QuartermasterIPC";
    println!("cargo:rerun-if-changed={protocol}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            // NSXPC requires Clang's extended protocol signatures for reply blocks.
            .file("native/protocol.m")
            .include(format!("{protocol}/include"))
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=15.0")
            .warnings_into_errors(true)
            .compile("qm_context_xpc");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
}
