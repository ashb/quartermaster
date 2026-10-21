fn main() {
    println!("cargo:rerun-if-changed=native/context_xpc.h");
    println!("cargo:rerun-if-changed=native/context_xpc.m");
    let protocol = "../../macos/Security/Sources/QuartermasterIPC";
    println!("cargo:rerun-if-changed={protocol}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/context_xpc.m")
            .file(format!("{protocol}/context_protocol.m"))
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
