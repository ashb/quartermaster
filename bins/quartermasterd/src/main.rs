#[cfg(target_os = "macos")]
mod runtime;

fn main() {
    #[cfg(target_os = "macos")]
    if let Err(error) = runtime::run() {
        eprintln!("quartermasterd: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "macos"))]
    std::process::exit(77);
}
