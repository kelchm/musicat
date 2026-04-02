fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=MediaPlayer");

    // Link libmtp for Zune/MTP device sync
    // Requires libmtp-dev (or libmtp-zune) installed on the system.
    // On Debian/Ubuntu: apt install libmtp-dev
    // For Zune support: build and install https://github.com/kbhomes/libmtp-zune
    println!("cargo:rustc-link-lib=mtp");

    tauri_build::build()
}
