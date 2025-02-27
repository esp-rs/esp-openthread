use std::env;

use anyhow::Result;

const ESP32_RISCV_TARGET: &str = "riscv32imac-unknown-none-elf";

fn main() -> Result<()> {
    let crate_root_dir = env::var("CARGO_MANIFEST_DIR")?;
    let target = env::var("TARGET")?;

    if target != ESP32_RISCV_TARGET {
        panic!("This build script only supports the `riscv32imac-unknown-none-elf` target for now");
    }

    println!("cargo:rustc-link-lib={}", "everest");
    println!("cargo:rustc-link-lib={}", "mbedcrypto");
    println!("cargo:rustc-link-lib={}", "mbedtls");
    println!("cargo:rustc-link-lib={}", "mbedx509");
    println!("cargo:rustc-link-lib={}", "openthread-mtd");
    println!(
        "cargo:rustc-link-lib={}",
        "openthread-platform-utils-static"
    );
    println!("cargo:rustc-link-lib={}", "openthread-platform");
    println!("cargo:rustc-link-lib={}", "p256m");
    println!("cargo:rustc-link-lib={}", "platform");
    println!("cargo:rustc-link-lib={}", "tcplp-mtd");

    println!("cargo:rustc-link-search={}/libs/{target}", crate_root_dir);

    Ok(())
}
