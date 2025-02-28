use std::{env, path::PathBuf};

use anyhow::Result;

#[path = "gen/builder.rs"]
mod builder;

fn main() -> Result<()> {
    let crate_root_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    builder::OpenThreadBuilder::track(&crate_root_path.join("gen"));
    builder::OpenThreadBuilder::track(&crate_root_path.join("openthread"));

    // If any one of these features is selected, we don't build anything
    // and just use the pre-generated baremetal ESP bindings and libraries
    let esp32 = env::var("CARGO_FEATURE_ESP32").is_ok();
    let esp32s2 = env::var("CARGO_FEATURE_ESP32S2").is_ok();
    let esp32s3 = env::var("CARGO_FEATURE_ESP32S3").is_ok();
    let esp32c3 = env::var("CARGO_FEATURE_ESP32C3").is_ok();
    let esp32c6 = env::var("CARGO_FEATURE_ESP32C6").is_ok();

    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();

    // If we're building for ESP32* baremetal, we don't need to do anything
    // Just link against the pre-built libraries and use the pre-generated bindings
    let bindings_dir = crate_root_path.join("src").join("include");
    let libs_dir = crate_root_path.join("libs");

    let dirs = if esp32 {
        Some((
            bindings_dir.join("esp32.rs"),
            libs_dir.join("xtensa-esp32-none-elf"),
        ))
    } else if esp32s2 {
        Some((
            bindings_dir.join("esp32s2.rs"),
            libs_dir.join("xtensa-esp32s2-none-elf"),
        ))
    } else if esp32s3 {
        Some((
            bindings_dir.join("esp32s3.rs"),
            libs_dir.join("xtensa-esp32s3-none-elf"),
        ))
    } else if esp32c3 {
        Some((
            bindings_dir.join("esp32c3.rs"),
            libs_dir.join("riscv32imc-unknown-none-elf"),
        ))
    } else if esp32c6 {
        Some((
            bindings_dir.join("esp32c6.rs"),
            libs_dir.join("riscv32imac-unknown-none-elf"),
        ))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us
        None
    } else {
        // Need to do on-the-fly build and bindings' generation
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

        let builder = builder::OpenThreadBuilder::new(
            crate_root_path.clone(),
            "generic".to_string(),
            None,
            None,
            None,
            Some(target),
            Some(host),
        );

        let libs_dir = builder.compile(&out, None)?;
        let bindings = builder.generate_bindings(&out, None)?;

        Some((bindings, libs_dir))
    };

    if let Some((bindings, libs_dir)) = dirs {
        println!(
            "cargo::rustc-env=OPENTHREAD_SYS_GENERATED_BINDINGS_FILE={}",
            bindings.display()
        );

        println!("cargo:rustc-link-lib=everest");
        println!("cargo:rustc-link-lib=mbedcrypto");
        println!("cargo:rustc-link-lib=mbedtls");
        println!("cargo:rustc-link-lib=mbedx509");
        println!("cargo:rustc-link-lib=openthread-mtd");
        println!(
            "cargo:rustc-link-lib=openthread-platform-utils-static"
        );
        println!("cargo:rustc-link-lib=openthread-platform");
        println!("cargo:rustc-link-lib=p256m");
        println!("cargo:rustc-link-lib=platform");
        println!("cargo:rustc-link-lib=tcplp-mtd");
        println!("cargo:rustc-link-search={}", libs_dir.display());
    }

    Ok(())
}
