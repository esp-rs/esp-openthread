use std::{
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;

fn main() -> Result<()> {
    // Put the linker script somewhere the linker can find it
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    copy_file(&out, "../libs/libeverest.a", "libeverest.a")?;
    copy_file(&out, "../libs/libmbedcrypto.a", "libmbedcrypto.a")?;
    copy_file(&out, "../libs/libmbedtls.a", "libmbedtls.a")?;
    copy_file(&out, "../libs/libmbedx509.a", "libmbedx509.a")?;
    copy_file(&out, "../libs/libopenthread-mtd.a", "libopenthread-mtd.a")?;
    copy_file(
        &out,
        "../libs/libopenthread-platform-utils-static.a",
        "libopenthread-platform-utils-static.a",
    )?;
    copy_file(
        &out,
        "../libs/libopenthread-platform.a",
        "libopenthread-platform.a",
    )?;
    copy_file(&out, "../libs/libp256m.a", "libp256m.a")?;
    copy_file(&out, "../libs/libplatform.a", "libplatform.a")?;
    copy_file(&out, "../libs/libtcplp-mtd.a", "libtcplp-mtd.a")?;

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

    println!("cargo:rustc-link-search={}", out.display());

    Ok(())
}

fn copy_file(out: &PathBuf, from: &str, to: &str) -> Result<()> {
    let mut file = File::create(out.join(to))?;
    file.write_all(&fs::read(from)?)?;

    Ok(())
}
