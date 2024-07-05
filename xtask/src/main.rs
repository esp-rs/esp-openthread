use std::{path::PathBuf, process::Command};

use anyhow::{anyhow, Result};
use bindgen::Builder;
use directories::UserDirs;
use log::LevelFilter;

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    // Determine the $HOME directory, and subsequently the Espressif tools
    // directory:
    let home = UserDirs::new().unwrap().home_dir().to_path_buf();
    let tools = home.join(".espressif").join("tools");

    generate_bindings(
        &workspace,
        tools.join(
            "riscv32-esp-elf/esp-13.2.0_20230928/riscv32-esp-elf/riscv32-esp-elf/include/",
        ),
        tools.join("riscv32-esp-elf/esp-13.2.0_20230928/riscv32-esp-elf/riscv32-esp-elf/"),
    )?;

    Ok(())
}

fn generate_bindings(
    workspace: &PathBuf,
    include_path: PathBuf,
    sysroot_path: PathBuf,
) -> Result<()> {
    let sys_path = workspace.join("esp-openthread-sys");

    // Generate the bindings using `bindgen`:
    log::info!("Generating bindings");
    let bindings = Builder::default()
        .clang_args([
            &format!(
                "-I{}",
                sys_path
                    .join("../build_openthread")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                sys_path
                    .join("../build_openthread/openthread/include")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                sys_path
                    .join("include")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                include_path
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--sysroot={}",
                sysroot_path
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--target=riscv32"
            ),
        ])
        .ctypes_prefix("crate::c_types")
        .derive_debug(true)
        .header(sys_path.join("include/include.h").to_string_lossy())
        .layout_tests(false)
        .raw_line("#![allow(non_camel_case_types,non_snake_case,non_upper_case_globals,dead_code)]")
        .use_core()
        .generate()
        .map_err(|_| anyhow!("Failed to generate bindings"))?;

    // Write out the bindings to the appropriate path:
    let path = sys_path
        .join("src")
        .join("bindings.rs");
    log::info!("Writing out bindings to: {}", path.display());
    bindings.write_to_file(&path)?;

    // Format the bindings:
    Command::new("rustfmt")
        .arg(path.to_string_lossy().to_string())
        .output()?;

    Ok(())
}
