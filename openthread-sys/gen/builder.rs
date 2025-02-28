use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Result};
use bindgen::Builder;
use cmake::Config;

pub struct OpenThreadBuilder {
    crate_root_path: PathBuf,
    soc_config: String,
    clang_path: Option<PathBuf>,
    sysroot_path: Option<PathBuf>,
    cmake_target: Option<String>,
    clang_target: Option<String>,
    host: Option<String>,
}

impl OpenThreadBuilder {
    /// Create a new OpenThreadBuilder
    ///
    /// Arguments:
    /// - `crate_root_path`: Path to the root of the crate
    /// - `soc_config`: The name of the SoC configuration in the `headers/` directory. Use `generic` for a generic, software-only build
    /// - `clang_path`: Optional path to the Clang compiler. If not specified, the system Clang will be used for generating bindings,
    ///   and the system compiler (likely GCC) would be used for building the OpenThread C/C++ code itself
    /// - `sysroot_path`: Optional path to the compiler sysroot directory. If not specified, the host sysroot will be used
    /// - `cmake_target`: Optional target for CMake when building Openthread, with Rust target-triple syntax. If not specified, the "TARGET" env variable will be used
    /// - `clang_target`: Optional target for Clang when generating bindings. If not specified, the host target will be used
    /// - `host`: Optional host target for the build
    pub const fn new(
        crate_root_path: PathBuf,
        soc_config: String,
        clang_path: Option<PathBuf>,
        sysroot_path: Option<PathBuf>,
        cmake_target: Option<String>,
        clang_target: Option<String>,
        host: Option<String>,
    ) -> Self {
        Self {
            crate_root_path,
            soc_config,
            clang_path,
            sysroot_path,
            cmake_target,
            clang_target,
            host,
        }
    }

    /// Generate bindings for openthread-sys
    ///
    /// Arguments:
    /// - `out_path`: Path to write the bindings to
    pub fn generate_bindings(
        &self,
        out_path: &Path,
        copy_file_path: Option<&Path>,
    ) -> Result<PathBuf> {
        if let Some(clang_path) = &self.clang_path {
            std::env::set_var("CLANG_PATH", clang_path);
        }

        let canon = |path: &Path| {
            // TODO: Is this really necessary?
            path.display()
                .to_string()
                .replace('\\', "/")
                .replace("//?/C:", "")
        };

        // Generate the bindings using `bindgen`:
        log::info!("Generating bindings");
        let mut builder = Builder::default()
            .use_core()
            .enable_function_attribute_detection()
            .derive_debug(false)
            .layout_tests(false)
            .blocklist_function("strtold")
            .blocklist_function("_strtold_r")
            .blocklist_function("v.*printf")
            .blocklist_function("v.*scanf")
            .blocklist_function("_v.*printf_r")
            .blocklist_function("_v.*scanf_r")
            .header(
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("include.h")
                    .to_string_lossy(),
            )
            .clang_args([
                &format!(
                    "-I{}",
                    canon(&self.crate_root_path.join("openthread").join("include"))
                ),
                &format!(
                    "-I{}",
                    canon(
                        &self
                            .crate_root_path
                            .join("gen")
                            .join("include")
                            .join("soc")
                            .join(&self.soc_config)
                    )
                ),
            ]);

        if let Some(sysroot_path) = &self.sysroot_path {
            builder = builder.clang_args([
                &format!("-I{}", canon(&sysroot_path.join("include"))),
                &format!("--sysroot={}", canon(sysroot_path)),
            ]);
        }

        if let Some(target) = &self.clang_target {
            builder = builder.clang_arg(format!("--target={target}"));
        }

        let bindings = builder
            .generate()
            .map_err(|_| anyhow!("Failed to generate bindings"))?;

        let bindings_file = out_path.join("bindings.rs");

        // Write out the bindings to the appropriate path:
        log::info!("Writing out bindings to: {}", bindings_file.display());
        bindings.write_to_file(&bindings_file)?;

        // Format the bindings:
        Command::new("rustfmt")
            .arg(bindings_file.to_string_lossy().to_string())
            .arg("--config")
            .arg("normalize_doc_attributes=true")
            .output()?;

        if let Some(copy_file_path) = copy_file_path {
            log::info!("Copying bindings to {}", copy_file_path.display());
            std::fs::create_dir_all(copy_file_path.parent().unwrap())?;
            std::fs::copy(&bindings_file, copy_file_path)?;
        }

        Ok(bindings_file)
    }

    /// Compile OpenThread
    ///
    /// Arguments:
    /// - `out_path`: Path to write the compiled libraries to
    pub fn compile(&self, out_path: &Path, copy_path: Option<&Path>) -> Result<PathBuf> {
        if let Some(clang_path) = &self.clang_path {
            std::env::set_var("CLANG_PATH", clang_path);
        }

        log::info!("Compiling for {} SOC", self.soc_config);
        let ot_path = self.crate_root_path.clone(); //.join("openthread");

        let target_dir = out_path.join("openthread").join("build");

        std::fs::create_dir_all(&target_dir)?;

        // Compile OpenThread and generate libraries to link against
        log::info!("Compiling OpenThread");
        let mut config = Config::new(&ot_path);

        config
            .define("OT_LOG_LEVEL", "DEBG")
            .define("OT_LOG_OUTPUT", "PLATFORM_DEFINED")
            .define("OT_FTD", "OFF")
            .define("OT_MTD", "ON")
            .define("OT_RCP", "OFF")
            .define("OT_APP_CLI", "OFF")
            .define("OT_APP_NCP", "OFF")
            .define("OT_APP_RCP", "OFF")
            .define("OT_PLATFORM", "external")
            .define("OT_SLAAC", "ON")
            .define("OT_SETTINGS_RAM", "ON")
            .define("OT_SRP_CLIENT", "ON")
            .define("OT_ECDSA", "ON")
            .define("OT_PING_SENDER", "ON")
            //.define("OT_COMPILE_WARNING_AS_ERROR", "ON "$@" "${OT_SRCDIR}"")
            .define("ENABLE_PROGRAMS", "OFF")
            .define("ENABLE_TESTING", "OFF")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            .define("CMAKE_BUILD_TYPE", "MinSizeRel")
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                self
                    .crate_root_path
                    .join("gen")
                    .join("toolchains")
                    .join(format!("toolchain-clang-{}.cmake", self.soc_config)),
            )
            // .cflag(&format!(
            //     "-I{}",
            //     self.crate_root_path
            //         .join("gen")
            //         .join("include")
            //         .join("soc")
            //         .join(&self.soc_config)
            //         .display()
            // ))
            // .cflag(&format!("-DMBEDTLS_CONFIG_FILE='<config.h>'"))
            // .cxxflag(&format!("-DMBEDTLS_CONFIG_FILE='<config.h>'"))
            .profile("Release")
            .out_dir(&target_dir);

        if let Some(target) = &self.cmake_target {
            config.target(target);
        }

        if let Some(host) = &self.host {
            config.host(host);
        }

        config.build();

        let lib_dir = target_dir.join("build").join("lib");

        if let Some(copy_path) = copy_path {
            log::info!(
                "Copying OpenThread libraries from {} to {}",
                lib_dir.display(),
                copy_path.display()
            );
            std::fs::create_dir_all(copy_path)?;

            for file in [
                "libeverest.a",
                "libmbedcrypto.a",
                "libmbedx509.a",
                "libmbedtls.a",
                "libopenthread-mtd.a",
                "libopenthread-platform-utils-static.a",
                "libopenthread-platform.a",
                "libp256m.a",
                "libplatform.a",
                "libtcplp-mtd.a",
            ] {
                std::fs::copy(lib_dir.join(file), copy_path.join(file))?;
            }
        }

        Ok(lib_dir)
    }

    /// Re-run the build script if the file or directory has changed.
    #[allow(unused)]
    pub fn track(file_or_dir: &Path) {
        println!("cargo:rerun-if-changed={}", file_or_dir.display())
    }
}
