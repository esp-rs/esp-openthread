use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use directories::UserDirs;
use log::LevelFilter;
use tempdir::TempDir;

#[path = "../../openthread-sys/gen/builder.rs"]
mod builder;

// Arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Compile and generate bindings for OpenThread to be used in Rust.", long_about = None, subcommand_required = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate Rust bindings for mbedtls and generate .a libraries
    Gen {
        #[arg(long, value_name = "TARGET", value_enum)]
        chip: Option<Soc>,
    },
    /// Generate Rust bindings for mbedtls
    Bindings {
        #[arg(long, value_name = "TARGET", value_enum)]
        chip: Option<Soc>,
    },
    /// Build mbedtls and generate .a libraries
    Compile {
        #[arg(long, value_name = "TARGET", value_enum)]
        chip: Option<Soc>,
    },
}

/// All SOCs available for compiling and binding
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum Soc {
    ESP32,
    ESP32S2,
    ESP32S3,
    ESP32C3,
    ESP32C6,
}

impl core::fmt::Display for Soc {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Soc::ESP32 => write!(f, "esp32"),
            Soc::ESP32S2 => write!(f, "esp32s2"),
            Soc::ESP32S3 => write!(f, "esp32s3"),
            Soc::ESP32C3 => write!(f, "esp32c3"),
            Soc::ESP32C6 => write!(f, "esp32c6"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Arch {
    RiscV,
    Xtensa,
}

impl Arch {
    pub const fn clang(&self) -> Option<&str> {
        const ESP_XTENSA_CLANG_PATH: &str = "xtensa-esp32-elf-clang/esp-18.1.2_20240912/esp-clang/bin/clang";

        match self {
            Arch::Xtensa => Some(ESP_XTENSA_CLANG_PATH),
            // Clang is a cross-compiler
            _ => Some(ESP_XTENSA_CLANG_PATH),
        }
    }

    pub const fn sysroot(&self) -> &str {
        const ESP_XTENSA_SYSROOT_PATH: &str = "xtensa-esp-elf/esp-14.2.0_20240906/xtensa-esp-elf/xtensa-esp-elf";
        const ESP_RISCV_SYSROOT_PATH: &str = "riscv32-esp-elf/esp-14.2.0_20240906/riscv32-esp-elf/riscv32-esp-elf";
        
        match self {
            Arch::RiscV => ESP_RISCV_SYSROOT_PATH,
            Arch::Xtensa => ESP_XTENSA_SYSROOT_PATH,
        }
    }
}

/// Data for binding compiling on a target
struct CompilationTarget<'a> {
    /// Chip of the target
    soc: Soc,

    /// The chip architecture
    arch: Arch,

    /// Rust target triple
    target: &'a str,

    /// Clang target
    clang_target: &'a str,
}

impl CompilationTarget<'_> {
    pub fn gen(&self, sys_crate_root_path: PathBuf, toolchain_dir: &Path) -> Result<()> {
        self.build(sys_crate_root_path.clone(), toolchain_dir)?;
        self.generate_bindings(sys_crate_root_path, toolchain_dir)?;

        Ok(())
    }

    pub fn build(&self, sys_crate_root_path: PathBuf, toolchain_dir: &Path) -> Result<()> {
        let builder = builder::OpenThreadBuilder::new(
            sys_crate_root_path.clone(),
            format!("{}", self.soc),
            self.arch.clang().map(|clang| toolchain_dir.join(clang)),
            None,
            Some(self.target.into()),
            Some(self.clang_target.into()),
            // Fake host, but we do need to pass something to CMake
            Some("x86_64-unknown-linux-gnu".into()),
        );

        let out = TempDir::new("openthread-sys")?;

        builder.compile(
            out.path(),
            Some(&sys_crate_root_path.join("libs").join(self.target)),
        )?;

        Ok(())
    }

    pub fn generate_bindings(
        &self,
        sys_crate_root_path: PathBuf,
        toolchain_dir: &Path,
    ) -> Result<()> {
        let builder = builder::OpenThreadBuilder::new(
            sys_crate_root_path.clone(),
            format!("{}", self.soc),
            self.arch.clang().map(|clang| toolchain_dir.join(clang)),
            Some(toolchain_dir.join(self.arch.sysroot())),
            Some(self.target.into()),
            Some(self.clang_target.into()),
            None,
        );

        let out = TempDir::new("openthread-sys")?;

        builder.generate_bindings(
            out.path(),
            Some(
                &sys_crate_root_path
                    .join("src")
                    .join("include")
                    .join(format!("{}.rs", self.soc)),
            ),
        )?;

        Ok(())
    }
}

static COMPILATION_TARGETS: &[CompilationTarget] = &[
    CompilationTarget {
        soc: Soc::ESP32,
        arch: Arch::Xtensa,
        clang_target: "xtensa-esp32-none-elf",
        target: "xtensa-esp32-none-elf",
    },
    CompilationTarget {
        soc: Soc::ESP32S2,
        arch: Arch::Xtensa,
        clang_target: "xtensa-esp32s2-none-elf",
        target: "xtensa-esp32s2-none-elf",
    },
    CompilationTarget {
        soc: Soc::ESP32S3,
        arch: Arch::Xtensa,
        clang_target: "xtensa-esp32s3-none-elf",
        target: "xtensa-esp32s3-none-elf",
    },
    CompilationTarget {
        soc: Soc::ESP32C3,
        arch: Arch::RiscV,
        clang_target: "riscv32-esp-elf",
        target: "riscv32imc-unknown-none-elf",
    },
    CompilationTarget {
        soc: Soc::ESP32C6,
        arch: Arch::RiscV,
        clang_target: "riscv32-esp-elf",
        target: "riscv32imac-unknown-none-elf",
    },
];

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    let sys_crate_root_path = workspace.join("openthread-sys");

    // Determine the $HOME directory, and subsequently the Espressif tools
    // directory:
    let home = UserDirs::new().unwrap().home_dir().to_path_buf();
    // We use the tools that come installed with the toolchain
    // Note that the RiscV toolchain is not installed by default and needs the `-r` `espup` flag
    let toolchain_dir = home.join(".rustup").join("toolchains").join("esp");

    let args = Args::parse();

    let target = |chip| COMPILATION_TARGETS
        .iter()
        .find(|&target| target.soc == chip)
        .expect("Compilation target {chip} not found");

    match args.command {
        Some(Commands::Gen { chip }) => match chip {
            Some(chip) => {
                target(chip).gen(sys_crate_root_path.clone(), &toolchain_dir)?;
            }
            None => {
                for target in COMPILATION_TARGETS {
                    target.gen(sys_crate_root_path.clone(), &toolchain_dir)?;
                }
            }
        },
        Some(Commands::Compile { chip }) => match chip {
            Some(chip) => {
                target(chip).build(sys_crate_root_path.clone(), &toolchain_dir)?;
            }
            None => {
                for target in COMPILATION_TARGETS {
                    target.build(sys_crate_root_path.clone(), &toolchain_dir)?;
                }
            }
        },
        Some(Commands::Bindings { chip }) => match chip {
            Some(chip) => {
                target(chip).generate_bindings(sys_crate_root_path.clone(), &toolchain_dir)?;
            }
            None => {
                for target in COMPILATION_TARGETS {
                    target.generate_bindings(sys_crate_root_path.clone(), &toolchain_dir)?;
                }
            }
        },
        _ => {
            unreachable!();
        }
    }

    Ok(())
}
