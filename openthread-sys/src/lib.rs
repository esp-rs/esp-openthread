#![no_std]

pub use bindings::*;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]
pub mod bindings {
    #[cfg(all(
        not(target_os = "espidf"),
        not(any(
            feature = "esp32",
            feature = "esp32s2",
            feature = "esp32s3",
            feature = "esp32c3",
            feature = "esp32c6"
        ))
    ))]
    include!(env!("OPENTHREAD_SYS_GENERATED_BINDINGS_FILE"));

    // This and below are necessary because of https://github.com/rust-lang/cargo/issues/10358
    #[cfg(feature = "esp32")]
    include!("include/esp32.rs");

    #[cfg(feature = "esp32s2")]
    include!("include/esp32s2.rs");

    #[cfg(feature = "esp32s3")]
    include!("include/esp32s3.rs");

    #[cfg(feature = "esp32c3")]
    include!("include/esp32c3.rs");

    #[cfg(feature = "esp32c6")]
    include!("include/esp32c6.rs");

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
