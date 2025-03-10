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
    #[cfg(not(target_os = "espidf"))]
    include!(env!("OPENTHREAD_SYS_BINDINGS_FILE"));

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
