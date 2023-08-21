// mostly stubbing out the platform stuff for now

use esp_openthread_sys::{
    bindings::{otError, otLogLevel, otLogRegion},
    c_types,
};

pub(crate) static mut CURRENT_INSTANCE: usize = 0;

#[no_mangle]
pub extern "C" fn otPlatReset(_instance: *const u8) -> otError {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn otPlatLog(
    _level: otLogLevel,
    _region: otLogRegion,
    _format: *const c_types::c_char,
    _args: ...
) -> otError {
    todo!()
}

// other C functions

#[no_mangle]
pub extern "C" fn vsnprintf() {
    todo!()
}

#[no_mangle]
pub extern "C" fn iscntrl(v: u32) -> i32 {
    log::info!("iscntrl {}", v as u8 as char);
    0
}

#[no_mangle]
pub extern "C" fn isprint() {
    log::error!("isprint not implemented");
}

#[no_mangle]
pub extern "C" fn snprintf() {
    todo!()
}

#[no_mangle]
pub extern "C" fn isupper() {
    todo!()
}

#[no_mangle]
pub extern "C" fn strcmp() {
    todo!()
}
