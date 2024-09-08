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
pub extern "C" fn iscntrl(v: u32) -> i32 {
    log::info!("iscntrl {}", v as u8 as char);
    0
}

#[no_mangle]
pub extern "C" fn isprint() {
    log::error!("isprint not implemented");
}

#[no_mangle]
pub extern "C" fn isupper() {
    todo!()
}

#[no_mangle]
pub extern "C" fn strcmp() {
    todo!()
}

// copy pasta from https://github.com/esp-rs/esp-hal/blob/main/esp-wifi/src/compat/misc.rs#L101
#[no_mangle]
unsafe extern "C" fn strstr(str1: *const i8, str2: *const i8) -> *const i8 {
    let s1 = core::ffi::CStr::from_ptr(str1).to_str().unwrap();
    let s2 = core::ffi::CStr::from_ptr(str2).to_str().unwrap();

    let idx = s1.find(s2);

    match idx {
        Some(offset) => str1.add(offset),
        None => core::ptr::null(),
    }
}
