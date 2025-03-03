//! An internal module that does the plumbing from the OpenThread C "Platform" API callbacks to Rust

use core::cell::UnsafeCell;
use core::ffi::{c_char, CStr};

use openthread_sys::otError_OT_ERROR_NONE;

use crate::sys::{otError, otInstance, otLogLevel, otLogRegion, otRadioFrame};
use crate::{IntoOtCode, OtContext, OtActiveState};

/// A hack so that we can store a mutable reference to the active state in a global static variable
/// without any explicit synchronization
pub(crate) struct SyncUnsafeCell<T>(pub UnsafeCell<T>);

unsafe impl<T> Sync for SyncUnsafeCell<T> {}

/// A static, mutable global state that allows OpenThnread to call us back via its `otPlat*` functions
/// Look at `OtActiveState` and `OpenThread` for more information as to when this variable is set and unset
pub(crate) static OT_ACTIVE_STATE: SyncUnsafeCell<Option<OtActiveState<'static>>> =
    SyncUnsafeCell(UnsafeCell::new(None));

#[no_mangle]
pub extern "C" fn otPlatReset(instance: *const u8) -> otError {
    OtContext::callback(instance as *const _)
        .plat_reset()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatEntropyGet(output: *mut u8, len: u16) -> otError {
    OtContext::callback(core::ptr::null_mut())
        .plat_entropy_get(unsafe { core::slice::from_raw_parts_mut(output, len as usize) })
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otTaskletsSignalPending(instance: *mut otInstance) {
    OtContext::callback(instance).plat_tasklets_signal_pending();
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliGetNow(instance: *const otInstance) -> u32 {
    OtContext::callback(instance).plat_now()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStartAt(
    instance: *mut otInstance,
    at0: u32,
    adt: u32,
) -> otError {
    OtContext::callback(instance)
        .plat_alarm_set(at0, adt)
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStop(instance: *const otInstance) -> otError {
    OtContext::callback(instance)
        .plat_alarm_clear()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetIeeeEui64(instance: *const otInstance, mac: *mut u8) {
    let mac = unsafe { core::ptr::slice_from_raw_parts_mut(mac, 8).as_mut() }.unwrap();

    OtContext::callback(instance).plat_radio_ieee_eui64(mac.try_into().unwrap());
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetCaps(instance: *const otInstance) -> u8 {
    OtContext::callback(instance).plat_radio_caps()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetTransmitBuffer(instance: *const otInstance) -> *mut otRadioFrame {
    OtContext::callback(instance).plat_radio_transmit_buffer()
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnable(instance: *const otInstance) -> otError {
    OtContext::callback(instance)
        .plat_radio_enable()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSleep(instance: *const otInstance) -> otError {
    OtContext::callback(instance)
        .plat_radio_sleep()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioDisable(instance: *const otInstance) -> otError {
    OtContext::callback(instance)
        .plat_radio_disable()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPromiscuous(instance: *const otInstance, enable: bool) {
    OtContext::callback(instance).plat_radio_set_promiscuous(enable)
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetRssi(instance: *const otInstance) -> i8 {
    OtContext::callback(instance).plat_radio_get_rssi()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetReceiveSensitivity(instance: *const otInstance) -> i8 {
    OtContext::callback(instance).plat_radio_receive_sensititivy()
}

#[no_mangle]
pub extern "C" fn otPlatRadioIsEnabled(instance: *mut otInstance) -> bool {
    OtContext::callback(instance).plat_radio_is_enabled()
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnergyScan(
    instance: *const otInstance,
    channel: u8,
    duration: u16,
) -> otError {
    OtContext::callback(instance)
        .plat_radio_energy_scan(channel, duration)
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetPromiscuous(instance: *const otInstance) -> bool {
    OtContext::callback(instance).plat_radio_get_promiscuous()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetExtendedAddress(instance: *const otInstance, address: *const u8) {
    OtContext::callback(instance).plat_radio_set_extended_address(u64::from_be_bytes(
        unsafe { core::slice::from_raw_parts(address, 8) }
            .try_into()
            .unwrap(),
    ));
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetShortAddress(instance: *const otInstance, address: u16) {
    OtContext::callback(instance).plat_radio_set_short_address(address);
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPanId(instance: *const otInstance, pan_id: u16) {
    OtContext::callback(instance).plat_radio_set_pan_id(pan_id);
}

#[no_mangle]
pub extern "C" fn otPlatRadioTransmit(
    instance: *const otInstance,
    frame: *const otRadioFrame,
) -> otError {
    OtContext::callback(instance)
        .plat_radio_transmit(unsafe { &*frame })
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioReceive(instance: *mut otInstance, channel: u8) -> otError {
    OtContext::callback(instance)
        .plat_radio_receive(channel)
        .into_ot_code()
}

/// NOTE:
/// While the correct signature should be something like:
/// ```ignore
/// pub unsafe extern "C" fn otPlatLog(
///     _level: otLogLevel,
///     _region: otLogRegion,
///     _format: *const c_char,
///     _args: ...
/// ) -> otError {
///     todo!()
/// }
/// ```
///
/// ... varargs are not yet stable in Rust, so we cannot express this.
///
/// Fortunately, looking here: https://github.com/openthread/openthread/blob/31f2897951c9dfd89364121f0581622416e77a7b/src/core/common/log.cpp#L131
/// ... it seems (at least for now) that the "varargs" aspect of `otPlatLog` is not used on the OpenThread C++ side.
///
/// So - while risky - until the above OpenThread C++ code stays unchanged - we can get away with the function signature below.
#[no_mangle]
pub unsafe extern "C" fn otPlatLog(
    level: otLogLevel,
    _region: otLogRegion,
    _format: *const c_char,
    str: *const c_char,
) -> otError {
    #[allow(non_snake_case)]
    #[allow(unused)]
    let level = match level {
        0 => None,
        1 /*CRIT*/ => Some(log::Level::Error),
        2 /*WARN*/ => Some(log::Level::Warn),
        3 /*NOTE*/ => Some(log::Level::Info),
        4 /*INFO*/ => Some(log::Level::Debug),
        5 /*DEBG*/ => Some(log::Level::Trace),
        _ => Some(log::Level::Trace),
    };

    if let Some(level) = level {
        if let Ok(str) = CStr::from_ptr(str).to_str() {
            ::log::log!(level, "[OpenThread] {}", str);
        }
    }

    otError_OT_ERROR_NONE
}

// Other C functions which might generally not be supported by MCU ROMs or by - say - `tinyrlibc`

#[no_mangle]
pub extern "C" fn iscntrl(v: u32) -> bool {
    v < ' ' as u32
}

#[no_mangle]
pub extern "C" fn isprint(v: u32) -> bool {
    v >= ' ' as u32 && v <= 127
}

#[no_mangle]
pub extern "C" fn isupper(v: u32) -> bool {
    v >= 'A' as u32 && v <= 'Z' as u32
}
