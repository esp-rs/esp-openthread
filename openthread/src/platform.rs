use core::cell::UnsafeCell;

use crate::sys::{c_char, otError, otInstance, otLogLevel, otLogRegion, otRadioFrame};
use crate::{IntoOtCode, OpenThread, OtActiveState};

pub(crate) struct SyncUnsafeCell<T>(pub UnsafeCell<T>);

unsafe impl<T> Sync for SyncUnsafeCell<T> {}

pub(crate) static OT_ACTIVE_STATE: SyncUnsafeCell<Option<OtActiveState<'static>>> =
    SyncUnsafeCell(UnsafeCell::new(None));

#[no_mangle]
pub extern "C" fn otPlatReset(instance: *const u8) -> otError {
    OpenThread::callback(instance as *const _)
        .plat_reset()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatEntropyGet(output: *mut u8, len: u16) -> otError {
    OpenThread::callback(core::ptr::null_mut())
        .plat_entropy_get(unsafe { core::slice::from_raw_parts_mut(output, len as usize) })
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otTaskletsSignalPending(instance: *mut otInstance) {
    OpenThread::callback(instance).plat_tasklets_signal_pending();
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliGetNow(instance: *const otInstance) -> u32 {
    OpenThread::callback(instance).plat_now()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStartAt(
    instance: *mut otInstance,
    at0: u32,
    adt: u32,
) -> otError {
    OpenThread::callback(instance)
        .plat_alarm_set(at0, adt)
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStop(instance: *const otInstance) -> otError {
    OpenThread::callback(instance)
        .plat_alarm_clear()
        .into_ot_code()
}

/// Caller is required to ensure mac arg is sufficient length (6 bytes)
#[no_mangle]
pub extern "C" fn otPlatRadioGetIeeeEui64(instance: *const otInstance, mac: *mut u8) {
    let mac = unsafe { core::ptr::slice_from_raw_parts_mut(mac, 6).as_mut() }.unwrap();

    OpenThread::callback(instance).plat_radio_ieee_eui64(mac.try_into().unwrap());
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetCaps(instance: *const otInstance) -> u8 {
    OpenThread::callback(instance).plat_radio_caps()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetTransmitBuffer(instance: *const otInstance) -> *mut otRadioFrame {
    OpenThread::callback(instance).plat_radio_transmit_buffer()
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnable(instance: *const otInstance) -> otError {
    OpenThread::callback(instance)
        .plat_radio_enable()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSleep(instance: *const otInstance) -> otError {
    OpenThread::callback(instance)
        .plat_radio_sleep()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioDisable(instance: *const otInstance) -> otError {
    OpenThread::callback(instance)
        .plat_radio_disable()
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPromiscuous(instance: *const otInstance, enable: bool) {
    OpenThread::callback(instance).plat_radio_set_promiscuous(enable)
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetRssi(instance: *const otInstance) -> i8 {
    OpenThread::callback(instance).plat_radio_get_rssi()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetReceiveSensitivity(instance: *const otInstance) -> i8 {
    OpenThread::callback(instance).plat_radio_receive_sensititivy()
}

#[no_mangle]
pub extern "C" fn otPlatRadioIsEnabled(instance: *mut otInstance) -> bool {
    OpenThread::callback(instance).plat_radio_is_enabled()
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnergyScan(
    instance: *const otInstance,
    channel: u8,
    duration: u16,
) -> otError {
    OpenThread::callback(instance)
        .plat_radio_energy_scan(channel, duration)
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetPromiscuous(instance: *const otInstance) -> bool {
    OpenThread::callback(instance).plat_radio_get_promiscuous()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetExtendedAddress(instance: *const otInstance, address: *const u8) {
    OpenThread::callback(instance).plat_radio_set_extended_address(u64::from_be_bytes(
        unsafe { core::slice::from_raw_parts(address, 8) }
            .try_into()
            .unwrap(),
    ));
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetShortAddress(instance: *const otInstance, address: u16) {
    OpenThread::callback(instance).plat_radio_set_short_address(address);
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPanId(instance: *const otInstance, pan_id: u16) {
    OpenThread::callback(instance).plat_radio_set_pan_id(pan_id);
}

#[no_mangle]
pub extern "C" fn otPlatRadioTransmit(
    instance: *const otInstance,
    frame: *const otRadioFrame,
) -> otError {
    OpenThread::callback(instance)
        .plat_radio_transmit(unsafe { &*frame })
        .into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioReceive(instance: *mut otInstance, channel: u8) -> otError {
    OpenThread::callback(instance)
        .plat_radio_receive(channel)
        .into_ot_code()
}

#[no_mangle]
pub unsafe extern "C" fn otPlatLog(
    _level: otLogLevel,
    _region: otLogRegion,
    _format: *const c_char,
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
    let s1 = core::ffi::CStr::from_ptr(str1 as *const _)
        .to_str()
        .unwrap();
    let s2 = core::ffi::CStr::from_ptr(str2 as *const _)
        .to_str()
        .unwrap();

    let idx = s1.find(s2);

    match idx {
        Some(offset) => str1.add(offset),
        None => core::ptr::null(),
    }
}
