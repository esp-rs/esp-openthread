use core::cell::Cell;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use esp_openthread_sys::otMessage;

use crate::sys::{c_char, otError, otInstance, otLogLevel, otLogRegion, otRadioFrame};
use crate::{IntoOtCode, OtError};

pub(crate) trait OtCallback: OtPlatformCallback + OtPlatformRadioCallback {}

pub(crate) trait OtPlatformCallback {
    fn reset(&mut self) -> Result<(), OtError>;

    fn rand(&mut self, buf: &mut [u8]) -> Result<(), OtError>;

    fn tasklets_pending(&mut self);

    fn changed(&mut self, flags: u32);

    fn ipv6_received(&mut self, message: *mut otMessage);

    fn now(&mut self) -> u32;

    fn alarm_set(&mut self, at0_ms: u32, adt_ms: u32) -> Result<(), OtError>;
    fn alarm_clear(&mut self) -> Result<(), OtError>;
}

pub(crate) trait OtPlatformRadioCallback {
    fn ieee_eui64(&mut self, mac: &mut [u8; 6]);

    fn caps(&mut self) -> u8;
    fn enabled(&mut self) -> bool;

    fn rssi(&mut self) -> i8;
    fn receive_sensitivity(&mut self) -> i8;

    fn promiscuous(&mut self) -> bool;

    fn set_enabled(&mut self, enabled: bool) -> Result<(), OtError>;

    fn set_promiscuous(&mut self, promiscuous: bool);
    fn set_extended_address(&mut self, address: u64);
    fn set_short_address(&mut self, address: u16);
    fn set_pan_id(&mut self, pan_id: u16);

    fn energy_scan(&mut self, channel: u8, duration: u16) -> Result<(), OtError>;
    fn sleep(&mut self) -> Result<(), OtError>;

    fn transmit_buffer(&mut self) -> *mut otRadioFrame;

    fn transmit(&mut self, frame: &otRadioFrame) -> Result<(), OtError>;
    fn receive(&mut self, channel: u8) -> Result<(), OtError>;
}

pub(crate) struct OtCallCProxy {
    _instance: *mut otInstance,
    callback: *mut dyn OtCallback,
}

impl OtCallCProxy {
    pub(crate) unsafe fn new<'a>(
        instance: *mut otInstance,
        callback: *mut (dyn OtCallback + 'a),
    ) -> Self {
        #[allow(clippy::missing_transmute_annotations)]
        Self {
            _instance: instance,
            callback: unsafe { core::mem::transmute(callback) },
        }
    }

    pub(crate) fn call<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        OT_CALLBACK.lock(|cb| {
            cb.set(Some(OtSendCallback(self.callback)));
        });

        let res = f();

        OT_CALLBACK.lock(|cb| cb.set(None));

        res
    }

    pub(crate) fn ot_c_callback<F, T>(_instance: *const otInstance, f: F) -> T
    where
        F: FnOnce(&mut dyn OtCallback) -> T,
    {
        let cb = OT_CALLBACK.lock(|cb| cb.get()).unwrap();

        let cb = unsafe { cb.0.as_mut() }.unwrap();

        f(cb)
    }
}

#[derive(Copy, Clone)]
pub(crate) struct OtSendCallback<'a>(pub(crate) *mut (dyn OtCallback + 'a));

unsafe impl Send for OtSendCallback<'_> {}

// TODO: Do it lockless
pub(crate) static OT_CALLBACK: Mutex<
    CriticalSectionRawMutex,
    Cell<Option<OtSendCallback<'static>>>,
> = Mutex::new(Cell::new(None));

#[no_mangle]
pub extern "C" fn otPlatReset(instance: *const u8) -> otError {
    let instance = instance as *mut otInstance; // TODO
    OtCallCProxy::ot_c_callback(instance, |cb| cb.reset()).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliGetNow(instance: *const otInstance) -> u32 {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.now())
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStartAt(
    instance: *mut otInstance,
    at0: u32,
    adt: u32,
) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.alarm_set(at0, adt)).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStop(instance: *const otInstance) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.alarm_clear()).into_ot_code()
}

/// Caller is required to ensure mac arg is sufficient length (6 bytes)
#[no_mangle]
pub extern "C" fn otPlatRadioGetIeeeEui64(instance: *const otInstance, mac: *mut u8) {
    OtCallCProxy::ot_c_callback(instance, |cb| {
        let mac = unsafe { core::ptr::slice_from_raw_parts_mut(mac, 6).as_mut() }.unwrap();
        cb.ieee_eui64(mac.try_into().unwrap());
    });
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetCaps(instance: *const otInstance) -> u8 {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.caps())
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetTransmitBuffer(instance: *const otInstance) -> *mut otRadioFrame {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.transmit_buffer())
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnable(instance: *const otInstance) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.set_enabled(true)).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSleep(instance: *const otInstance) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.sleep()).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioDisable(instance: *const otInstance) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.set_enabled(false)).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPromiscuous(instance: *const otInstance, enable: bool) {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.set_promiscuous(enable));
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetRssi(instance: *const otInstance) -> i8 {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.rssi())
}

// from https://github.com/espressif/esp-idf/blob/release/v5.3/components/openthread/src/port/esp_openthread_radio.c#L35
#[no_mangle]
pub extern "C" fn otPlatRadioGetReceiveSensitivity(instance: *const otInstance) -> i8 {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.receive_sensitivity())
}

#[no_mangle]
pub extern "C" fn otPlatRadioIsEnabled(instance: *mut otInstance) -> bool {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.enabled())
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnergyScan(
    instance: *const otInstance,
    channel: u8,
    duration: u16,
) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.energy_scan(channel, duration)).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetPromiscuous(instance: *const otInstance) -> bool {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.promiscuous())
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetExtendedAddress(instance: *const otInstance, address: *const u8) {
    OtCallCProxy::ot_c_callback(instance, |cb| {
        cb.set_extended_address(u64::from_be_bytes(
            unsafe { core::slice::from_raw_parts(address, 8) }
                .try_into()
                .unwrap(),
        ))
    });
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetShortAddress(instance: *const otInstance, address: u16) {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.set_short_address(address));
}

#[no_mangle]
pub extern "C" fn otTaskletsSignalPending(instance: *mut otInstance) {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.tasklets_pending());
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPanId(instance: *const otInstance, pan_id: u16) {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.set_pan_id(pan_id));
}

#[no_mangle]
pub extern "C" fn otPlatRadioTransmit(
    instance: *const otInstance,
    frame: *const otRadioFrame,
) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.transmit(unsafe { &*frame })).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatRadioReceive(instance: *mut otInstance, channel: u8) -> otError {
    OtCallCProxy::ot_c_callback(instance, |cb| cb.receive(channel)).into_ot_code()
}

#[no_mangle]
pub extern "C" fn otPlatEntropyGet(output: *mut u8, len: u16) -> otError {
    OtCallCProxy::ot_c_callback(core::ptr::null_mut(), |cb| {
        cb.rand(unsafe { core::slice::from_raw_parts_mut(output, len as usize) })
    })
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
