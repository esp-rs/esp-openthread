#![no_std]
#![feature(c_variadic)]

mod entropy;
mod platform;
mod radio;
mod settings;
mod timer;

use core::{borrow::BorrowMut, cell::RefCell};

use critical_section::Mutex;
use esp_hal::systimer::{Alarm, Target};
use esp_ieee802154::{rssi_to_lqi, Ieee802154};

#[cfg(feature = "esp32c6")]
use esp32c6_hal as esp_hal;
#[cfg(feature = "esp32h2")]
use esp32h2_hal as esp_hal;

// for now just re-export all
pub use esp_openthread_sys as sys;
use esp_openthread_sys::bindings::otPlatRadioReceiveDone;
use sys::bindings::{
    __BindgenBitfieldUnit, otError_OT_ERROR_NONE, otInstance, otRadioFrame,
    otRadioFrame__bindgen_ty_1, otRadioFrame__bindgen_ty_1__bindgen_ty_2,
};

use crate::timer::current_millis;

static RADIO: Mutex<RefCell<Option<Ieee802154>>> = Mutex::new(RefCell::new(None));

static SETTINGS: Mutex<RefCell<Option<NetworkSettings>>> = Mutex::new(RefCell::new(None));

pub static mut RCV_FRAME_PSDU: [u8; 127] = [0u8; 127];
static mut RCV_FRAME: otRadioFrame = otRadioFrame {
    mPsdu: unsafe { &mut RCV_FRAME_PSDU as *mut u8 },
    mLength: 0,
    mChannel: 0,
    mRadioType: 0,
    mInfo: otRadioFrame__bindgen_ty_1 {
        mRxInfo: otRadioFrame__bindgen_ty_1__bindgen_ty_2 {
            mTimestamp: 0,
            mAckFrameCounter: 0,
            mAckKeyId: 0,
            mRssi: 0,
            mLqi: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
        },
    },
};

#[derive(Debug, Clone, Copy, Default)]
struct NetworkSettings {
    promiscuous: bool,
    ext_address: u64,
    short_address: u16,
    pan_id: u16,
    channel: u8,
}

#[non_exhaustive]
pub struct OpenThread {}

impl OpenThread {
    pub fn new(mut radio: Ieee802154, timer: Alarm<Target, 0>, rng: esp_hal::Rng) -> Self {
        timer::install_isr(timer);
        entropy::init_rng(rng);

        radio.set_tx_done_callback_fn(radio::trigger_tx_done);

        critical_section::with(|cs| {
            RADIO.borrow_ref_mut(cs).replace(radio);
        });

        Self {}
    }

    /// Run due timers, get and forward received messages
    pub fn process(&self, instance: *mut otInstance) {
        crate::timer::run_if_due();

        while let Some(raw) = with_radio(|radio| radio.get_raw_received()).unwrap() {
            let rssi = raw.data[raw.data[0] as usize - 1] as i8;

            unsafe {
                let len = raw.data[0];

                log::error!("RCV {:02x?}", &raw.data[1..][..len as usize]);


                RCV_FRAME_PSDU[..len as usize].copy_from_slice(&raw.data[1..][..len as usize]);
                RCV_FRAME.mLength = len as u16;
                RCV_FRAME.mRadioType = 1; // ????
                RCV_FRAME.mChannel = raw.channel;
                RCV_FRAME.mInfo.mRxInfo.mRssi = rssi;
                RCV_FRAME.mInfo.mRxInfo.mLqi = rssi_to_lqi(rssi);
                RCV_FRAME.mInfo.mRxInfo.mTimestamp = current_millis() * 1000;

                log::error!("received something ... need to handle!");
                otPlatRadioReceiveDone(instance, &mut RCV_FRAME, otError_OT_ERROR_NONE);
            }
        }
    }
}

fn with_radio<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&mut Ieee802154) -> T,
{
    critical_section::with(|cs| {
        let mut radio = RADIO.borrow_ref_mut(cs);
        let radio = radio.borrow_mut();

        if let Some(radio) = radio.as_mut() {
            Some(f(radio))
        } else {
            None
        }
    })
}

fn get_settings() -> NetworkSettings {
    critical_section::with(|cs| {
        let mut settings = SETTINGS.borrow_ref_mut(cs);
        let settings = settings.borrow_mut();

        if let Some(settings) = settings.as_mut() {
            settings.clone()
        } else {
            NetworkSettings::default()
        }
    })
}

fn set_settings(settings: NetworkSettings) {
    critical_section::with(|cs| {
        SETTINGS.borrow_ref_mut(cs).borrow_mut().replace(settings);
    });
}
