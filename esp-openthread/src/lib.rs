#![no_std]
#![feature(c_variadic)]

mod entropy;
mod platform;
mod radio;
mod settings;
mod timer;

use core::{borrow::BorrowMut, cell::RefCell, marker::PhantomData};

use bitflags::bitflags;
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
    __BindgenBitfieldUnit, otChangedFlags, otError_OT_ERROR_NONE, otInstance, otInstanceInitSingle,
    otIp6GetUnicastAddresses, otIp6SetEnabled, otRadioFrame, otRadioFrame__bindgen_ty_1,
    otRadioFrame__bindgen_ty_1__bindgen_ty_2, otSetStateChangedCallback, otTaskletsArePending,
    otTaskletsProcess, otThreadSetEnabled,
};

use crate::timer::current_millis;

static RADIO: Mutex<RefCell<Option<&'static mut Ieee802154>>> = Mutex::new(RefCell::new(None));

static NETWORK_SETTINGS: Mutex<RefCell<Option<NetworkSettings>>> = Mutex::new(RefCell::new(None));

static CHANGE_CALLBACK: Mutex<RefCell<Option<&'static mut (dyn FnMut(ChangedFlags) + Send)>>> =
    Mutex::new(RefCell::new(None));

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

#[macro_export]
macro_rules! checked {
    ($value:expr) => {
        if $value != 0 {
            Err(crate::Error::InternalError($value))
        } else {
            core::result::Result::<(), crate::Error>::Ok(())
        }
    };
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    InternalError(u32),
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ChangedFlags: u32 {
        // IPv6 address was added
        const Ipv6AddressAdded = 1;
        // IPv6 address was removed
        const Ipv6AddressRemoved = 2;
        // Role (disabled, detached, child, router, leader) changed
        const ThreadRoleChanged = 4;
        // The link-local address changed
        const ThreadLlAddressChanged = 8;
        // The mesh-local address changed
        const ThreadMeshLocalAddressChanged = 16;
        //  RLOC was added
        const ThreadRlocAdded = 32;
        // RLOC was removed
        const ThreadRlocRemoved = 64;
        // Partition ID changed
        const ThreadPartitionIdChanged = 128;
        // Thread Key Sequence changed
        const ThreadKeySequenceChanged = 256;
        // Thread Network Data changed
        const ThreadNetworkDataChanged = 512;
        // Child was added
        const ThreadChildAdded = 1024;
        // Child was removed
        const ThreadChildRemoved = 2048;
        // Subscribed to a IPv6 multicast address
        const Ipv6MulticastSubscribed = 4096;
        // Unsubscribed from a IPv6 multicast address
        const Ipv6MulticastUnsubscribed = 8192;
        // Thread network channel changed
        const ThreadNetworkChannelChanged = 16384;
        // Thread network PAN Id changed
        const ThreadPanIdChanged = 32768;
        // Thread network name changed
        const ThreadNetworkNameChanged = 65536;
        // Thread network extended PAN ID changed
        const ThreadExtendedPanIdChanged = 131072;
        // Network key changed
        const ThreadNetworkKeyChanged = 262144;
        // PSKc changed
        const ThreadPskcChanged = 524288;
        // Security Policy changed
        const ThreadSecurityPolicyChanged = 1048576;
        // Channel Manager new pending Thread channel changed
        const ChannelManagerNewChannelChanged = 2097152;
        // Supported channel mask changed
        const SupportedChannelMaskChanged = 4194304;
        // Commissioner state changed
        const CommissionerStateChanged = 8388608;
        // Thread network interface state changed
        const ThreadNetworkInterfaceStateChanged = 16777216;
        // Backbone Router state changed
        const ThreadBackboneRouterStateChanged = 33554432;
        // Local Backbone Router configuration changed
        const ThreadBackboneRouterLocalChanged = 67108864;
        // Joiner state changed
        const JoinerStateChanged = 134217728;
        //  Active Operational Dataset changed
        const ActiveDatasetChanged = 268435456;
        // Pending Operational Dataset changed
        const PendingDatasetChanged = 536870912;


    }
}

/// IPv6 network interface unicast address
#[derive(Debug, Clone, Copy)]
pub struct NetworkInterfaceUnicastAddress {
    // The IPv6 unicast address
    pub address: no_std_net::Ipv6Addr,
    // The Prefix length (in bits)
    pub prefix: u8,
    // The IPv6 address origin
    pub origin: u8,
}

#[derive(Debug, Clone, Copy, Default)]
struct NetworkSettings {
    promiscuous: bool,
    ext_address: u64,
    short_address: u16,
    pan_id: u16,
    channel: u8,
}

#[non_exhaustive]
pub struct OpenThread<'a> {
    _phantom: PhantomData<&'a ()>,
    // pub for now
    pub instance: *mut otInstance,
}

impl<'a> OpenThread<'a> {
    pub fn new(radio: &'a mut Ieee802154, timer: Alarm<Target, 0>, rng: esp_hal::Rng) -> Self {
        timer::install_isr(timer);
        entropy::init_rng(rng);

        radio.set_tx_done_callback_fn(radio::trigger_tx_done);

        critical_section::with(|cs| {
            RADIO
                .borrow_ref_mut(cs)
                .replace(unsafe { core::mem::transmute(radio) });
        });

        let instance = unsafe { otInstanceInitSingle() };
        log::debug!("otInstanceInitSingle done, instance = {:p}", instance);

        let res = unsafe {
            otSetStateChangedCallback(instance, Some(change_callback), core::ptr::null_mut())
        };
        log::debug!("otSetStateChangedCallback {res}");

        Self {
            _phantom: PhantomData,
            instance,
        }
    }

    /// Set the change callback
    pub fn set_change_callback(
        &mut self,
        callback: Option<&'a mut (dyn FnMut(ChangedFlags) + Send)>,
    ) {
        critical_section::with(|cs| {
            let mut change_callback = CHANGE_CALLBACK.borrow_ref_mut(cs);
            *change_callback = unsafe { core::mem::transmute(callback) };
        });
    }

    /// Brings the IPv6 interface up or down.
    pub fn ipv6_set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        checked!(unsafe { otIp6SetEnabled(self.instance, enabled) })
    }

    /// This function starts Thread protocol operation.
    ///
    /// The interface must be up when calling this function.
    pub fn thread_set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        checked!(unsafe { otThreadSetEnabled(self.instance, enabled) })
    }

    /// Gets the list of IPv6 addresses assigned to the Thread interface.
    pub fn ipv6_get_unicast_addresses<const N: usize>(
        &self,
    ) -> heapless::Vec<NetworkInterfaceUnicastAddress, N> {
        let mut result = heapless::Vec::new();
        let mut addr = unsafe { otIp6GetUnicastAddresses(self.instance) };

        loop {
            let a = unsafe { &*addr };

            let octets = unsafe { a.mAddress.mFields.m16 };

            if result
                .push(NetworkInterfaceUnicastAddress {
                    address: no_std_net::Ipv6Addr::new(
                        octets[0].to_be(),
                        octets[1].to_be(),
                        octets[2].to_be(),
                        octets[3].to_be(),
                        octets[4].to_be(),
                        octets[5].to_be(),
                        octets[6].to_be(),
                        octets[7].to_be(),
                    ),
                    prefix: a.mPrefixLength,
                    origin: a.mAddressOrigin,
                })
                .is_err()
            {
                break;
            }

            if a.mNext.is_null() {
                break;
            }

            addr = a.mNext;
        }

        result
    }

    /// Run tasks
    ///
    /// Make sure to periodically call this function.
    pub fn run_tasklets(&self) {
        unsafe {
            if otTaskletsArePending(self.instance) {
                otTaskletsProcess(self.instance);
            }
        }
    }

    /// Run due timers, get and forward received messages
    ///
    /// Make sure to periodically call this function.
    pub fn process(&self) {
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
                otPlatRadioReceiveDone(self.instance, &mut RCV_FRAME, otError_OT_ERROR_NONE);
            }
        }
    }
}

impl<'a> Drop for OpenThread<'a> {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            RADIO.borrow_ref_mut(cs).take();
            NETWORK_SETTINGS.borrow_ref_mut(cs).take();
            CHANGE_CALLBACK.borrow_ref_mut(cs).take();
        });
    }
}

unsafe extern "C" fn change_callback(
    flags: otChangedFlags,
    _context: *mut esp_openthread_sys::c_types::c_void,
) {
    log::debug!("change_callback otChangedFlags={:32b}", flags);
    critical_section::with(|cs| {
        let mut change_callback = CHANGE_CALLBACK.borrow_ref_mut(cs);
        let callback = change_callback.as_mut();

        if let Some(callback) = callback {
            callback(ChangedFlags::from_bits(flags).unwrap());
        }
    });
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
        let mut settings = NETWORK_SETTINGS.borrow_ref_mut(cs);
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
        NETWORK_SETTINGS
            .borrow_ref_mut(cs)
            .borrow_mut()
            .replace(settings);
    });
}
