//! Currently just uses the plain OpenThread API

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_ieee802154::Ieee802154;
use esp_openthread::sys::{
    bindings::{
        otChangedFlags, otDatasetSetActive, otExtendedPanId, otInstance, otInstanceInitSingle,
        otIp6GetUnicastAddresses, otIp6SetEnabled, otMeshLocalPrefix, otNetworkKey, otNetworkName,
        otOperationalDataset, otOperationalDatasetComponents, otPskc, otSecurityPolicy,
        otSetStateChangedCallback, otTaskletsArePending, otTaskletsProcess, otThreadSetEnabled,
        otTimestamp,
    },
    c_types,
};
use esp_println::{print, println};
use hal::{
    clock::ClockControl, peripherals::Peripherals, prelude::*, systimer, Rng,
};

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let peripherals = Peripherals::take();
    let mut system = peripherals.PCR.split();
    let _clocks = ClockControl::boot_defaults(system.clock_control).freeze();

    println!("Initializing");

    let systimer = systimer::SystemTimer::new(peripherals.SYSTIMER);
    let (_, _, radio) = peripherals.RADIO.split();
    let mut ieee802154 = Ieee802154::new(radio, &mut system.radio_clock_control);
    let openthread = esp_openthread::OpenThread::new(
        &mut ieee802154,
        systimer.alarm0,
        Rng::new(peripherals.RNG),
    );

    unsafe {
        // see https://openthread.io/codelabs/openthread-apis#7

        let instance = otInstanceInitSingle();
        println!("otInstanceInitSingle done....");

        let res = otSetStateChangedCallback(instance, Some(change_callback), core::ptr::null_mut());
        println!("otSetStateChangedCallback {res}");

        let dataset = otOperationalDataset {
            mActiveTimestamp: otTimestamp {
                mSeconds: 1,
                mTicks: 0,
                mAuthoritative: false,
            },
            mPendingTimestamp: otTimestamp {
                mSeconds: 0,
                mTicks: 0,
                mAuthoritative: false,
            },
            mNetworkKey: otNetworkKey {
                m8: [
                    0xfe, 0x04, 0x58, 0xf7, 0xdb, 0x96, 0x35, 0x4e, 0xaa, 0x60, 0x41, 0xb8, 0x80,
                    0xea, 0x9c, 0x0f,
                ],
            },
            mNetworkName: otNetworkName {
                m8: [
                    b'O' as i8, b'p' as i8, b'e' as i8, b'n' as i8, b'T' as i8, b'h' as i8,
                    b'r' as i8, b'e' as i8, b'a' as i8, b'd' as i8, b'-' as i8, b'5' as i8,
                    b'8' as i8, b'd' as i8, b'1' as i8, 0, 0,
                ],
            },
            mExtendedPanId: otExtendedPanId {
                m8: [0x3a, 0x90, 0xe3, 0xa3, 0x19, 0xa9, 0x04, 0x94],
            },
            mMeshLocalPrefix: otMeshLocalPrefix { m8: [0u8; 8] },
            mDelay: 0,
            mPanId: 0x58d1,
            mChannel: 11,
            mPskc: otPskc { m8: [0u8; 16] },
            mSecurityPolicy: otSecurityPolicy {
                mRotationTime: 0,
                _bitfield_align_1: [0u8; 0],
                _bitfield_1: otSecurityPolicy::new_bitfield_1(
                    false, false, false, false, false, false, false, false, false, 0,
                ),
            },
            mChannelMask: 0x07fff800,
            mComponents: otOperationalDatasetComponents {
                _bitfield_align_1: [0u8; 0],
                _bitfield_1: otOperationalDatasetComponents::new_bitfield_1(
                    true, false, true, true, true, false, false, true, true, false, false, false,
                ),
            },
        };

        let res = otDatasetSetActive(instance, &dataset);
        println!("otDatasetSetActive {res}");

        let res = otIp6SetEnabled(instance, true);
        println!("otIp6SetEnabled {res}");

        let res = otThreadSetEnabled(instance, true);
        println!("otThreadSetEnabled {res}");

        print_address(instance);

        loop {
            openthread.process(instance);
            if otTaskletsArePending(instance) {
                otTaskletsProcess(instance);
            }
        }
    }
}

unsafe extern "C" fn change_callback(flags: otChangedFlags, _context: *mut crate::c_types::c_void) {
    println!("change_callback otChangedFlags={:32b}", flags);
}

fn print_address(instance: *mut otInstance) {
    unsafe {
        let mut addr = otIp6GetUnicastAddresses(instance);

        loop {
            let a = &*addr;

            let octets = a.mAddress.mFields.m8;
            if octets[0] == 0xfe && octets[1] == 0x80 {
                print!("Link local address ");
                let mut i = 0;
                for o in octets {
                    print!("{:02x}", o);
                    if i % 2 == 1 && i != 15 {
                        print!(":");
                    }
                    i += 1;
                }
                println!();
            }

            if a.mNext.is_null() {
                break;
            }

            addr = a.mNext;
        }
    }
}
