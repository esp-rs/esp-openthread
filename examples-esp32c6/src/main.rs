//! Most minimal example. See README.md for instructions.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_ieee802154::Ieee802154;
use esp_openthread::NetworkInterfaceUnicastAddress;
use esp_openthread::OperationalDataset;
use esp_openthread::ThreadTimestamp;
use esp_println::println;
use hal::{clock::ClockControl, peripherals::Peripherals, prelude::*, systimer, Rng};

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let _clocks = ClockControl::boot_defaults(system.clock_control).freeze();

    println!("Initializing");

    let systimer = systimer::SystemTimer::new(peripherals.SYSTIMER);
    let radio = peripherals.IEEE802154;
    let mut ieee802154 = Ieee802154::new(radio, &mut system.radio_clock_control);
    let mut openthread = esp_openthread::OpenThread::new(
        &mut ieee802154,
        systimer.alarm0,
        Rng::new(peripherals.RNG),
    );

    let mut callback = |flags| println!("{:?}", flags);
    openthread.set_change_callback(Some(&mut callback));

    // see https://openthread.io/codelabs/openthread-apis#7

    let dataset = OperationalDataset {
        active_timestamp: Some(ThreadTimestamp {
            seconds: 1,
            ticks: 0,
            authoritative: false,
        }),
        network_key: Some([
            0xfe, 0x04, 0x58, 0xf7, 0xdb, 0x96, 0x35, 0x4e, 0xaa, 0x60, 0x41, 0xb8, 0x80, 0xea,
            0x9c, 0x0f,
        ]),
        network_name: Some(heapless::String::from("OpenThread-58d1")),
        extended_pan_id: Some([0x3a, 0x90, 0xe3, 0xa3, 0x19, 0xa9, 0x04, 0x94]),
        pan_id: Some(0x58d1),

        ..OperationalDataset::default()
    };
    openthread.set_active_dataset(dataset).unwrap();

    openthread.ipv6_set_enabled(true).unwrap();

    openthread.thread_set_enabled(true).unwrap();

    let addrs: heapless::Vec<NetworkInterfaceUnicastAddress, 5> =
        openthread.ipv6_get_unicast_addresses();

    print_link_local_address(addrs);

    loop {
        openthread.process();
        openthread.run_tasklets();
    }
}

fn print_link_local_address(addrs: heapless::Vec<NetworkInterfaceUnicastAddress, 5>) {
    for addr in addrs {
        if addr.address.segments()[0] == 0xfe80 {
            println!("{}", addr.address);
        }
    }
}
