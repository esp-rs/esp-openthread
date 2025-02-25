//! Most minimal example. See README.md for instructions.

#![no_std]
#![no_main]

use core::cell::RefCell;
use core::pin::pin;

use critical_section::Mutex;
use esp_backtrace as _;
use esp_hal::main;
use esp_hal::rng::Rng;
use esp_hal::timer::systimer::{Alarm, SystemTimer};
use esp_ieee802154::Ieee802154;
use esp_openthread::{NetworkInterfaceUnicastAddress, OperationalDataset, ThreadTimestamp};
use esp_println::println;
use static_cell::StaticCell;

const BOUND_PORT: u16 = 1212;

#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let peripherals = esp_hal::init(esp_hal::Config::default());

    println!("Initializing");

    let radio = peripherals.IEEE802154;
    let mut ieee802154 = Ieee802154::new(radio, peripherals.RADIO_CLK);

    // init timer for otPlatAlarm
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let mut timer = PeriodicTimer::new(systimer.alarm0);
    timer.start(1u64.secs());

    let mut openthread =
        esp_openthread::OpenThread::new(&mut ieee802154, timer, Rng::new(peripherals.RNG));

    let changed = Mutex::new(RefCell::new(false));
    let mut callback = |flags| {
        println!("{:?}", flags);
        critical_section::with(|cs| *changed.borrow_ref_mut(cs) = true);
    };

    openthread.set_change_callback(Some(&mut callback));

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
        network_name: Some("OpenThread-58d1".try_into().unwrap()),
        extended_pan_id: Some([0x3a, 0x90, 0xe3, 0xa3, 0x19, 0xa9, 0x04, 0x94]),
        pan_id: Some(0x58d1),
        channel: Some(11),
        channel_mask: Some(0x07fff800),
        ..OperationalDataset::default()
    };
    println!("dataset : {:?}", dataset);

    openthread.set_active_dataset(dataset).unwrap();

    openthread.ipv6_set_enabled(true).unwrap();

    openthread.thread_set_enabled(true).unwrap();

    let addrs: heapless::Vec<NetworkInterfaceUnicastAddress, 5> =
        openthread.ipv6_get_unicast_addresses();

    print_all_addresses(addrs);

    let mut socket = openthread.get_udp_socket::<512>().unwrap();
    let mut socket = pin!(socket);
    socket.bind(BOUND_PORT).unwrap();

    let mut buffer = [0u8; 512];

    loop {
        openthread.process();
        openthread.run_tasklets();
        let (len, from, port) = socket.receive(&mut buffer).unwrap();
        if len > 0 {
            println!(
                "received {:02x?} from {:?} port {}",
                &buffer[..len],
                from,
                port
            );

            socket.send(from, BOUND_PORT, b"Hello").unwrap();
            println!("Sent message");
        }

        critical_section::with(|cs| {
            let mut c = changed.borrow_ref_mut(cs);
            if *c {
                let addrs: heapless::Vec<NetworkInterfaceUnicastAddress, 5> =
                    openthread.ipv6_get_unicast_addresses();

                print_all_addresses(addrs);
                *c = false;
            }
        });
    }
}

fn print_all_addresses(addrs: heapless::Vec<NetworkInterfaceUnicastAddress, 5>) {
    println!("Currently assigned addresses");
    for addr in addrs {
        println!("{}", addr.address);
    }
    println!();
}
