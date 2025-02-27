//! Most minimal example. See README.md for instructions.

#![no_std]
#![no_main]

use core::net::Ipv6Addr;

use embassy_executor::Spawner;
use embassy_net::udp::{PacketMetadata, UdpMetadata, UdpSocket};
use embassy_net::{Config, Runner, StackResources};

use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_ieee802154::Ieee802154;

use esp_openthread::enet::{self, EnetDriver, EnetRunner};
use esp_openthread::esp::EspRadio;
use esp_openthread::{OperationalDataset, OtResources, ThreadTimestamp};

use log::info;

use rand_core::RngCore;

macro_rules! mk_static {
    ($t:ty) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit();
        x
    }};
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

const BOUND_PORT: u16 = 1212;

const IPV6_PACKET_SIZE: usize = 1280;
const ENET_MAX_SOCKETS: usize = 2;

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let rng = mk_static!(Rng, Rng::new(peripherals.RNG));
    let ot_resources = mk_static!(OtResources, OtResources::new());
    let enet_driver_state =
        mk_static!(enet::EnetDriverState<IPV6_PACKET_SIZE, 1, 1>, enet::EnetDriverState::new());

    let enet_seed = rng.next_u64();

    let (mut ot_controller, _enet_controller, enet_driver_runner, enet_driver) =
        enet::new(rng, enet_driver_state, ot_resources).unwrap();

    spawner
        .spawn(run_enet_driver(
            enet_driver_runner,
            EspRadio::new(Ieee802154::new(
                peripherals.IEEE802154,
                peripherals.RADIO_CLK,
            )),
        ))
        .unwrap();

    let enet_resources = mk_static!(StackResources<ENET_MAX_SOCKETS>, StackResources::new());

    let (stack, enet_runner) =
        embassy_net::new(enet_driver, Config::default(), enet_resources, enet_seed);

    spawner.spawn(run_enet(enet_runner)).unwrap();

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
        network_name: Some("OpenThread-58d1"),
        extended_pan_id: Some([0x3a, 0x90, 0xe3, 0xa3, 0x19, 0xa9, 0x04, 0x94]),
        pan_id: Some(0x58d1),
        channel: Some(11),
        channel_mask: Some(0x07fff800),
        ..OperationalDataset::default()
    };
    info!("Dataset: {:?}", dataset);

    ot_controller.set_dataset(&dataset).unwrap();
    ot_controller.enable_ipv6(true).unwrap();
    ot_controller.enable_thread(true).unwrap();

    loop {
        info!("Waiting to get an IPv6 address from OpenThread...");

        let mut addrs = [Ipv6Addr::UNSPECIFIED; 4];

        let addrs_len = ot_controller.ipv6_addrs(&mut addrs).unwrap();
        if addrs_len > 0 {
            info!(
                "Got IPv6 address(es) from OpenThread: {:?}",
                &addrs[..addrs_len]
            );
            break;
        }
    }

    let (mut rx_meta, mut tx_meta) = ([PacketMetadata::EMPTY; 2], [PacketMetadata::EMPTY; 2]);
    let rx_buf = unsafe { mk_static!([u8; IPV6_PACKET_SIZE]).assume_init_mut() };
    let tx_buf = unsafe { mk_static!([u8; IPV6_PACKET_SIZE]).assume_init_mut() };

    let mut socket = UdpSocket::new(stack, &mut rx_meta, rx_buf, &mut tx_meta, tx_buf);

    socket.bind(BOUND_PORT).unwrap();

    let buf: &mut [u8] = unsafe { mk_static!([u8; IPV6_PACKET_SIZE]).assume_init_mut() };

    loop {
        let (
            len,
            UdpMetadata {
                endpoint,
                local_address,
                ..
            },
        ) = socket.recv_from(buf).await.unwrap();

        info!(
            "Got {:02x?} from {} on {:?}",
            &buf[..len],
            endpoint,
            local_address
        );

        socket.send_to(b"Hello", endpoint).await.unwrap();
        info!("Sent `b\"Hello\"`");
    }
}

#[embassy_executor::task]
async fn run_enet_driver(
    mut runner: EnetRunner<'static, IPV6_PACKET_SIZE>,
    radio: EspRadio<'static>,
) -> ! {
    runner.run(radio).await
}

#[embassy_executor::task]
async fn run_enet(mut runner: Runner<'static, EnetDriver<'static, IPV6_PACKET_SIZE>>) -> ! {
    runner.run().await
}
