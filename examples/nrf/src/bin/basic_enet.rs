//! Basic example for NRF, demonstrating the integration of `openthread` with `embassy-net`.
//!
//! The example provisions an MTD device with fixed Thread network settings, waits for the device to connect,
//! and then sends and receives Ipv6 UDP packets over the `IEEE 802.15.4` radio.
//!
//! See README.md for instructions on how to configure the other Thread peer (a FTD), using another Esp device.

#![no_std]
#![no_main]

use core::net::Ipv6Addr;

use embassy_executor::Spawner;
use embassy_net::udp::{PacketMetadata, UdpMetadata, UdpSocket};
use embassy_net::{Config, ConfigV6, Ipv6Cidr, Runner, StackResources, StaticConfigV6};

use embassy_nrf::peripherals::{RADIO, RNG};
use embassy_nrf::rng::{self, Rng};
use embassy_nrf::{bind_interrupts, peripherals, radio};

use heapless::Vec;

use log::info;

use {panic_probe as _, rtt_target as _};

use openthread::enet::{self, EnetDriver, EnetRunner};
use openthread::nrf::{Ieee802154, NrfRadio};
use openthread::{
    AckPolicy, EnhRadio, FilterPolicy, OpenThread, OperationalDataset, OtResources, ThreadTimestamp,
};

use rand_core::RngCore;

use rtt_target::rtt_init_log;

use tinyrlibc as _;

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

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    RNG => rng::InterruptHandler<peripherals::RNG>;
});

const BOUND_PORT: u16 = 1212;

const IPV6_PACKET_SIZE: usize = 1280;
const ENET_MAX_SOCKETS: usize = 2;

const LOG_RINGBUF_SIZE: usize = 4096;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;

    let p = embassy_nrf::init(config);

    rtt_init_log!(
        log::LevelFilter::Info,
        rtt_target::ChannelMode::NoBlockSkip,
        LOG_RINGBUF_SIZE
    );

    info!("Starting...");

    let rng = mk_static!(Rng<RNG>, Rng::new(p.RNG, Irqs));
    let enet_seed = rng.next_u64();

    let ot_resources = mk_static!(OtResources, OtResources::new());
    let enet_driver_state =
        mk_static!(enet::EnetDriverState<IPV6_PACKET_SIZE, 1, 1>, enet::EnetDriverState::new());

    let ot = OpenThread::new(rng, ot_resources).unwrap();

    let (_enet_controller, enet_driver_runner, enet_driver) = enet::new(ot, enet_driver_state);

    let radio = EnhRadio::new(
        NrfRadio::new(Ieee802154::new(p.RADIO, Irqs)),
        AckPolicy::all(),
        FilterPolicy::all(),
    );

    info!("Radio created");

    spawner
        .spawn(run_enet_driver(enet_driver_runner, radio))
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

    ot.set_active_dataset(&dataset).unwrap();
    ot.enable_ipv6(true).unwrap();
    ot.enable_thread(true).unwrap();

    loop {
        info!("Waiting to get an IPv6 address from OpenThread...");

        let mut addrs = heapless::Vec::<(Ipv6Addr, u8), 4>::new();
        ot.ipv6_addrs(|addr| {
            if let Some(addr) = addr {
                let _ = addrs.push(addr);
            }

            Ok(())
        })
        .unwrap();

        if !addrs.is_empty() {
            info!("Got IPv6 address(es) from OpenThread: {addrs:?}");

            // NOTE: Ideally, we should track any changes to the OpenThread Ipv6 conf with `ot_controller.wait_changed()`
            // and re-initialize the embassy-net config with the new Ip and prefix.
            let (linklocal_addr, linklocal_prefix) = addrs
                .iter()
                .find(|(addr, _)| addr.is_unicast_link_local())
                .expect("No link-local address found");

            info!("Will bind to link-local {linklocal_addr} Ipv6 addr");

            stack.set_config_v6(ConfigV6::Static(StaticConfigV6 {
                address: Ipv6Cidr::new(*linklocal_addr, *linklocal_prefix),
                gateway: None,           // TODO
                dns_servers: Vec::new(), // TODO
            }));

            break;
        }
    }

    let (mut rx_meta, mut tx_meta) = ([PacketMetadata::EMPTY; 2], [PacketMetadata::EMPTY; 2]);
    let rx_buf = unsafe { mk_static!([u8; IPV6_PACKET_SIZE]).assume_init_mut() };
    let tx_buf = unsafe { mk_static!([u8; IPV6_PACKET_SIZE]).assume_init_mut() };

    let mut socket = UdpSocket::new(stack, &mut rx_meta, rx_buf, &mut tx_meta, tx_buf);

    socket.bind(BOUND_PORT).unwrap();

    info!("Opened socket on port {BOUND_PORT} and waiting for packets...");

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
    radio: EnhRadio<NrfRadio<'static, RADIO>>,
) -> ! {
    runner.run(radio).await
}

#[embassy_executor::task]
async fn run_enet(mut runner: Runner<'static, EnetDriver<'static, IPV6_PACKET_SIZE>>) -> ! {
    runner.run().await
}
