//! Basic example for NRF, demonstrating the usage of OpenThread native UDP sockets.
//!
//! The example provisions an MTD device with fixed Thread network settings, waits for the device to connect,
//! and then sends and receives Ipv6 UDP packets over the `IEEE 802.15.4` radio.
//!
//! See README.md for instructions on how to configure the other Thread peer (a FTD), using an Esp device.

#![no_std]
#![no_main]

use core::net::{Ipv6Addr, SocketAddrV6};

use embassy_executor::InterruptExecutor;
use embassy_executor::Spawner;

use embassy_nrf::interrupt;
use embassy_nrf::interrupt::{InterruptExt, Priority};
use embassy_nrf::peripherals::{RADIO, RNG};
use embassy_nrf::rng::{self, Rng};
use embassy_nrf::{bind_interrupts, peripherals, radio};

use log::info;

use panic_probe as _;

use openthread::nrf::{Ieee802154, NrfRadio};
use openthread::{
    AckPolicy, Capabilities, EnhRadio, FilterPolicy, OpenThread, OperationalDataset, OtResources,
    OtUdpResources, PhyRadioRunner, ProxyRadio, ProxyRadioResources, ThreadTimestamp, UdpSocket,
};

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

#[interrupt]
unsafe fn EGU1_SWI1() {
    EXECUTOR_HIGH.on_interrupt()
}

static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

const BOUND_PORT: u16 = 1212;

const UDP_SOCKETS_BUF: usize = 1280;
const UDP_MAX_SOCKETS: usize = 2;

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

    let ot_resources = mk_static!(OtResources, OtResources::new());
    let ot_udp_resources =
        mk_static!(OtUdpResources<UDP_MAX_SOCKETS, UDP_SOCKETS_BUF>, OtUdpResources::new());

    let ot = OpenThread::new_with_udp(rng, ot_resources, ot_udp_resources).unwrap();

    info!("About to spawn OT runner");

    let proxy_radio_resources = mk_static!(ProxyRadioResources, ProxyRadioResources::new());
    let (proxy_radio, phy_radio_runner) =
        ProxyRadio::new(Capabilities::empty(), proxy_radio_resources);

    let radio = EnhRadio::new(
        NrfRadio::new(Ieee802154::new(p.RADIO, Irqs)),
        embassy_time::Delay,
        AckPolicy::all(),
        FilterPolicy::all(),
    );

    // High-priority executor: EGU1_SWI1, priority level 6
    interrupt::EGU1_SWI1.set_priority(Priority::P6);

    let spawner_high = EXECUTOR_HIGH.start(interrupt::EGU1_SWI1);
    spawner_high
        .spawn(run_radio(phy_radio_runner, radio))
        .unwrap();

    info!("Radio created");

    spawner.spawn(run_ot(ot, proxy_radio)).unwrap();

    info!("About to spawn OT IP info");

    spawner.spawn(run_ot_ip_info(ot)).unwrap();

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

    let socket = UdpSocket::bind(
        ot,
        &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BOUND_PORT, 0, 0),
    )
    .unwrap();

    info!("Opened socket on port {BOUND_PORT} and waiting for packets...");

    let buf: &mut [u8] = unsafe { mk_static!([u8; UDP_SOCKETS_BUF]).assume_init_mut() };

    loop {
        let (len, local, remote) = socket.recv(buf).await.unwrap();

        info!("Got {:02x?} from {remote} on {local}", &buf[..len]);

        socket.send(b"Hello", Some(&local), &remote).await.unwrap();
        info!("Sent `b\"Hello\"`");
    }
}

#[embassy_executor::task]
async fn run_ot(ot: OpenThread<'static>, radio: ProxyRadio<'static>) -> ! {
    ot.run(radio).await
}

#[embassy_executor::task]
async fn run_radio(
    mut runner: PhyRadioRunner<'static>,
    radio: EnhRadio<NrfRadio<'static, RADIO>, embassy_time::Delay>,
) -> ! {
    runner.run(radio).await
}

#[embassy_executor::task]
async fn run_ot_ip_info(ot: OpenThread<'static>) -> ! {
    let mut cur_addrs = heapless::Vec::<(Ipv6Addr, u8), 4>::new();

    loop {
        let mut addrs = heapless::Vec::<(Ipv6Addr, u8), 4>::new();
        ot.ipv6_addrs(|addr| {
            if let Some(addr) = addr {
                let _ = addrs.push(addr);
            }

            Ok(())
        })
        .unwrap();

        if cur_addrs != addrs {
            info!("Got new IPv6 address(es) from OpenThread: {addrs:?}");

            cur_addrs = addrs;

            info!("Waiting for OpenThread changes signal...");
        }

        ot.wait_changed().await;
    }
}
