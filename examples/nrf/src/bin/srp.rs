//! An example for NRF, demonstrating the usage of OpenThread native UDP sockets as well as the SRP API.
//!
//! The example provisions an MTD device with fixed Thread network settings, waits for the device to connect,
//! and then sends and receives Ipv6 UDP packets over the `IEEE 802.15.4` radio.
//!
//! The example also registers the MTD device under the hostname `srp-example` and should thus be pingable as `srp-example.local`
//! from your Wifi/Ethernet network, as long as you are running the other thread peer as a Thread Border Router (see below).
//!
//! See README.md for instructions on how to configure the other Thread peer (a FTD), using another Esp device.

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

use openthread::nrf::{Ieee802154, NrfRadio};
use openthread::{
    OpenThread, OperationalDataset, OtResources, OtSrpResources, OtUdpResources, PhyRadioRunner,
    ProxyRadio, ProxyRadioResources, Radio, SrpConf, ThreadTimestamp, UdpSocket,
};

use panic_rtt_target as _;

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
unsafe fn EGU0_SWI0() {
    EXECUTOR_HIGH.on_interrupt()
}

static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

const BOUND_PORT: u16 = 1212;

const UDP_SOCKETS_BUF: usize = 1280;
const UDP_MAX_SOCKETS: usize = 2;

const SRP_SERVICE_BUF: usize = 300;
const SRP_MAX_SERVICES: usize = 2;

const LOG_RINGBUF_SIZE: usize = 4096;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;

    let p = embassy_nrf::init(config);

    rtt_target::rtt_init_log!(
        log::LevelFilter::Info,
        rtt_target::ChannelMode::NoBlockSkip,
        LOG_RINGBUF_SIZE
    );

    info!("Starting...");

    let rng = mk_static!(Rng<RNG>, Rng::new(p.RNG, Irqs));

    let ot_resources = mk_static!(OtResources, OtResources::new());
    let ot_udp_resources =
        mk_static!(OtUdpResources<UDP_MAX_SOCKETS, UDP_SOCKETS_BUF>, OtUdpResources::new());
    let ot_srp_resources =
        mk_static!(OtSrpResources<SRP_MAX_SERVICES, SRP_SERVICE_BUF>, OtSrpResources::new());

    let ot = OpenThread::new_with_udp_srp(rng, ot_resources, ot_udp_resources, ot_srp_resources)
        .unwrap();

    info!("About to spawn OT runner");

    let mut radio = NrfRadio::new(Ieee802154::new(p.RADIO, Irqs));

    let proxy_radio_resources = mk_static!(ProxyRadioResources, ProxyRadioResources::new());
    let (proxy_radio, phy_radio_runner) = ProxyRadio::new(radio.caps(), proxy_radio_resources);

    // High-priority executor: EGU0_SWI0, priority level 7
    interrupt::EGU0_SWI0.set_priority(Priority::P7);

    let spawner_high = EXECUTOR_HIGH.start(interrupt::EGU0_SWI0);
    spawner_high
        .spawn(run_radio(phy_radio_runner, radio))
        .unwrap();

    info!("Radio created");

    spawner.spawn(run_ot(ot, proxy_radio)).unwrap();

    spawner.spawn(run_ot_info(ot)).unwrap();

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

    ot.srp_set_conf(&SrpConf {
        host_name: "srp-example",
        ..SrpConf::new()
    })
    .unwrap();

    ot.srp_autostart().unwrap();

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
async fn run_ot_info(ot: OpenThread<'static>) -> ! {
    let mut cur_state = None;
    let mut cur_server_addr = None;

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

        let mut state = cur_state;
        let server_addr = ot.srp_server_addr().unwrap();

        ot.srp_conf(|_, new_state| {
            state = Some(new_state);
            Ok(())
        })
        .unwrap();

        if cur_addrs != addrs || cur_state != state || cur_server_addr != server_addr {
            info!("Got new IPv6 address(es) and/or SRP state from OpenThread:\nIP addrs: {addrs:?}\nSRP state: {state:?}\nSRP server addr: {server_addr:?}");

            cur_addrs = addrs;
            cur_state = state;
            cur_server_addr = server_addr;

            info!("Waiting for OpenThread changes signal...");
        }

        ot.wait_changed().await;
    }
}

#[embassy_executor::task]
async fn run_radio(mut runner: PhyRadioRunner<'static>, radio: NrfRadio<'static, RADIO>) -> ! {
    runner
        .run(
            radio,
            embassy_time::Delay, /*TODO: Likely not precise enough*/
        )
        .await
}
