//! An implementation of an OpenThread Driver for `embassy-net` using the `embassy-net-driver-channel` crate.

use core::pin::pin;

use embassy_futures::select::{select3, Either3};
use embassy_net_driver_channel::{driver::HardwareAddress, RxRunner, TxRunner};

use rand_core::RngCore;

use crate::{OpenThread, OtController, OtError, OtResources, OtRunner, OtRx, OtTx, Radio};

pub use embassy_net_driver_channel::{
    Device as EnetDriver, State as EnetDriverState, StateRunner as EnetDriverStateRunner,
};

/// Create a new OpenThread driver for `embassy-net`, by internally instantiating the `openthread` API types
/// and combining them with the `embassy-net-driver-channel` runner types.
///
/// The driver is communicating with `embassy-net` and `smoltcp` using naked Ipv6 frames, without
/// any hardware address and any additional framing (like e.g. Ethernet) attached.
///
/// All details about the network stack (i.e. that it is based on IEEE 802.15.4) are abstracted away and
/// invisible to `embassy-net` and `smoltcp`.
///
/// Arguments:
/// - `rng`: A mutable reference to a random number generator.
/// - `state`: A mutable reference to the `embassy-net-driver-channel` state resources.
/// - `resources`: A mutable reference to the `openthread` resources.
///
/// Returns:
/// - In case there were no errors related to initializing the OpenThread library, a tuple containing:
///   - The OpenThread controller
///   - The `embassy-net-driver-channel` state runner (note: this is not really a "runner" per se, but more of a controller to switch on/off the Driver)
///   - A runner that runs both the `openthread` stack as well as the `embassy-net` driver stack
///   - The `embassy-net` Driver for OpenThread
pub fn new<'d, const MTU: usize, const N_RX: usize, const N_TX: usize>(
    rng: &'d mut dyn RngCore,
    state: &'d mut EnetDriverState<MTU, N_RX, N_TX>,
    resources: &'d mut OtResources,
) -> Result<
    (
        OtController<'d>,
        EnetDriverStateRunner<'d>,
        EnetRunner<'d, MTU>,
        EnetDriver<'d, MTU>,
    ),
    OtError,
> {
    let (ot_controller, ot_rx, ot_tx, ot_runner) = OpenThread::new(rng, resources)?.split();

    let (runner, device) = embassy_net_driver_channel::new(state, HardwareAddress::Ip);

    let (state_runner, rx_runner, tx_runner) = runner.split();

    Ok((
        ot_controller,
        state_runner,
        EnetRunner {
            rx: ot_rx,
            tx: ot_tx,
            rx_runner,
            tx_runner,
            ot_runner,
        },
        device,
    ))
}

/// A runner that runs both the `openthread` stack runner as well as the `embassy-net-driver-channel` runner.
///
/// The runner also does the Ipv6 packets' ingress/egress to/from the `embassy-net` stack and to/from `openthread`.
pub struct EnetRunner<'d, const MTU: usize> {
    rx: OtRx<'d>,
    tx: OtTx<'d>,
    rx_runner: RxRunner<'d, MTU>,
    tx_runner: TxRunner<'d, MTU>,
    ot_runner: OtRunner<'d>,
}

impl<const MTU: usize> EnetRunner<'_, MTU> {
    /// Run the OpenThread stack and the `embassy-net-driver-channel` runner.
    ///
    /// Arguments:
    /// - `radio`: The radio to be used by the OpenThread stack.
    pub async fn run<R>(&mut self, mut radio: R) -> !
    where
        R: Radio,
    {
        let mut rx = pin!(Self::run_rx(&mut self.rx, &mut self.rx_runner));
        let mut tx = pin!(Self::run_tx(&mut self.tx, &mut self.tx_runner));
        let mut ot = pin!(Self::run_ot(&mut self.ot_runner, &mut radio));

        match select3(&mut rx, &mut tx, &mut ot).await {
            Either3::First(r) | Either3::Second(r) | Either3::Third(r) => r,
        }
    }

    async fn run_rx(rx: &mut OtRx<'_>, rx_runner: &mut RxRunner<'_, MTU>) -> ! {
        loop {
            rx.wait_available().await.unwrap();

            let buf = rx_runner.rx_buf().await;

            let len = rx.rx(buf).await.unwrap();

            rx_runner.rx_done(len);
        }
    }

    async fn run_tx(tx: &mut OtTx<'_>, tx_runner: &mut TxRunner<'_, MTU>) -> ! {
        loop {
            tx.wait_available().await.unwrap();

            let buf = tx_runner.tx_buf().await;

            tx.tx(buf).await.unwrap();

            tx_runner.tx_done();
        }
    }

    async fn run_ot<R>(runner: &mut OtRunner<'_>, radio: R) -> !
    where
        R: Radio,
    {
        runner.run(radio).await
    }
}
