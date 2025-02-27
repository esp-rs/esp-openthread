use core::pin::pin;

use embassy_futures::select::{select3, Either3};
use embassy_net_driver_channel::{driver::HardwareAddress, RxRunner, TxRunner};

use rand_core::RngCore;

use crate::{OtController, OtError, OtResources, OtRunner, OtRx, OtTx, Radio};

pub use embassy_net_driver_channel::{
    Device as EnetDriver, State as EnetDriverState, StateRunner as EnetDriverStateRunner,
};

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
    let (ot_controller, ot_rx, ot_tx, ot_runner) = crate::new(rng, resources)?;

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

pub struct EnetRunner<'d, const MTU: usize> {
    rx: OtRx<'d>,
    tx: OtTx<'d>,
    rx_runner: RxRunner<'d, MTU>,
    tx_runner: TxRunner<'d, MTU>,
    ot_runner: OtRunner<'d>,
}

impl<const MTU: usize> EnetRunner<'_, MTU> {
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
