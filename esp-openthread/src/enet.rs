use embassy_net_driver_channel::{RxRunner, State, TxRunner};

use rand_core::RngCore;

use crate::{OtRx, OtRxPacket, OtTx};

pub fn new<'d, const MTU: usize, const N_RX: usize, const N_TX: usize>(
    state: &'d mut State<MTU, N_RX, N_TX>,
) {
}

pub struct EnetOtRx<'a, const MTU: usize>(RxRunner<'a, MTU>);

impl<'a, const MTU: usize> EnetOtRx<'a, MTU> {
    pub const fn new(rx_runner: RxRunner<'a, MTU>) -> Self {
        Self(rx_runner)
    }
}

impl<'a, const MTU: usize> OtRx for EnetOtRx<'a, MTU> {
    fn rx(&mut self, packet: OtRxPacket) {
        if let Some(buf) = self.0.try_rx_buf() {
            let len = packet.copy_to(buf);

            self.0.rx_done(len);
        }
    }
}

pub async fn enet_tx<C, F, const MTU: usize>(
    mut tx_runner: TxRunner<'_, MTU>,
    mut tx: OtTx<'_, C, F>,
) where
    C: RngCore,
    F: OtRx,
{
    let packet = &*tx_runner.tx_buf().await;

    let _ = tx.tx(packet);

    tx_runner.tx_done();
}
