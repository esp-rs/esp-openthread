use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use esp_ieee802154::{Error, Ieee802154};

use crate::{Config, PsduMeta, Radio, RadioError};

impl RadioError for Error {
    fn kind(&self) -> crate::RadioErrorKind {
        todo!()
    }
}

pub struct EspRadio<'a>(Ieee802154<'a>, u8);

impl<'a> EspRadio<'a> {
    pub fn new(ieee802154: Ieee802154<'a>) -> Self {
        let mut this = Self(ieee802154, 0);

        this.0.set_rx_available_callback_fn(Self::rx_callback);
        this.0.set_tx_done_callback_fn(Self::tx_callback);

        this
    }

    fn rx_callback() {
        RX_SIGNAL.signal(());
    }

    fn tx_callback() {
        TX_SIGNAL.signal(());
    }
}

impl Radio for EspRadio<'_> {
    type Error = Error;

    async fn caps(&mut self) -> u8 {
        0
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        // TODO self.0.set_config(config)
        Ok(())
    }

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error> {
        TX_SIGNAL.reset();

        self.0.transmit_raw(psdu)?;

        TX_SIGNAL.wait().await;

        Ok(())
    }

    async fn receive(
        &mut self,
        _channel: u8,
        psdu_buf: &mut [u8],
    ) -> Result<PsduMeta, Self::Error> {
        RX_SIGNAL.reset();
        self.0.start_receive();

        let raw = loop {
            if let Some(frame) = self.0.raw_received() {
                break frame;
            }

            RX_SIGNAL.wait().await;
        };

        let len = (raw.data[0] & 0x7f) as usize;
        psdu_buf[..len].copy_from_slice(&raw.data[1..][..len]);

        let rssi = (len + 1 < raw.data.len()).then(|| raw.data[len + 1] as i8);

        Ok(PsduMeta {
            len,
            channel: raw.channel,
            rssi,
        })
    }
}

// Esp chips have a single radio, so having statics for these is OK
static TX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
