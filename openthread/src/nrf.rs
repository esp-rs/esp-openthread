//! `Radio` trait implementation for the `embassy-nrf` ESP IEEE 802.15.4 radio.

use log::{debug, trace};

pub use embassy_nrf::radio::ieee802154::{Cca as RadioCca, Packet};

use crate::{Capabilities, Cca, Config, PsduMeta, Radio, RadioError, RadioErrorKind};

pub use embassy_nrf::radio::ieee802154::Radio as Ieee802154;
pub use embassy_nrf::radio::{Error, Instance as Ieee802154Peripheral};

impl RadioError for Error {
    fn kind(&self) -> RadioErrorKind {
        // TODO
        RadioErrorKind::Other
    }
}

/// The `esp-hal` ESP IEEE 802.15.4 radio.
pub struct NrfRadio<'a, T>
where
    T: Ieee802154Peripheral,
{
    driver: Ieee802154<'a, T>,
    config: Config,
}

impl<'a, T> NrfRadio<'a, T>
where
    T: Ieee802154Peripheral,
{
    const DEFAULT_CONFIG: Config = Config::new();

    /// Create a new `EspRadio` instance.
    pub fn new(radio: Ieee802154<'a, T>) -> Self {
        let mut this = Self {
            driver: radio,
            config: Self::DEFAULT_CONFIG,
        };

        this.update_driver_config();

        this
    }

    fn update_driver_config(&mut self) {
        let config = &self.config;

        self.driver.set_channel(config.channel);
        self.driver.set_cca(match config.cca {
            Cca::Carrier => RadioCca::CarrierSense,
            Cca::Ed { ed_threshold } => RadioCca::EnergyDetection { ed_threshold },
            Cca::CarrierAndEd { ed_threshold } => RadioCca::EnergyDetection { ed_threshold },
            Cca::CarrierOrEd { ed_threshold } => RadioCca::EnergyDetection { ed_threshold },
        });
        self.driver.set_transmission_power(config.power);
    }
}

impl<T> Radio for NrfRadio<'_, T>
where
    T: Ieee802154Peripheral,
{
    type Error = Error;

    async fn caps(&mut self) -> Capabilities {
        Capabilities::AUTO_ACK | Capabilities::RX_WHEN_IDLE
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        if self.config != *config {
            debug!("Setting radio config: {config:?}");

            self.config = config.clone();
            self.update_driver_config();
        }

        Ok(())
    }

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error> {
        debug!("NRF Radio, about to transmit: {psdu:02x?}");

        let mut packet = Packet::new();
        // TODO: CRC mismatch between what OT gives and what NRF expects
        packet.copy_from_slice(&psdu[..psdu.len() - 2]);

        self.driver.try_send(&mut packet).await?;

        trace!("NRF Radio, transmission done");

        Ok(())
    }

    // TODO: For NRF, need to implement software ACK for received frames
    // as this is not supported imn hardware.
    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        trace!("NRF Radio, about to receive");

        let channel = self.config.channel;

        let mut packet = Packet::new();

        self.driver.receive(&mut packet).await?;

        let len = (packet.len()) as _;
        psdu_buf[..len].copy_from_slice(&packet);

        debug!("NRF Radio, received: {:02x?}", &psdu_buf[..len]);

        let lqi = packet.lqi();
        let rssi = lqi as _; // TODO: Convert LQI to RSSI

        Ok(PsduMeta {
            // TODO: CRC mismatch between what NRF gives and what OT expects
            len: len + 2,
            channel,
            rssi: Some(rssi),
        })
    }
}
