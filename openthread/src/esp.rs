//! `Radio` trait implementation for the `esp-hal` ESP IEEE 802.15.4 radio.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

use esp_ieee802154::{Config as EspConfig, Error, Ieee802154};

use crate::{Capabilities, Cca, Config, PsduMeta, Radio, RadioError, RadioErrorKind};

impl RadioError for Error {
    fn kind(&self) -> RadioErrorKind {
        // TODO
        RadioErrorKind::Other
    }
}

/// The `esp-hal` ESP IEEE 802.15.4 radio.
pub struct EspRadio<'a> {
    driver: Ieee802154<'a>,
    config: Config,
}

impl<'a> EspRadio<'a> {
    const DEFAULT_CONFIG: Config = Config::new();

    /// Create a new `EspRadio` instance.
    pub fn new(ieee802154: Ieee802154<'a>) -> Self {
        let mut this = Self {
            driver: ieee802154,
            config: Self::DEFAULT_CONFIG,
        };

        this.driver.set_rx_available_callback_fn(Self::rx_callback);
        this.driver.set_tx_done_callback_fn(Self::tx_callback);

        this.update_driver_config();

        this
    }

    fn update_driver_config(&mut self) {
        let config = &self.config;

        let esp_config = EspConfig {
            auto_ack_tx: config.auto_ack,
            auto_ack_rx: config.auto_ack,
            enhance_ack_tx: config.auto_ack,
            promiscuous: config.promiscuous,
            coordinator: false,
            rx_when_idle: config.rx_when_idle,
            txpower: config.power,
            channel: config.channel,
            cca_threshold: match config.cca {
                Cca::Carrier => 0,
                Cca::Ed { ed_threshold } => ed_threshold as _,
                Cca::CarrierAndEd { ed_threshold } => ed_threshold as _,
                Cca::CarrierOrEd { ed_threshold } => ed_threshold as _,
            },
            cca_mode: match config.cca {
                Cca::Carrier => esp_ieee802154::CcaMode::Carrier,
                Cca::Ed { .. } => esp_ieee802154::CcaMode::Ed,
                Cca::CarrierAndEd { .. } => esp_ieee802154::CcaMode::CarrierAndEd,
                Cca::CarrierOrEd { .. } => esp_ieee802154::CcaMode::CarrierOrEd,
            },
            pan_id: config.pan_id,
            short_addr: config.short_addr,
            ext_addr: config.ext_addr,
        };

        self.driver.set_config(esp_config);
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

    async fn caps(&mut self) -> Capabilities {
        Capabilities::AUTO_ACK | Capabilities::FILTER_EXT_ADDR | Capabilities::RX_WHEN_IDLE
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.config = config.clone();
        self.update_driver_config();

        Ok(())
    }

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error> {
        TX_SIGNAL.reset();

        self.driver.transmit_raw(psdu)?;

        TX_SIGNAL.wait().await;

        Ok(())
    }

    async fn receive(&mut self, channel: u8, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        if channel != self.config.channel {
            self.config.channel = channel;
            self.update_driver_config();
        }

        RX_SIGNAL.reset();
        self.driver.start_receive();

        let raw = loop {
            if let Some(frame) = self.driver.raw_received() {
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
