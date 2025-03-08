//! IEEE 802.15.4 PHY Radio trait and associated types for OpenThread.
//!
//! `openthread` operates the radio in terms of this trait, which is implemented by the actual radio driver.

use core::fmt::Debug;

use bitflags::bitflags;

/// The error kind for radio errors.
// TODO: Fill in with extra variants
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RadioErrorKind {
    /// Other radio error
    Other,
}

/// The error type for radio errors.
pub trait RadioError: Debug {
    /// The kind of error.
    fn kind(&self) -> RadioErrorKind;
}

/// Carrier sense or Energy Detection (ED) mode.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Cca {
    /// Carrier sense
    #[default]
    Carrier,
    /// Energy Detection / Energy Above Threshold
    Ed {
        /// Energy measurements above this value mean that the channel is assumed to be busy.
        /// Note the measurement range is 0..0xFF - where 0 means that the received power was
        /// less than 10 dB above the selected receiver sensitivity. This value is not given in dBm,
        /// but can be converted. See the nrf52840 Product Specification Section 6.20.12.4
        /// for details.
        ed_threshold: u8,
    },
    /// Carrier sense or Energy Detection
    CarrierOrEd { ed_threshold: u8 },
    /// Carrier sense and Energy Detection
    CarrierAndEd { ed_threshold: u8 },
}

bitflags! {
    /// Radio capabilities.
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u16 {
        /// Radio supports energy scan.
        const ENERGY_SCAN = 0x01;
        /// Radio supports promiscuous mode.
        const PROMISCUOUS = 0x02;
        /// Radio supports sleep mode.
        const SLEEP = 0x04;
        /// Radio supports automatic acknowledgement of TX and RX frames.
        const AUTO_ACK = 0x08;
        /// Radio supports receiving during idle state.
        const RX_WHEN_IDLE = 0x10;
        /// Radio supports filtering of PHY phrames by their short address in the MAC payload.
        const FILTER_SHORT_ADDR = 0x20;
        /// Radio supports filtering of PHY phrames by their extended address in the MAC payload.
        const FILTER_EXT_ADDR = 0x40;
        /// Radio supports filtering of PHY phrames by their PAN ID in the MAC payload.
        const FILTER_PAN_ID = 0x80;
    }
}

/// Radio configuration.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Config {
    /// Channel number
    pub channel: u8,
    /// Transmit power in dBm
    pub power: i8,
    /// Clear channel assessment (CCA) mode
    pub cca: Cca,
    /// TBD
    pub sfd: u8,
    /// Promiscuous mode (receive all frames regardless of address filtering)
    /// Disregarded if the radio is not capable of operating in promiscuous mode.
    pub promiscuous: bool,
    /// PAN ID filter
    /// Disregarded if the radio is not capable of filtering by PAN ID.
    pub pan_id: Option<u16>,
    /// Short address filter
    /// Disregarded if the radio is not capable of filtering by short address.
    pub short_addr: Option<u16>,
    /// Extended address filter
    /// Disregarded if the radio is not capable of filtering by extended address.
    pub ext_addr: Option<u64>,
    /// Receive during idle state
    /// Disregarded if the radio is not capable of receiving during idle state.
    pub rx_when_idle: bool,
    /// Automatic acknowledgement of received frames processing of transmitted frames' ACKs
    /// Disregarded if the radio is not capable of automatic acknowledgement.
    pub auto_ack: bool,
}

impl Config {
    /// Create a new default configuration.
    pub const fn new() -> Self {
        Self {
            channel: 15,
            power: 10,
            cca: Cca::Carrier,
            sfd: 0,
            promiscuous: false,
            pan_id: None,
            short_addr: None,
            ext_addr: None,
            rx_when_idle: false,
            auto_ack: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Meta-data associated with the received IEEE 802.15.4 frame
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PsduMeta {
    /// Length of the PSDU in the frame
    pub len: usize,
    /// Channel on which the frame was received
    pub channel: u8,
    /// Received Signal Strength Indicator (RSSI) in dBm
    /// (if the radio supports appending it at the end of the frame, or `None` otherwise)
    pub rssi: Option<i8>,
}

/// The IEEE 802.15.4 PHY Radio trait.
pub trait Radio {
    /// The error type for radio operations.
    type Error: RadioError;

    /// Get the radio capabilities.
    async fn caps(&mut self) -> Capabilities;

    /// Set the radio configuration.
    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error>;

    // TODO
    //fn sleep(&mut self);

    // TODO
    //fn rssi(&mut self) -> i8;

    // TODO
    //fn receive_sensitivity(&mut self) -> i8;

    // TODO
    //fn set_enabled(&mut self, enabled: bool) -> Result<(), Self::Error>;

    // TODO
    //fn energy_scan(&mut self, channel: u8, duration: u16) -> Result<(), Self::Error>;

    /// Transmit a radio frame.
    ///
    /// Arguments:
    /// - `psdu`: The PSDU to transmit as part of the frame.
    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error>;

    /// Receive a radio frame.
    ///
    /// Arguments:
    /// - `psdu_buf`: The buffer to store the received PSDU.
    ///
    /// Returns:
    /// - The meta-data associated with the received frame.
    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error>;
}

impl<T> Radio for &mut T
where
    T: Radio,
{
    type Error = T::Error;

    async fn caps(&mut self) -> Capabilities {
        T::caps(self).await
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        T::set_config(self, config).await
    }

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error> {
        T::transmit(self, psdu).await
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        T::receive(self, psdu_buf).await
    }
}
