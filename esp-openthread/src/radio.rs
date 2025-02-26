use core::fmt::Debug;

use bitflags::bitflags;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RadioErrorKind {
    Other,
}

pub trait RadioError: Debug {
    fn kind(&self) -> RadioErrorKind;
}

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
    CarrierOrEd {
        ed_threshold: u8,
    },
    CarrierAndEd {
        ed_threshold: u8,
    },
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u16 {
        const ENERGY_SCAN = 0x01;
        const PROMISCUOUS = 0x02;
        const SLEEP = 0x04;
        const AUTO_ACK = 0x08;
        const RX_WHEN_IDLE = 0x10;
        const FILTER_SHORT_ADDR = 0x20;
        const FILTER_EXT_ADDR = 0x40;
        const FILTER_PAN_ID = 0x80;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Config {
    pub channel: u8,
    pub power: i8,
    pub cca: Cca,
    pub sfd: u8,

    pub promiscuous: bool,
    pub pan_id: Option<u16>,
    pub short_addr: Option<u16>,
    pub ext_addr: Option<u64>,
    pub rx_when_idle: bool,
    pub auto_ack: bool,
}

impl Config {
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PsduMeta {
    pub len: usize,
    pub channel: u8,
    pub rssi: Option<i8>,
}

pub trait Radio {
    type Error: RadioError;

    async fn caps(&mut self) -> Capabilities;

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

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error>;

    async fn receive(&mut self, channel: u8, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error>;
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

    async fn receive(&mut self, channel: u8, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        T::receive(self, channel, psdu_buf).await
    }
}
