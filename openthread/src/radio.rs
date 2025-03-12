//! IEEE 802.15.4 PHY Radio trait and associated types for OpenThread.
//!
//! `openthread` operates the radio in terms of this trait, which is implemented by the actual radio driver.

use core::fmt::Debug;
use core::pin::pin;

use bitflags::bitflags;

use embassy_futures::select::{select, Either};
use mac::ACK_PSDU_LEN;

/// The error kind for radio errors.
// TODO: Fill in with extra variants
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RadioErrorKind {
    /// Receiving failed
    RxFailed,
    /// Transmitting failed
    TxFailed,
    /// Receiving failed due to sending an ACK frame failed
    TxAckFailed,
    /// Transmitting failed due to receiving an ACK frame failed
    RxAckFailed,
    /// Transmitting failed due to no ACK received
    RxAckTimeout,
    /// Transmitting failed due to invalid ACK received
    RxAckInvalid,
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
    /// If the radio is not capable of filtering by PAN ID, it should be wrapped with `EnhRadio` with
    /// `FilterPolicy::pan_id` set to `true`.
    pub pan_id: Option<u16>,
    /// Short address filter
    /// If the radio is not capable of filtering by short address, it should be wrapped with `EnhRadio` with
    /// `FilterPolicy::short_addr` set to `true`.
    pub short_addr: Option<u16>,
    /// Extended address filter
    /// If the radio is not capable of filtering by extended address, it should be wrapped with `EnhRadio` with
    /// `FilterPolicy::ext_addr` set to `true`.
    pub ext_addr: Option<u64>,
    /// Receive during idle state
    /// Disregarded if the radio is not capable of receiving during idle state.
    pub rx_when_idle: bool,
}

impl Config {
    /// Create a new default configuration.
    pub const fn new() -> Self {
        Self {
            channel: 15,
            power: 8,
            cca: Cca::Carrier,
            sfd: 0,
            promiscuous: false,
            pan_id: None,
            short_addr: None,
            ext_addr: None,
            rx_when_idle: false,
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
///
/// If the concrete radio trait implementation is NOT capable of sending ACKs for received frames
/// and/or waiting for and processing incoming ACK frames for its transmitted frames, then the implementation
/// should be wrapped in the `EnhRadio` wrapper wuth the appropriate `AckPolicy` passed in so that the
/// ACK handling is done by the `EnhRadio` wrapper.
///
/// If the concrete radio trait implementation is NOT capable of filtering received frames by PAN ID,
/// and/or short address, and/or extended address, then the implementation should be wrapped in the
/// `EnhRadio` wrapper with the appropriate `FilterPolicy::pan_id`, `FilterPolicy::short_addr`, and
/// `FilterPolicy::ext_addr` set to `true` as required.
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

/// An error type for the enhanced radio.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum EnhRadioError<T> {
    /// Receiving failed due to sending an ACK frame failed
    TxAckFailed(T),
    /// Transmitting failed due to receiving an ACK frame failed
    RxAckFailed(T),
    /// Transmitting failed due to no ACK received
    RxAckTimeout,
    /// Transmitting failed due to invalid ACK received
    RxAckInvalid,
    /// Error coming from the wrapped radio
    Io(T),
}

impl<T> RadioError for EnhRadioError<T>
where
    T: RadioError,
{
    fn kind(&self) -> RadioErrorKind {
        match self {
            EnhRadioError::TxAckFailed(_) => RadioErrorKind::TxAckFailed,
            EnhRadioError::RxAckFailed(_) => RadioErrorKind::RxAckFailed,
            EnhRadioError::RxAckTimeout => RadioErrorKind::RxAckTimeout,
            EnhRadioError::RxAckInvalid => RadioErrorKind::RxAckInvalid,
            EnhRadioError::Io(e) => e.kind(),
        }
    }
}

/// A filter policy for the enhanced radio.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct FilterPolicy {
    /// Filter by PAN ID
    pan_id: bool,
    /// Filter by short address
    short_addr: bool,
    /// Filter by extended address
    ext_addr: bool,
}

impl FilterPolicy {
    /// Create a new filter policy which does not filter.
    pub const fn none() -> Self {
        Self {
            pan_id: false,
            short_addr: false,
            ext_addr: false,
        }
    }

    /// Create a new filter policy which filters by all addresses.
    pub const fn all() -> Self {
        Self {
            pan_id: true,
            short_addr: true,
            ext_addr: true,
        }
    }
}

/// An ACK policy for the enhanced radio.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct AckPolicy {
    /// Process ACKs for transmitted frames
    pub tx_ack: bool,
    /// Send ACKs for received frames
    pub rx_ack: bool,
}

impl AckPolicy {
    /// Create a new ACK policy which does not process or send ACKs.
    pub const fn none() -> Self {
        Self {
            tx_ack: false,
            rx_ack: false,
        }
    }

    /// Create a new ACK policy which processes and sends ACKs.
    pub const fn all() -> Self {
        Self {
            tx_ack: true,
            rx_ack: true,
        }
    }
}

/// An enhanced radio that can optionally send and receive ACKs for transmitted frames
/// as well as optionally do address filtering.
pub struct EnhRadio<T> {
    radio: T,
    ack_buf: [u8; ACK_PSDU_LEN],
    ack_policy: AckPolicy,
    filter_policy: FilterPolicy,
    filter_pan_id: Option<u16>,
    filter_short_addr: Option<u16>,
    filter_ext_addr: Option<u64>,
}

impl<T> EnhRadio<T>
where
    T: Radio,
{
    const ACK_WAIT_US: u64 = 190;

    /// Create a new enhanced radio.
    ///
    /// Arguments:
    /// - `radio`: The radio to wrap.
    /// - `ack_policy`: The ACK policy to use.
    /// - `filter_policy`: The filter policy to use.
    pub fn new(radio: T, ack_policy: AckPolicy, filter_policy: FilterPolicy) -> Self {
        Self {
            radio,
            ack_buf: [0; ACK_PSDU_LEN],
            ack_policy,
            filter_policy,
            filter_pan_id: None,
            filter_short_addr: None,
            filter_ext_addr: None,
        }
    }

    fn needs_ack(psdu: &[u8]) -> Result<bool, EnhRadioError<T::Error>> {
        if psdu.len() < mac::ACK_PSDU_LEN {
            Err(EnhRadioError::RxAckInvalid)?;
        }

        Ok(mac::FrameType::get(psdu).needs_ack(mac::FrameVersion::get(psdu)))
    }

    fn fill_ack(psdu: &[u8], ack_buf: &mut [u8]) -> Result<usize, EnhRadioError<T::Error>> {
        if psdu.len() < mac::ACK_PSDU_LEN {
            Err(EnhRadioError::RxAckInvalid)?;
        }

        Ok(mac::fill_ack(psdu, ack_buf))
    }

    fn process_ack(psdu: &[u8]) -> Result<(), EnhRadioError<T::Error>> {
        if psdu.len() < mac::ACK_PSDU_LEN {
            Err(EnhRadioError::RxAckInvalid)?;
        }

        if mac::FrameType::get(psdu) != mac::FrameType::Ack {
            Err(EnhRadioError::RxAckInvalid)?;
        }

        Ok(())
    }
}

impl<T> Radio for EnhRadio<T>
where
    T: Radio,
{
    type Error = EnhRadioError<T::Error>;

    async fn caps(&mut self) -> Capabilities {
        self.radio.caps().await
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.radio
            .set_config(config)
            .await
            .map_err(Self::Error::Io)?;

        if self.filter_policy.pan_id {
            self.filter_pan_id = config.pan_id;
        }

        if self.filter_policy.short_addr {
            self.filter_short_addr = config.short_addr;
        }

        if self.filter_policy.ext_addr {
            self.filter_ext_addr = config.ext_addr;
        }

        Ok(())
    }

    async fn transmit(&mut self, psdu: &[u8]) -> Result<(), Self::Error> {
        self.radio.transmit(psdu).await.map_err(Self::Error::Io)?;

        if self.ack_policy.tx_ack {
            if Self::needs_ack(psdu)? {
                let result = {
                    let mut ack = pin!(self.radio.receive(&mut self.ack_buf));
                    let mut timeout = pin!(embassy_time::Timer::after(
                        embassy_time::Duration::from_micros(Self::ACK_WAIT_US)
                    ));

                    select(&mut ack, &mut timeout).await
                };

                let ack_meta = match result {
                    Either::First(result) => result.map_err(Self::Error::RxAckFailed)?,
                    Either::Second(_) => Err(Self::Error::RxAckTimeout)?,
                };

                Self::process_ack(&self.ack_buf[..ack_meta.len])?;
            }
        }

        Ok(())
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        loop {
            let psdu_meta = self
                .radio
                .receive(psdu_buf)
                .await
                .map_err(Self::Error::Io)?;

            if let Some(pan_id) = self.filter_pan_id.as_ref() {
                if mac::pan_id(psdu_buf) != Some(*pan_id) {
                    continue;
                }
            }

            if let Some(short_addr) = self.filter_short_addr.as_ref() {
                if mac::short_addr(psdu_buf) != Some(*short_addr) {
                    continue;
                }
            }

            if let Some(ext_addr) = self.filter_ext_addr.as_ref() {
                if mac::ext_addr(psdu_buf) != Some(*ext_addr) {
                    continue;
                }
            }

            if self.ack_policy.rx_ack {
                let psdu = &psdu_buf[..psdu_meta.len];

                if Self::needs_ack(psdu)? {
                    let ack_len = Self::fill_ack(psdu, &mut self.ack_buf)?;
                    self.radio
                        .transmit(&self.ack_buf[..ack_len])
                        .await
                        .map_err(Self::Error::TxAckFailed)?;
                }
            }

            break Ok(psdu_meta);
        }
    }
}

/// A minimal set of utilities for working with IEEE 802.15.4 MAC frames
/// so that ACKs can be send or processed.
mod mac {
    pub const ACK_PSDU_LEN: usize = FCF_LEN + SEQ_LEN + CRC_LEN;

    const FCF_LEN: usize = 2;
    const SEQ_LEN: usize = 1;
    const CRC_LEN: usize = 2;

    const FCF_FRAME_VERSION_SHIFT: u16 = 12;
    const FCF_FRAME_VERSION_MASK: u16 = 3 << FCF_FRAME_VERSION_SHIFT;
    const FCF_ACK_MASK: u16 = 2;
    const FCF_PENDING_MASK: u16 = 1 << 4;
    const FCF_HAS_PAN_ID_MASK: u16 = 1 << 6;
    const FCF_HAS_ADDR_MASK: u16 = 1 << 7;
    const FCF_HAS_EXT_ADDR_MASK: u16 = 1 << 8;
    const FCF_FRAME_TYPE_MASK: u16 = 0x07;

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum FrameVersion {
        IEEE802154_2003,
        IEEE802154_2006,
        IEEE802154_2015,
    }

    impl FrameVersion {
        pub fn get(psdu: &[u8]) -> Self {
            match fcf(psdu) >> FCF_FRAME_VERSION_SHIFT {
                0 => FrameVersion::IEEE802154_2003,
                1 => FrameVersion::IEEE802154_2006,
                2 => FrameVersion::IEEE802154_2015,
                _ => unreachable!(),
            }
        }
    }

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub enum FrameType {
        Beacon,
        Data,
        Ack,
        Command,
    }

    impl FrameType {
        pub fn get(psdu: &[u8]) -> Self {
            match fcf(psdu) >> FCF_FRAME_TYPE_MASK {
                0 => FrameType::Beacon,
                1 => FrameType::Data,
                2 => FrameType::Ack,
                3 => FrameType::Command,
                _ => unreachable!(),
            }
        }

        pub fn needs_ack(&self, frame_version: FrameVersion) -> bool {
            matches!(self, FrameType::Data)
                || matches!(frame_version, FrameVersion::IEEE802154_2015)
                    && matches!(self, FrameType::Command)
        }
    }

    pub fn fill_ack(src: &[u8], ack: &mut [u8]) -> usize {
        assert!(src.len() >= ACK_PSDU_LEN);
        assert!(ack.len() >= ACK_PSDU_LEN);

        let src_fcf = fcf(src);
        let src_seq = seq(src);

        let pending = (src_fcf & FCF_PENDING_MASK) != 0;
        let ack_fcf = (src_fcf & FCF_FRAME_VERSION_MASK)
            | FCF_ACK_MASK
            | if pending { FCF_PENDING_MASK } else { 0 };

        ack[0] = ack_fcf.to_le_bytes()[0];
        ack[1] = ack_fcf.to_le_bytes()[1];
        ack[2] = src_seq;

        ACK_PSDU_LEN
    }

    fn fcf(psdu: &[u8]) -> u16 {
        u16::from_le_bytes([psdu[1], psdu[0]])
    }

    fn seq(psdu: &[u8]) -> u8 {
        psdu[2]
    }

    pub fn pan_id(psdu: &[u8]) -> Option<u16> {
        if (fcf(psdu) & FCF_HAS_PAN_ID_MASK) != 0 {
            Some(u16::from_le_bytes([psdu[5], psdu[4]]))
        } else {
            None
        }
    }

    pub fn short_addr(psdu: &[u8]) -> Option<u16> {
        if (fcf(psdu) & FCF_HAS_ADDR_MASK) != 0 {
            Some(u16::from_le_bytes([psdu[7], psdu[6]]))
        } else {
            None
        }
    }

    pub fn ext_addr(psdu: &[u8]) -> Option<u64> {
        if (fcf(psdu) & FCF_HAS_EXT_ADDR_MASK) != 0 {
            Some(u64::from_le_bytes([
                psdu[15], psdu[14], psdu[13], psdu[12], psdu[11], psdu[10], psdu[9], psdu[8],
            ]))
        } else {
            None
        }
    }
}
