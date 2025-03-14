//! IEEE 802.15.4 PHY Radio trait and associated types for OpenThread.
//!
//! `openthread` operates the radio in terms of this trait, which is implemented by the actual radio driver.

use core::fmt::Debug;
use core::future::Future;
use core::iter::repeat_n;
use core::mem::MaybeUninit;
use core::pin::pin;

use bitflags::bitflags;

use embassy_futures::select::{select, Either};

use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::signal::Signal;
use embassy_sync::zerocopy_channel::{Channel, Receiver, Sender};

use embedded_hal_async::delay::DelayNs;

use log::{debug, trace};

use mac::MacFrame;

use crate::sys::OT_RADIO_FRAME_MAX_SIZE;

/// The error kind for radio errors.
// TODO: Fill in with extra variants
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RadioErrorKind {
    /// Invalid TX frame
    TxInvalid,
    /// Invalid RX frame
    RxInvalid,
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

impl RadioError for RadioErrorKind {
    fn kind(&self) -> RadioErrorKind {
        *self
    }
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
        const SLEEP = 0x03;
        /// Radio supports receiving during idle state.
        const RX_WHEN_IDLE = 0x04;
    }
}

bitflags! {
    /// Radio capabilities.
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MacCapabilities: u16 {
        /// Radio supports automatic acknowledgement of TX frames.
        const TX_ACK = 0x01;
        /// Radio sending of ACK frames for received TX frames.
        const RX_ACK = 0x02;
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
    /// Receive during idle state
    /// Disregarded if the radio is not capable of receiving during idle state.
    pub rx_when_idle: bool,
    /// PAN ID filter
    /// Disregarded if the radio is not capable of filtering by PAN ID.
    pub pan_id: Option<u16>,
    /// Short address filter
    /// Disregarded if the radio is not capable of filtering by short address.
    pub short_addr: Option<u16>,
    /// Extended address filter
    /// Disregarded if the radio is not capable of filtering by extended address.
    pub ext_addr: Option<u64>,
}

impl Config {
    /// Create a new default configuration.
    pub const fn new() -> Self {
        Self {
            channel: 11,
            power: 8,
            cca: Cca::Carrier,
            sfd: 0,
            promiscuous: false,
            rx_when_idle: false,
            pan_id: None,
            short_addr: None,
            ext_addr: None,
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
/// While the trait models the PHY layer of the radio, it might implement some "MAC-offloading"
/// capabilities as well - namely - the ability to send and receive ACK frames for transmitted frames,
/// and the ability to filter received frames by PAN ID, short address, and extended address.
///
/// If some of these capabilities are not available, `OpenThread` will emulate those in software.
///
/// The trait is used to abstract the radio hardware and provide a common interface for the radio
/// operations. It needs to support the following operations:
/// - Get the radio capabilities (phy and mac ones)
/// - Set the radio configuration
/// - Transmit a radio frame and (optionally) wait for an ACK frame (if the transmitted frame requires an ACK)
/// - Receive a radio frame and (optionally) send an ACK frame (if the received frame requires an ACK)
/// - Optionally, drop received radio frames if they do not match the filter criteria (PAN ID, short address, extended address)
///
/// The trait is NOT required to support the following operations:
/// - Re-sending a TX frame if the ACK frame was not received; this is done by OpenThread
/// - Dropping a duplicate RX frame; this is done by OpenThread
/// - MAC layer security; this is done by OpenThread
pub trait Radio {
    /// The error type for radio operations.
    type Error: RadioError;

    /// Get the radio capabilities.
    fn caps(&mut self) -> Capabilities;

    /// Get the radio "MAC-offloading" capabilities.
    /// If some of these are missing, `OpenThread` will emulate them in software.
    fn mac_caps(&mut self) -> MacCapabilities;

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
    /// - `ack_psdu_buf`: The buffer to store the received ACK PSDU if the radio is capable of reporting received ACKs.
    ///
    /// Returns:
    /// - The meta-data associated with the received ACK frame if the radio is capable of reporting received ACKs
    ///   and an ACK was expected and received for the transmitted frame.
    async fn transmit(
        &mut self,
        psdu: &[u8],
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduMeta>, Self::Error>;

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

    fn caps(&mut self) -> Capabilities {
        T::caps(self)
    }

    fn mac_caps(&mut self) -> MacCapabilities {
        T::mac_caps(self)
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        T::set_config(self, config).await
    }

    async fn transmit(
        &mut self,
        psdu: &[u8],
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduMeta>, Self::Error> {
        T::transmit(self, psdu, ack_psdu_buf).await
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        T::receive(self, psdu_buf).await
    }
}

/// An error type for the enhanced radio.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MacRadioError<T> {
    /// Invalid TX frame
    TxInvalid,
    /// Invalid RX frame
    RxInvalid,
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

impl<T> RadioError for MacRadioError<T>
where
    T: RadioError,
{
    fn kind(&self) -> RadioErrorKind {
        match self {
            Self::TxInvalid => RadioErrorKind::TxInvalid,
            Self::RxInvalid => RadioErrorKind::RxInvalid,
            Self::RxAckInvalid => RadioErrorKind::RxAckInvalid,
            Self::TxAckFailed(_) => RadioErrorKind::TxAckFailed,
            Self::RxAckFailed(_) => RadioErrorKind::RxAckFailed,
            Self::RxAckTimeout => RadioErrorKind::RxAckTimeout,
            Self::Io(e) => e.kind(),
        }
    }
}

/// An enhanced radio that can optionally send and receive ACKs for transmitted frames
/// as well as optionally do address filtering.
pub(crate) struct MacRadio<T, D> {
    /// The wrapped radio.
    radio: T,
    /// The delay implementation to use.
    /// Necessary for the waiting timeout for a TX ACK to be received
    /// if the `MacRadio` is instructed to receive TX ACKs in software.
    ///
    /// Should be with a high precision of ideally < 10us.
    delay: D,
    /// The buffer for the ACK PSDU, if the `MacRadio` is instructed
    /// to send or receive ACKs in software.
    ack_buf: [u8; MacFrame::ACK_PSDU_LEN],
    /// The PAN ID to filter by, if the filter policy allows it.
    pan_id: Option<u16>,
    /// The short address to filter by, if the filter policy allows it.
    short_addr: Option<u16>,
    /// The extended address to filter by, if the filter policy allows it.
    ext_addr: Option<u64>,
}

impl<T, D> MacRadio<T, D>
where
    T: Radio,
    D: DelayNs,
{
    /// The waiting timeout for a TX ACK to be received.
    /// 190us per spec.
    const ACK_WAIT_US: u32 = 190;

    /// Create a new enhanced radio.
    ///
    /// Arguments:
    /// - `radio`: The radio to wrap.
    /// - `delay`: The delay implementation to use. Should be with a high precision of ideally < 10us
    /// - `ack_policy`: The ACK policy to use.
    /// - `filter_policy`: The filter policy to use.
    pub fn new(radio: T, delay: D) -> Self {
        Self {
            radio,
            delay,
            ack_buf: [0; MacFrame::ACK_PSDU_LEN],
            pan_id: None,
            short_addr: None,
            ext_addr: None,
        }
    }
}

impl<T, D> Radio for MacRadio<T, D>
where
    T: Radio,
    D: DelayNs,
{
    type Error = MacRadioError<T::Error>;

    fn caps(&mut self) -> Capabilities {
        self.radio.caps()
    }

    fn mac_caps(&mut self) -> MacCapabilities {
        self.radio.mac_caps()
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.radio
            .set_config(config)
            .await
            .map_err(Self::Error::Io)?;

        if !self
            .radio
            .mac_caps()
            .contains(MacCapabilities::FILTER_PAN_ID)
        {
            self.pan_id = config.pan_id;
        }

        if !self
            .radio
            .mac_caps()
            .contains(MacCapabilities::FILTER_SHORT_ADDR)
        {
            self.short_addr = config.short_addr;
        }

        if !self
            .radio
            .mac_caps()
            .contains(MacCapabilities::FILTER_EXT_ADDR)
        {
            self.ext_addr = config.ext_addr;
        }

        Ok(())
    }

    async fn transmit(
        &mut self,
        psdu: &[u8],
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduMeta>, Self::Error> {
        if !self.radio.mac_caps().contains(MacCapabilities::TX_ACK)
            && MacFrame::new(psdu)
                .needs_ack()
                .map_err(|_| MacRadioError::TxInvalid)?
        {
            debug!("MacRadio, about to transmit with ACK: {psdu:02x?}");

            self.radio
                .transmit(psdu, None)
                .await
                .map_err(Self::Error::Io)?;

            let result = {
                let mut ack = pin!(self.radio.receive(&mut self.ack_buf));
                let mut timeout = pin!(self.delay.delay_us(Self::ACK_WAIT_US));

                select(&mut ack, &mut timeout).await
            };

            let ack_meta = match result {
                Either::First(result) => result.map_err(Self::Error::RxAckFailed)?,
                Either::Second(_) => {
                    debug!("MacRadio, transmit ACK timeout");

                    Err(Self::Error::RxAckTimeout)?
                }
            };

            let ack_psdu = &self.ack_buf[..ack_meta.len];

            let ack_mac_frame = MacFrame::new(ack_psdu);

            if ack_mac_frame
                .ack_for(MacFrame::new(psdu))
                .map_err(|_| MacRadioError::RxAckInvalid)?
            {
                debug!("MacRadio, received transmit ACK: {ack_psdu:02x?}, meta: {ack_meta:?}");

                if let Some(ack_psdu_buf) = ack_psdu_buf {
                    ack_psdu_buf.copy_from_slice(ack_psdu);
                }

                Ok(Some(ack_meta))
            } else {
                Err(Self::Error::RxAckInvalid)?
            }
        } else {
            self.radio
                .transmit(psdu, ack_psdu_buf)
                .await
                .map_err(Self::Error::Io)
        }
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        loop {
            debug!("MacRadio, about to receive");

            let psdu_meta = self
                .radio
                .receive(psdu_buf)
                .await
                .map_err(Self::Error::Io)?;

            let psdu = &psdu_buf[..psdu_meta.len];

            debug!("MacRadio, received: {psdu:02x?}, meta: {psdu_meta:?}");

            let mac_frame = MacFrame::new(psdu);

            if let Some(pan_id) = self.pan_id.as_ref() {
                if let Some(dst_pan_id) = mac_frame
                    .dst_pan_id()
                    .map_err(|_| MacRadioError::RxInvalid)?
                {
                    if dst_pan_id != *pan_id {
                        debug!("MacRadio filtering, expected Pan ID 0x{pan_id:02x}, got 0x{dst_pan_id:02x}, dropping");
                        continue;
                    }
                }
            }

            if let Some(short_addr) = self.short_addr.as_ref() {
                if let Some(short_dst_addr) = mac_frame
                    .short_dst_addr()
                    .map_err(|_| MacRadioError::RxInvalid)?
                {
                    if short_dst_addr != *short_addr {
                        debug!("MacRadio filtering, expected short address 0x{short_addr:02x}, got 0x{short_dst_addr:02x}, dropping");
                        continue;
                    }
                }
            }

            if let Some(ext_addr) = self.ext_addr.as_ref() {
                if let Some(ext_dst_addr) = mac_frame
                    .ext_dst_addr()
                    .map_err(|_| MacRadioError::RxInvalid)?
                {
                    if ext_dst_addr != *ext_addr {
                        debug!("MacRadio filtering, expected extended address 0x{ext_addr:08x}, got 0x{ext_dst_addr:08x}, dropping");
                        continue;
                    }
                }
            }

            if !self.radio.mac_caps().contains(MacCapabilities::RX_ACK)
                && mac_frame
                    .needs_ack()
                    .map_err(|_| MacRadioError::RxInvalid)?
            {
                let ack_len = mac_frame
                    .fill_ack(&mut self.ack_buf)
                    .map_err(|_| MacRadioError::RxInvalid)?;

                let ack_psdu = &self.ack_buf[..ack_len];
                debug!("MacRadio, about to transmit ACK: {ack_psdu:02x?}");

                self.radio
                    .transmit(ack_psdu, None)
                    .await
                    .map_err(Self::Error::TxAckFailed)?;
            }

            break Ok(psdu_meta);
        }
    }
}

/// The resources for the radio proxy.
pub struct ProxyRadioResources {
    request_buf: MaybeUninit<[ProxyRadioRequest; 1]>,
    response_buf: MaybeUninit<[ProxyRadioResponse; 1]>,
    state: MaybeUninit<ProxyRadioState<'static>>,
}

impl ProxyRadioResources {
    /// Create a new set of radio proxy resources.
    pub const fn new() -> Self {
        Self {
            request_buf: MaybeUninit::uninit(),
            response_buf: MaybeUninit::uninit(),
            state: MaybeUninit::uninit(),
        }
    }
}

impl Default for ProxyRadioResources {
    fn default() -> Self {
        Self::new()
    }
}

/// A type that allows to offload the execution (TX/RX) of the actual PHY `Radio` impl
/// to a separate - possibly higher-priority - executor.
///
/// Running the PHY radio in a separate higher priority executor is particularly desirable in the cases where it
/// cannot do MAC-offloading (ACKs and filtering) in hardware, and hence the `MacRadio` wrapper is used to handle
/// these tasks in software. Due to timing constraints with ACKs and filtering, this task should have a higher
/// priority than all other `OpenThread`-related tasks.
///
/// This is achieved by splitting the radio into two types:
/// - `ProxyRadio`, which is a radio proxy that implements the `Radio` trait and is to be used by the main execution
///   by passing it to `OpenThread::run`
/// - `PhyRadioRunner`, which is `Send` and therefore can be sent to a separate executor - to run the radio.
///   Invoke `PhyRadioRunner::run(<the-phy-radio>, <delay-provider>).await` in that separate executor.
pub struct ProxyRadio<'a> {
    /// The radio capabilities. Should match what the PHY radio reports
    caps: Capabilities,
    /// The request channel to the PHY radio
    request: Sender<'a, CriticalSectionRawMutex, ProxyRadioRequest>,
    /// The response channel from the PHY radio
    response: Receiver<'a, CriticalSectionRawMutex, ProxyRadioResponse>,
    /// The signal to indicate a new request to the PHY radio, so that
    /// the PHY radio can cancel the current request (if any) and start processing the new one
    new_request: &'a Signal<CriticalSectionRawMutex, ()>,
    /// The signal to indicate to us that the PHY radio has started processing the new request
    /// so that we can fill the request and wait for the response
    request_processing_started: &'a Signal<CriticalSectionRawMutex, ()>,
    /// The current radio configuration
    config: Config,
}

impl<'a> ProxyRadio<'a> {
    const INIT_REQUEST: [ProxyRadioRequest; 1] = [ProxyRadioRequest::new()];
    const INIT_RESPONSE: [ProxyRadioResponse; 1] = [ProxyRadioResponse::new()];

    /// Create a new `ProxyRadio` and its `PhyRadioRunner` instances.
    ///
    /// Arguments:
    /// - `caps`: The radio capabilities. Should match the ones of the PHY radio
    /// - `resources`: The radio proxy resources
    pub fn new(
        caps: Capabilities,
        resources: &'a mut ProxyRadioResources,
    ) -> (Self, PhyRadioRunner<'a>) {
        resources.request_buf.write(Self::INIT_REQUEST);
        resources.response_buf.write(Self::INIT_RESPONSE);

        #[allow(clippy::missing_transmute_annotations)]
        resources.state.write(ProxyRadioState::new(
            unsafe { core::mem::transmute(resources.request_buf.assume_init_mut()) },
            unsafe { core::mem::transmute(resources.response_buf.assume_init_mut()) },
        ));

        let state = unsafe { resources.state.assume_init_mut() };

        state.split(caps)
    }

    /// Indicate to the driver that the current requerst (if any) should be cancelled
    /// and start a new one.
    async fn initiate_new_request(&mut self) {
        // NOTE: The sequence of signals amd waits is important here
        // so as not to deadlock

        // Start clean
        self.request_processing_started.reset();

        // Indicate cancellation to the driver
        self.new_request.signal(());

        // Wait for the driver to indicate that the request processing has started
        // The driver should be waiting for the new request at its channel at this point,
        // which is empty because it had cleared it before notifying us
        self.request_processing_started.wait().await;

        // Clear the response channel; the PHY runner is async-locking the request channel
        // first, and only after that - the response channel, so we can be sure that the driver
        // is not waiting on the response channel at this point
        let resp = self.response.try_receive();
        if resp.is_some() {
            self.response.receive_done();
        }
    }
}

impl Radio for ProxyRadio<'_> {
    type Error = RadioErrorKind;

    fn caps(&mut self) -> Capabilities {
        self.caps
    }

    fn mac_caps(&mut self) -> MacCapabilities {
        // ... because the actual PHY radio on the other side
        // of the pipe will be wrapped with `MacRadio` if it cannot do ACKs and filtering in hardware
        MacCapabilities::all()
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        // There is no separate command for updating the configuration
        // The updated configuration is always valid for the next request
        self.config = config.clone();
        Ok(())
    }

    async fn transmit(
        &mut self,
        psdu: &[u8],
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduMeta>, Self::Error> {
        trace!("ProxyRadio, about to transmit: {psdu:02x?}");

        self.initiate_new_request().await;

        {
            let req = self.request.send().await;

            req.tx = true;
            req.config = self.config.clone();
            req.psdu.clear();
            req.psdu.extend_from_slice(psdu).unwrap();

            debug!("ProxyRadio, transmit request sent: {req:?}");

            self.request.send_done();
        }

        trace!("ProxyRadio, waiting for transmit response");

        let resp = self.response.receive().await;

        debug!("ProxyRadio, transmit response received: {resp:?}");

        let psdu_meta = (ack_psdu_buf.is_some() && !resp.psdu.is_empty()).then_some(PsduMeta {
            len: resp.psdu.len(),
            channel: resp.psdu_channel,
            rssi: resp.psdu_rssi,
        });

        if let Some(ack_psdu_buf) = ack_psdu_buf {
            if psdu_meta.is_some() {
                ack_psdu_buf.copy_from_slice(&resp.psdu);
            } else {
                ack_psdu_buf.fill(0);
            }
        }

        let result = resp.result.map(|_| psdu_meta);

        self.response.receive_done();

        result
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduMeta, Self::Error> {
        trace!("ProxyRadio, about to receive");

        self.initiate_new_request().await;

        {
            let req = self.request.send().await;

            req.tx = false;
            req.config = self.config.clone();
            req.psdu.clear();

            debug!("ProxyRadio, receive request sent: {req:?}");

            self.request.send_done();
        }

        trace!("ProxyRadio, waiting for receive response");

        let resp = self.response.receive().await;

        debug!("ProxyRadio, receive response received: {resp:?}");

        match resp.result {
            Ok(()) => {
                let len = resp.psdu.len();
                psdu_buf[..len].copy_from_slice(&resp.psdu);

                let psdu_meta = PsduMeta {
                    len,
                    channel: resp.psdu_channel,
                    rssi: resp.psdu_rssi,
                };

                self.response.receive_done();

                Ok(psdu_meta)
            }
            Err(e) => {
                self.response.receive_done();
                Err(e)
            }
        }
    }
}

/// A type modeling the running of the PHY radio - the other side of the `ProxyRadio` pipe.
pub struct PhyRadioRunner<'a> {
    /// The request channel from the proxy radio
    request: Receiver<'a, CriticalSectionRawMutex, ProxyRadioRequest>,
    /// The response channel to the proxy radio
    response: Sender<'a, CriticalSectionRawMutex, ProxyRadioResponse>,
    /// The signal to indicate a new request from the proxy radio
    /// which means we have to cancel processing the current request (if any)
    new_request: &'a Signal<CriticalSectionRawMutex, ()>,
    /// The signal to indicate the start of a new request processing
    /// to the proxy radio, so that it can fill the request and wait for the response
    request_processing_started: &'a Signal<CriticalSectionRawMutex, ()>,
}

impl PhyRadioRunner<'_> {
    /// Run the PHY radio.
    ///
    /// Arguments:
    /// - `radio`: The PHY radio to run.
    /// - `delay`: The delay implementation to use.
    pub async fn run<T, D>(&mut self, radio: T, delay: D) -> !
    where
        T: Radio,
        D: DelayNs,
    {
        let mut radio = MacRadio::new(radio, delay);

        debug!("PhyRadioRunner, running");

        self.new_request.wait().await;

        loop {
            debug!("PhyRadioRunner, new request received");

            let req = self.request.try_receive();
            if req.is_some() {
                // Make room for the new request
                self.request.receive_done();
            }

            // Indicate to the other end of the pipe the start of a new request processing
            self.request_processing_started.signal(());

            if self.process(&mut radio).await.is_none() {
                // Processing was cancelled by a new request,
                // no need to wait for the next one
                debug!("PhyRadioRunner, processing cancelled");
                continue;
            }

            // Processing was done successfully (meaning, the request was processed and not cancelled)
            // wait for a new one to arrive
            self.new_request.wait().await;
        }
    }

    // Process a single request (TX or RX) by first updating the driver configuration
    // (driver should skip that if the new configuration is the same as the current one),
    // and then transmitting or receiving the frame.
    //
    // Updating the configuration, as well as the TX/RX operation might be cancelled at
    // any moment, if a new request arrives.
    async fn process<T>(&mut self, mut radio: T) -> Option<()>
    where
        T: Radio,
    {
        // Always lock the request first; see `cancel_current_request`
        let request = Self::with_cancel(self.request.receive(), self.new_request).await?;

        let response = Self::with_cancel(self.response.send(), self.new_request).await?;

        debug!("PhyRadioRunner, processing request: {request:?}");

        // Always first set the configuration relevant for the current TX/RX request
        // The PHY driver should have intelligence to skip the configuration update if the new
        // configuration is the same as the current one
        let result = Self::with_cancel(radio.set_config(&request.config), self.new_request)
            .await?
            .map_err(|e| e.kind());

        trace!("PhyRadioRunner, configuration set: {result:?}");

        let result = if result.is_err() {
            // Setting driver configuration resulted in an error, so skip the rest of the processing
            result
        } else {
            response
                .psdu
                .extend(repeat_n(0, response.psdu.capacity() - response.psdu.len()));

            let result = if request.tx {
                // ... as the driver is not oblidged to return the ACK frame
                response.psdu.fill(0);

                Self::with_cancel(
                    radio.transmit(&request.psdu, Some(&mut response.psdu)),
                    self.new_request,
                )
                .await?
                .map_err(|e| e.kind())
            } else {
                Self::with_cancel(radio.receive(&mut response.psdu), self.new_request)
                    .await?
                    .map_err(|e| e.kind())
                    .map(Some)
            };

            if let Ok(Some(psdu_meta)) = &result {
                response.psdu.truncate(psdu_meta.len);
                response.psdu_channel = psdu_meta.channel;
                response.psdu_rssi = psdu_meta.rssi;
            } else {
                // No frame returned, so clear the response fields
                response.psdu.clear();
                response.psdu_channel = 0;
                response.psdu_rssi = None;
            }

            result.map(|_| ())
        };

        response.result = result;

        debug!("PhyRadioRunner, processed response: {response:?}");

        self.request.receive_done();
        self.response.send_done();

        Some(())
    }

    async fn with_cancel<F>(fut: F, cancel: &Signal<impl RawMutex, ()>) -> Option<F::Output>
    where
        F: Future,
    {
        match select(fut, cancel.wait()).await {
            Either::First(result) => Some(result),
            Either::Second(_) => None,
        }
    }
}

// Should be safe because while not (yet) marked formally as such, zerocopy-channel's
// `Receiver` and `Sender` are `Send`, as long as the critical section is `Send` + `Sync`
// (which is the case as we use `CriticalSectionRawMutex`), and the `ProxyRadioRequest` and
// `ProxyRadioResponse` are `Send` (which is the case).
//
// The signals are obviously `Send` + `Sync`.
unsafe impl Send for PhyRadioRunner<'_> {}

const PSDU_LEN: usize = OT_RADIO_FRAME_MAX_SIZE as _;

/// The state of the proxy radio
///
/// This state is borrowed and shared between
/// the two ends of the pipe: the proxy radio, and the PHY radio runner.
struct ProxyRadioState<'a> {
    /// The request channel to the PHY radio
    request: Channel<'a, CriticalSectionRawMutex, ProxyRadioRequest>,
    /// The response channel from the PHY radio
    response: Channel<'a, CriticalSectionRawMutex, ProxyRadioResponse>,
    /// The signal to indicate a new request to the PHY radio
    new_request: Signal<CriticalSectionRawMutex, ()>,
    /// The signal of the PHY radio to indicate the start of a new request processing
    request_processing_started: Signal<CriticalSectionRawMutex, ()>,
}

impl<'a> ProxyRadioState<'a> {
    /// Create a new proxy radio state.
    ///
    /// Arguments:
    /// - `request_buf`: The request buffer
    /// - `response_buf`: The response buffer
    fn new(
        request_buf: &'a mut [ProxyRadioRequest; 1],
        response_buf: &'a mut [ProxyRadioResponse; 1],
    ) -> Self {
        Self {
            request: Channel::new(request_buf),
            response: Channel::new(response_buf),
            new_request: Signal::new(),
            request_processing_started: Signal::new(),
        }
    }

    /// Split the state into the proxy radio and the PHY radio runner.
    fn split(&mut self, caps: Capabilities) -> (ProxyRadio<'_>, PhyRadioRunner<'_>) {
        let (request_sender, request_receiver) = self.request.split();
        let (response_sender, response_receiver) = self.response.split();

        (
            ProxyRadio {
                caps,
                request: request_sender,
                response: response_receiver,
                new_request: &self.new_request,
                request_processing_started: &self.request_processing_started,
                config: Config::new(),
            },
            PhyRadioRunner {
                request: request_receiver,
                response: response_sender,
                new_request: &self.new_request,
                request_processing_started: &self.request_processing_started,
            },
        )
    }
}

/// A proxy radio request.
#[derive(Debug)]
struct ProxyRadioRequest {
    /// Transmit or receive
    tx: bool,
    /// The radio configuration for the TX/RX operation
    config: Config,
    /// The PSDU to transmit for the TX operation
    psdu: heapless::Vec<u8, PSDU_LEN>,
}

impl ProxyRadioRequest {
    /// Create a new empty proxy radio request.
    const fn new() -> Self {
        Self {
            tx: false,
            config: Config::new(),
            psdu: heapless::Vec::new(),
        }
    }
}

/// A proxy radio response.
#[derive(Debug)]
struct ProxyRadioResponse {
    /// The result of the TX/RX operation
    result: Result<(), RadioErrorKind>,
    /// The received PSDU, if the operation was successful:
    /// - For TX: the received ACK PSDU (might be empty)
    /// - For RX: the received frame PSDU
    psdu: heapless::Vec<u8, PSDU_LEN>,
    /// The channel on which the frame was received:
    /// - For TX: the channel on which the ACK frame was received
    /// - For RX: the channel on which the regular frame was received
    psdu_channel: u8,
    /// The RSSI of the received frame, if the radio supports appending it at the end of the frame:
    /// - For TX: the RSSI of the received ACK frame
    /// - For RX: the RSSI of the received frame
    psdu_rssi: Option<i8>,
}

impl ProxyRadioResponse {
    /// Create a new empty proxy radio response.
    const fn new() -> Self {
        Self {
            result: Ok(()),
            psdu: heapless::Vec::new(),
            psdu_channel: 0,
            psdu_rssi: None,
        }
    }
}

/// A minimal set of utilities for working with IEEE 802.15.4 MAC frames
/// so that ACKs can be send or processed.
mod mac {
    use core::ops::Deref;
    use core::slice::SliceIndex;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub enum FrameError {
        FrameTooShort,
    }

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct MacFrame<'a>(&'a [u8]);

    impl<'a> MacFrame<'a> {
        pub const ACK_PSDU_LEN: usize = Self::FCF_LEN + Self::SEQ_LEN + Self::CRC_LEN;

        const FCF_LEN: usize = 2;
        const SEQ_LEN: usize = 1;
        const CRC_LEN: usize = 2;

        const FCF_OFFSET: usize = 0;
        const SEQ_OFFSET: usize = Self::FCF_LEN;
        const ADDRS_OFFSET: usize = Self::SEQ_OFFSET + Self::SEQ_LEN;

        const FCF_FRAME_TYPE_MASK: u16 = 0x07;
        const FCF_FRAME_TYPE_ACK: u16 = 0x02;
        #[allow(unused)]
        const FCF_SECURITY_BIT: u16 = 1 << 3;
        #[allow(unused)]
        const FCF_PENDING_BIT: u16 = 1 << 4;
        const FCF_ACK_REQ_NIT: u16 = 1 << 5;
        #[allow(unused)]
        const FCF_PAN_ID_COMPRESSION_MASK: u16 = 1 << 6;
        const FCF_FRAME_DST_ADDR_MODE_SHIFT: u16 = 10;
        const FCF_FRAME_DST_ADDR_MODE_MASK: u16 = 0x03 << Self::FCF_FRAME_DST_ADDR_MODE_SHIFT;
        const FCF_FRAME_VERSION_SHIFT: u16 = 12;
        const FCF_FRAME_VERSION_MASK: u16 = 0x03 << Self::FCF_FRAME_VERSION_SHIFT;
        #[allow(unused)]
        const FCF_FRAME_SRC_ADDR_MODE_SHIFT: u16 = 14;
        #[allow(unused)]
        const FCF_FRAME_SRC_ADDR_MODE_MASK: u16 = 0x03 << Self::FCF_FRAME_DST_ADDR_MODE_SHIFT;

        pub const fn new(psdu: &'a [u8]) -> Self {
            Self(psdu)
        }

        #[inline(always)]
        pub fn needs_ack(self) -> Result<bool, FrameError> {
            Ok((self.fcf()? & Self::FCF_ACK_REQ_NIT) != 0)
        }

        pub fn fill_ack(self, ack: &mut [u8]) -> Result<usize, FrameError> {
            assert!(ack.len() >= Self::ACK_PSDU_LEN);

            let src_fcf = self.fcf()?;
            let src_seq = self.seq()?;

            let ack_fcf = Self::FCF_FRAME_TYPE_ACK
                | (src_fcf & Self::FCF_FRAME_VERSION_MASK)
                //| (src_fcf & Self::FCF_PENDING_MASK)
                ;

            ack[0] = ack_fcf.to_le_bytes()[0];
            ack[1] = ack_fcf.to_le_bytes()[1];
            ack[2] = src_seq;
            ack[3] = 0; // CRC, will be filled-in by the PHY driver
            ack[4] = 0; // CRC, will be filled-in by the PHY driver

            Ok(Self::ACK_PSDU_LEN)
        }

        pub fn ack_for(&self, orig: MacFrame) -> Result<bool, FrameError> {
            Ok(matches!(FrameType::get(*self)?, FrameType::Ack) && self.seq()? == orig.seq()?)
        }

        #[inline(always)]
        pub fn dst_pan_id(self) -> Result<Option<u16>, FrameError> {
            Ok(if FrameAddrMode::get_dst(self)?.pan_id_present() {
                Some(u16::from_le_bytes(
                    self.get(Self::ADDRS_OFFSET..)?
                        .get(..2)?
                        .0
                        .try_into()
                        .unwrap(),
                ))
            } else {
                None
            })
        }

        #[inline(always)]
        pub fn short_dst_addr(self) -> Result<Option<u16>, FrameError> {
            Ok(if FrameAddrMode::get_dst(self)?.short_addr_present() {
                Some(u16::from_le_bytes(
                    self.get(Self::ADDRS_OFFSET + 2..)?
                        .get(..2)?
                        .0
                        .try_into()
                        .unwrap(),
                ))
            } else {
                None
            })
        }

        #[inline(always)]
        pub fn ext_dst_addr(self) -> Result<Option<u64>, FrameError> {
            Ok(if FrameAddrMode::get_dst(self)?.ext_addr_present() {
                Some(u64::from_le_bytes(
                    self.get(Self::ADDRS_OFFSET + 2..)?
                        .get(..8)?
                        .0
                        .try_into()
                        .unwrap(),
                ))
            } else {
                None
            })
        }

        #[inline(always)]
        fn fcf(&self) -> Result<u16, FrameError> {
            Ok(u16::from_le_bytes(
                self.get(Self::FCF_OFFSET..)?
                    .get(..Self::FCF_LEN)?
                    .0
                    .try_into()
                    .unwrap(),
            ))
        }

        #[inline(always)]
        fn seq(&self) -> Result<u8, FrameError> {
            Ok(self.get(Self::SEQ_OFFSET..)?.get(..Self::SEQ_LEN)?.0[0])
        }

        #[inline(always)]
        fn get<I>(&self, index: I) -> Result<Self, FrameError>
        where
            I: SliceIndex<[u8], Output = [u8]>,
        {
            if let Some(slice) = self.0.get(index) {
                Ok(Self(slice))
            } else {
                Err(FrameError::FrameTooShort)
            }
        }
    }

    impl Deref for MacFrame<'_> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.0
        }
    }

    // #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    // enum FrameVersion {
    //     IEEE802154_2003,
    //     IEEE802154_2006,
    //     IEEE802154_2015,
    //     Other,
    // }

    // impl FrameVersion {
    //     #[inline(always)]
    //     pub fn get(frame: MacFrame) -> Result<Self, FrameError> {
    //         Ok(match (frame.fcf()? & MacFrame::FCF_FRAME_VERSION_MASK) >> MacFrame::FCF_FRAME_VERSION_SHIFT {
    //             0 => Self::IEEE802154_2003,
    //             1 => Self::IEEE802154_2006,
    //             2 => Self::IEEE802154_2015,
    //             _ => Self::Other,
    //         })
    //     }
    // }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    enum FrameType {
        Beacon,
        Data,
        Ack,
        Command,
        Other,
    }

    impl FrameType {
        #[inline(always)]
        pub fn get(frame: MacFrame) -> Result<Self, FrameError> {
            Ok(match frame.fcf()? & MacFrame::FCF_FRAME_TYPE_MASK {
                0 => Self::Beacon,
                1 => Self::Data,
                2 => Self::Ack,
                3 => Self::Command,
                _ => Self::Other,
            })
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    enum FrameAddrMode {
        NotPresent,
        Reserved,
        Short,
        Extended,
    }

    impl FrameAddrMode {
        #[inline(always)]
        pub fn get_dst(frame: MacFrame) -> Result<Self, FrameError> {
            Ok(Self::get(
                (frame.fcf()? & MacFrame::FCF_FRAME_DST_ADDR_MODE_MASK)
                    >> MacFrame::FCF_FRAME_DST_ADDR_MODE_SHIFT,
            ))
        }

        // #[inline(always)]
        // pub const fn len(&self) -> usize {
        //     match self {
        //         Self::NotPresent | Self::Reserved => 0,
        //         Self::Short => 2 + 2,
        //         Self::Extended => 2 + 8,
        //     }
        // }

        #[inline(always)]
        pub const fn pan_id_present(&self) -> bool {
            matches!(self, Self::Short | Self::Extended)
        }

        #[inline(always)]
        pub const fn short_addr_present(&self) -> bool {
            matches!(self, Self::Short)
        }

        #[inline(always)]
        pub const fn ext_addr_present(&self) -> bool {
            matches!(self, Self::Extended)
        }

        #[inline(always)]
        const fn get(num: u16) -> Self {
            match num {
                0 => Self::NotPresent,
                1 => Self::Reserved,
                2 => Self::Short,
                3 => Self::Extended,
                _ => unreachable!(),
            }
        }
    }
}
