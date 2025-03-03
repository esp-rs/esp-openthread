//! A safe API for OpenThread (`openthread-sys`)

#![no_std]
#![allow(async_fn_in_trait)]

use core::cell::{RefCell, RefMut};
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::net::Ipv6Addr;
use core::pin::pin;
use core::ptr::addr_of_mut;

use embassy_futures::select::{Either, Either3};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};

use embassy_time::Instant;

use log::{debug, info, trace, warn};

use platform::OT_ACTIVE_STATE;

use rand_core::RngCore;

pub use dataset::*;
pub use openthread_sys as sys;
pub use radio::*;
pub use udp::*;

mod dataset;
#[cfg(feature = "embassy-net-driver-channel")]
pub mod enet;
#[cfg(any(feature = "esp32h2", feature = "esp32c6"))]
pub mod esp;
mod platform;
mod radio;
#[cfg(feature = "srp-client")]
mod srp_client;
mod udp;

use sys::{
    otChangedFlags, otDatasetSetActive, otError, otError_OT_ERROR_DROP, otError_OT_ERROR_FAILED,
    otError_OT_ERROR_NONE, otError_OT_ERROR_NO_BUFS, otInstance, otInstanceInitSingle,
    otIp6GetUnicastAddresses, otIp6NewMessageFromBuffer, otIp6Send, otIp6SetEnabled,
    otIp6SetReceiveCallback, otMessage, otMessageFree,
    otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL, otMessageRead, otMessageSettings,
    otOperationalDataset, otPlatAlarmMilliFired, otPlatRadioEnergyScanDone, otPlatRadioReceiveDone,
    otPlatRadioTxDone, otPlatRadioTxStarted, otRadioFrame, otSetStateChangedCallback,
    otTaskletsProcess, otThreadSetEnabled, OT_RADIO_FRAME_MAX_SIZE,
};

/// A newtype wrapper over the native OpenThread error type (`otError`).
///
/// This type is used to represent errors that can occur when interacting with the OpenThread library.
///
/// Brings extra ergonomics to the error handling, by providing a more Rust-like API.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtError(otError);

impl OtError {
    /// Create a new `OtError` from a raw `otError` value.
    pub const fn new(value: otError) -> Self {
        Self(value)
    }

    /// Convert to the raw `otError` value.
    pub fn into_inner(self) -> otError {
        self.0
    }
}

impl From<u32> for OtError {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// A macro for converting an `otError` value to a `Result<(), OtError>` value.
macro_rules! ot {
    ($code: expr) => {{
        match $code {
            $crate::sys::otError_OT_ERROR_NONE => Ok(()),
            err => Err($crate::OtError::new(err)),
        }
    }};
}

/// An extension trait for converting a `Result<(), OtError>` to a raw `otError` OpenThread error code.
pub trait IntoOtCode {
    /// Convert the `Result<(), OtError>` to a raw `otError` OpenThread error code.
    fn into_ot_code(self) -> otError;
}

impl IntoOtCode for Result<(), OtError> {
    fn into_ot_code(self) -> otError {
        match self {
            Ok(_) => otError_OT_ERROR_NONE,
            Err(e) => e.into_inner(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct OpenThread<'a>(&'a OtState<'static>);

impl<'a> OpenThread<'a> {
    pub fn new<const N: usize>(
        rng: &'a mut dyn RngCore,
        resources: &'a mut OtResources<N>,
    ) -> Result<Self, OtError> {
        // Needed so that we convert from the the actual `'a` lifetime of `rng` to the fake `'static` lifetime in `OtResources`
        #[allow(clippy::missing_transmute_annotations)]
        let state = { &*resources.init(unsafe { core::mem::transmute(rng) })? };
    
        Ok(Self(state))
    }

    /// Create a new OpenThread controller and its associated components.
    ///
    /// Arguments:
    /// - `rng`: A mutable reference to a random number generator that will be used by OpenThread.
    /// - `resources`: A mutable reference to the OpenThread resources.
    ///
    /// Returns:
    /// - In case there were no errors related to initializing the OpenThread library, a tuple containing:
    ///   - The OpenThread controller
    ///   - The OpenThread Ipv6 packets receiver
    ///   - The OpenThread Ipv6 packets transmitter
    ///   - The OpenThread stack runner
    pub fn split(self) -> (OtController<'a>, OtRx<'a>, OtTx<'a>, OtRunner<'a>) {
        (
            OtController(self),
            OtRx(self),
            OtTx(self),
            OtRunner(self),
        )
    }

    pub fn split_borrow_mut(&mut self) -> (OtController<'_>, OtRx<'_>, OtTx<'_>, OtRunner<'_>) {
        (
            OtController(*self),
            OtRx(*self),
            OtTx(*self),
            OtRunner(*self),
        )
    }

    /// Set a new active dataset in the OpenThread stack.
    ///
    /// Arguments:
    /// - `dataset`: A reference to the new dataset to be set.
    pub fn set_dataset(&self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        dataset.store_raw(&mut state.data.dataset_resources.dataset);

        ot!(unsafe {
            otDatasetSetActive(state.data.instance, &state.data.dataset_resources.dataset)
        })
    }

    /// Brings the OpenThread IPv6 interface up or down.
    pub fn enable_ipv6(&self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        ot!(unsafe { otIp6SetEnabled(state.data.instance, enable) })
    }

    /// This function starts/stops the Thread protocol operation.
    ///
    /// TODO: The interface must be up when calling this function.
    pub fn enable_thread(&self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        ot!(unsafe { otThreadSetEnabled(state.data.instance, enable) })
    }

    /// Gets the list of IPv6 addresses currently assigned to the Thread interface
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the IPv6 addresses will be stored.
    ///
    /// Returns:
    /// - The total number of IPv6 addresses available. If this number is greater than
    ///   the length of the buffer, only the first `buf.len()` addresses will be stored in the buffer.
    pub fn ipv6_addrs(&self, buf: &mut [(Ipv6Addr, u8)]) -> Result<usize, OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        let mut addrs_ptr = unsafe { otIp6GetUnicastAddresses(state.data.instance) };

        let mut offset = 0;

        while !addrs_ptr.is_null() {
            let addrs = unsafe { addrs_ptr.as_ref() }.unwrap();

            if offset < buf.len() {
                buf[offset] = (
                    unsafe { addrs.mAddress.mFields.m8 }.into(),
                    addrs.mPrefixLength,
                );
            }

            offset += 1;
            addrs_ptr = addrs.mNext;
        }

        Ok(offset)
    }

    /// Wait for the OpenThread stack to change its state.
    pub async fn wait_changed(&self) {
        self.0.signals.controller.wait().await;
    }

    /// Run the OpenThread stack with the provided radio implementation.
    ///
    /// Arguments:
    /// - `radio`: The radio to be used by the OpenThread stack.
    pub async fn run<R>(&self, radio: R) -> !
    where
        R: Radio,
    {
        self.run_all(radio).await
    }

    /// Wait for an IPv6 packet to be available.
    pub async fn wait_rx_available(&self) -> Result<(), OtError> {
        loop {
            trace!("Waiting for IPv6 packet reception availability");

            {
                let data = self.0.data.borrow_mut();

                if !data.rcv_packet_ipv6.is_null() {
                    trace!("IPv6 packet reception available");
                    break;
                }
            }

            self.0.signals.rx_ipv6.wait().await;
        }

        Ok(())
    }

    /// Receive an IPv6 packet.
    /// If there is no packet available, this function will async-wait until a packet is available.
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the received packet will be stored.
    ///
    /// Returns:
    /// - The length of the received packet.
    pub async fn rx(&self, buf: &mut [u8]) -> Result<usize, OtError> {
        loop {
            trace!("Waiting for IPv6 packet reception");

            {
                let mut ot = self.activate();
                let state = ot.state();

                if !state.data.rcv_packet_ipv6.is_null() {
                    let len = unsafe {
                        otMessageRead(
                            state.data.rcv_packet_ipv6,
                            0,
                            buf.as_mut_ptr() as *mut _,
                            buf.len() as _,
                        ) as _
                    };

                    unsafe {
                        otMessageFree(state.data.rcv_packet_ipv6);
                    }

                    state.data.rcv_packet_ipv6 = core::ptr::null_mut();

                    debug!("Received IPv6 packet: {:02x?}", &buf[..len]);

                    return Ok(len);
                }
            }

            self.0.signals.rx_ipv6.wait().await;
        }
    }

    /// Wait for the OpenThread stack to be ready to receive a new IPv6 packet (i.e. to have space for the packet).
    pub async fn wait_tx_available(&self) -> Result<(), OtError> {
        // TODO
        Ok(())
    }

    /// Transmit an IPv6 packet.
    ///
    /// Arguments:
    /// - `packet`: The packet to be transmitted.
    pub async fn tx(&self, packet: &[u8]) -> Result<(), OtError> {
        self.activate().tx_ip6(packet)?;

        debug!("Transmitted IPv6 packet: {:02x?}", packet);

        Ok(())
    }


    /// Initialize the OpenThread state, by:
    /// - Ingesting the random number generator
    /// - Initializing the OpenThread C library (returning the OpenThread singleton) TBD: Support more than one OT instance in future
    /// - Setting the state change callback into the OpenThread C library
    /// - Setting the IPv6 receive callback into the OpenThread C library
    ///
    /// NOTE: This method assumes that tbe `OtState` contents is already initialized
    /// (i.e. all signals are in their initial values, and the data which represents OpenThread C types is all zeroed-out)
    fn init(&mut self, rng: &'static mut dyn RngCore) -> Result<(), OtError> {
        {
            // TODO: Not ideal but we have to activate even before we have the instance
            // Reason: `otPlatEntropyGet` is called back
            let mut ot = self.activate();
            let state = ot.state();

            state.data.rng = Some(rng);
            state.data.instance = unsafe { otInstanceInitSingle() };

            info!(
                "OpenThread instance initialized at {:p}",
                state.data.instance
            );

            // TODO: Remove on drop

            ot!(unsafe {
                otSetStateChangedCallback(
                    state.data.instance,
                    Some(OtContext::plat_c_change_callback),
                    state.data.instance as *mut _,
                )
            })?;

            unsafe {
                otIp6SetReceiveCallback(
                    state.data.instance,
                    Some(OtContext::plat_c_ip6_receive_callback),
                    state.data.instance as *mut _,
                )
            }
        }

        Ok(())
    }

    /// Runs the OpenThread stack by:
    /// - Spinning a Radio async loop that takes "TX" and "RX" commands and sends/receives IEEE 802.15.4 frames
    /// - Spinning an Alarm async loop that notifies the OpenThread C library when an alarm is about to expire
    /// - Spinning the OpenThread C library itself by calling all tasklets and notifying for alarms if necessary
    async fn run_all<R>(&self, radio: R) -> !
    where
        R: Radio,
    {
        let mut radio = pin!(self.run_radio(radio));
        let mut alarm = pin!(self.run_alarm());
        let mut openthread = pin!(self.run_openthread());

        let result =
            embassy_futures::select::select3(&mut radio, &mut alarm, &mut openthread).await;

        match result {
            Either3::First(r) | Either3::Second(r) | Either3::Third(r) => r,
        }
    }

    /// An async loop that waits until the latest alarm (if any) expires and then notifies the OpenThread C library
    /// Based on `embassy-time` for simplicity and for achieving platform-neutrality.
    async fn run_alarm(&self) -> ! {
        loop {
            trace!("Waiting for trigger alarm request");

            let mut when = self.0.signals.alarm.wait().await;

            debug!("Got trigger alarm request: {when}, waiting for it to trigger");

            loop {
                let result = embassy_futures::select::select(
                    self.0.signals.alarm.wait(),
                    embassy_time::Timer::at(when),
                )
                .await;

                match result {
                    Either::First(new_when) => {
                        debug!("Alarm interrupted by new alarm: {new_when}");
                        when = new_when;
                    }
                    Either::Second(_) => {
                        // TODO: Rather than signalling the OT spin loop, notify OT directly?
                        debug!("Alarm triggered, notifying OT main loop");
                        self.0.signals.ot.signal(());
                        break;
                    }
                }
            }
        }
    }

    /// An async loop that sends or receives IEEE 802.15.4 frames, based on commands issued by the OT loop
    ///
    /// Needs to be a separate async loop, because OpenThread C is unaware of async/await and futures,
    /// however, the Radio driver is async.
    async fn run_radio<R>(&self, mut radio: R) -> !
    where
        R: Radio,
    {
        loop {
            trace!("Waiting for radio command");

            let mut cmd = self.0.signals.radio.wait().await;
            debug!("Got radio command: {cmd:?}");

            let config = {
                let mut ot = self.activate();
                let state = ot.state();

                state.data.radio_pending_conf.take()
            };

            if let Some(config) = config {
                debug!("Setting radio config: {config:?}");
                let _ = radio.set_config(&config).await;
            }

            // TODO: Borrow it from the resources
            let mut psdu_buf = [0_u8; OT_RADIO_FRAME_MAX_SIZE as usize];

            loop {
                match cmd {
                    RadioCommand::Conf => break,
                    RadioCommand::Tx => {
                        let psdu_len = {
                            let mut ot = self.activate();
                            let state = ot.state();

                            let psdu_len = state.data.radio_resources.snd_frame.mLength as usize;
                            psdu_buf[..psdu_len]
                                .copy_from_slice(&state.data.radio_resources.snd_psdu[..psdu_len]);

                            unsafe {
                                otPlatRadioTxStarted(
                                    state.data.instance,
                                    &mut state.data.radio_resources.snd_frame,
                                );
                            }

                            psdu_len
                        };

                        trace!("About to Tx 802.15.4 frame {:02x?}", &psdu_buf[..psdu_len]);

                        let mut new_cmd = pin!(self.0.signals.radio.wait());
                        let mut tx = pin!(radio.transmit(&psdu_buf[..psdu_len]));

                        let result = embassy_futures::select::select(&mut new_cmd, &mut tx).await;

                        match result {
                            Either::First(new_cmd) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                // Reporting send failure because we got interrupted
                                // by a new command
                                unsafe {
                                    otPlatRadioTxDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.snd_frame,
                                        &mut state.data.radio_resources.ack_frame,
                                        otError_OT_ERROR_FAILED,
                                    );
                                }

                                debug!("Tx interrupted by new command: {new_cmd:?}");

                                cmd = new_cmd;
                            }
                            Either::Second(result) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                unsafe {
                                    otPlatRadioTxDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.snd_frame,
                                        &mut state.data.radio_resources.ack_frame,
                                        if result.is_ok() {
                                            otError_OT_ERROR_NONE
                                        } else {
                                            otError_OT_ERROR_FAILED
                                        },
                                    );
                                }

                                debug!("Tx done: {result:?}");

                                break;
                            }
                        }
                    }
                    RadioCommand::Rx(channel) => {
                        trace!("Waiting for Rx on channel {channel}");

                        let result = {
                            let mut new_cmd = pin!(self.0.signals.radio.wait());
                            let mut rx = pin!(radio.receive(channel, &mut psdu_buf));

                            embassy_futures::select::select(&mut new_cmd, &mut rx).await
                        };

                        match result {
                            Either::First(new_cmd) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                // Reporting receive failure because we got interrupted
                                // by a new command
                                unsafe {
                                    otPlatRadioReceiveDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.rcv_frame,
                                        otError_OT_ERROR_FAILED,
                                    );
                                }

                                debug!("Rx interrupted by new command: {new_cmd:?}");

                                cmd = new_cmd;
                            }
                            Either::Second(result) => {
                                // https://github.com/espressif/esp-idf/blob/release/v5.3/components/ieee802154/private_include/esp_ieee802154_frame.h#L20
                                // TODO: Not sure we actually need any of this...
                                const IEEE802154_FRAME_TYPE_OFFSET: usize = 0; // .. as we have removed the PHR and we are indexing the PSDU
                                const IEEE802154_FRAME_TYPE_MASK: u8 = 0x07;
                                const IEEE802154_FRAME_TYPE_BEACON: u8 = 0x00;
                                const IEEE802154_FRAME_TYPE_DATA: u8 = 0x01;
                                const IEEE802154_FRAME_TYPE_ACK: u8 = 0x02;
                                const IEEE802154_FRAME_TYPE_COMMAND: u8 = 0x03;

                                let mut ot = self.activate();
                                let state = ot.state();

                                let Ok(psdu_meta) = result else {
                                    warn!("Rx failed: {result:?}");

                                    // Reporting receive failure because we got a driver error
                                    unsafe {
                                        otPlatRadioReceiveDone(
                                            state.data.instance,
                                            &mut state.data.radio_resources.rcv_frame,
                                            otError_OT_ERROR_FAILED,
                                        );
                                    }

                                    break;
                                };

                                debug!(
                                    "Rx done, got frame: {psdu_meta:?}, {:02x?}",
                                    &psdu_buf[..psdu_meta.len]
                                );

                                state.data.radio_resources.rcv_psdu[..psdu_meta.len]
                                    .copy_from_slice(&psdu_buf[..psdu_meta.len]);

                                let instance = state.data.instance;

                                let resources = &mut state.data.radio_resources;
                                let rcv_psdu = &resources.rcv_psdu[..psdu_meta.len];
                                let rcv_frame = &mut resources.rcv_frame;

                                fn frame_type(psdu: &[u8]) -> u8 {
                                    if psdu.len() == IEEE802154_FRAME_TYPE_OFFSET {
                                        return 0;
                                    }

                                    psdu[IEEE802154_FRAME_TYPE_OFFSET] & IEEE802154_FRAME_TYPE_MASK
                                }

                                /// Convert from RSSI (Received Signal Strength Indicator) to LQI (Link Quality
                                /// Indication)
                                ///
                                /// RSSI is a measure of incoherent (raw) RF power in a channel. LQI is a
                                /// cumulative value used in multi-hop networks to assess the cost of a link.
                                fn rssi_to_lqi(rssi: i8) -> u8 {
                                    if rssi < -80 {
                                        0
                                    } else if rssi > -30 {
                                        0xff
                                    } else {
                                        let lqi_convert = ((rssi as u32).wrapping_add(80)) * 255;
                                        (lqi_convert / 50) as u8
                                    }
                                }

                                match frame_type(rcv_psdu) {
                                    IEEE802154_FRAME_TYPE_DATA => {
                                        debug!("Got data frame, reporting");

                                        let rssi = psdu_meta.rssi.unwrap_or(0);

                                        rcv_frame.mLength = rcv_psdu.len() as u16;
                                        rcv_frame.mRadioType = 1; // ????
                                        rcv_frame.mChannel = channel;
                                        rcv_frame.mInfo.mRxInfo.mRssi = rssi;
                                        rcv_frame.mInfo.mRxInfo.mLqi = rssi_to_lqi(rssi);
                                        rcv_frame.mInfo.mRxInfo.mTimestamp =
                                            Instant::now().as_micros();

                                        unsafe {
                                            otPlatRadioReceiveDone(
                                                instance,
                                                rcv_frame,
                                                otError_OT_ERROR_NONE,
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_BEACON
                                    | IEEE802154_FRAME_TYPE_COMMAND => {
                                        warn!("Received beacon or MAC command frame, triggering scan done");

                                        // ed_rss for H2 and C6 is the same
                                        const ENERGY_DETECT_RSS: i8 = 16;

                                        unsafe {
                                            otPlatRadioEnergyScanDone(
                                                state.data.instance,
                                                ENERGY_DETECT_RSS,
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_ACK => {
                                        debug!("Received ack frame");
                                    }
                                    _ => {
                                        // Drop unsupported frames
                                        warn!("Unsupported frame type received");
                                    }
                                }

                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Spins the OpenThread C library loop by processing tasklets (if they are pending), alarms (if they are pending)
    /// or otherwise waiting until notified that there are either pending tasklets, or pending alarms.
    async fn run_openthread(&self) -> ! {
        loop {
            trace!("About to process Openthread tasklets and alarms");

            // Activate OpenThread and process any tasklets and alarms
            self.activate().process();

            // Nothing to process anymore, wait until somebody signals us that there is stuff to process
            self.0.signals.ot.wait().await;
        }
    }

    /// Activates the OpenThread stack.
    ///
    /// IMPORTANT: The OpenThread native C API can ONLY be called when this method is called and
    /// the returned `OpenThread` instance is in scope.
    ///
    /// IMPORTTANT: Do NOT hold on the `activate`d `OpenThread` instance accross `.await` points!
    ///
    /// Returns:
    /// - An `OpenThread` instance that represents the activated OpenThread stack.
    ///
    /// What activation means in the context of the `openthread` crate is as follows:
    /// - The global `OT_ACTIVE_STATE` variable is set to the current `OtActiveState` instance (which is a borrowed reference to the current `OtState` instance)
    ///   This is necessary so that when an native OpenThread C API "ot*" function is called, OpenThread can call us "back" via the `otPlat*` API
    /// - While the returned `OpenThread` instance is in scope, the data of `OtState` stays mutably borrowed
    fn activate(&self) -> OtContext<'_> {
        OtContext::activate_for(&self.0)
    }
}

/// The OpenThread controller type
///
/// Provides facilities for controlling the OpenThread stack, like setting a new dataset, enabling/disabling the IPv6 interface, etc.
pub struct OtController<'a>(OpenThread<'a>);

impl OtController<'_> {
    /// Set a new active dataset in the OpenThread stack.
    ///
    /// Arguments:
    /// - `dataset`: A reference to the new dataset to be set.
    pub fn set_dataset(&mut self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        self.0.set_dataset(dataset)
    }

    /// Brings the OpenThread IPv6 interface up or down.
    pub fn enable_ipv6(&mut self, enable: bool) -> Result<(), OtError> {
        self.0.enable_ipv6(enable)
    }

    /// This function starts/stops the Thread protocol operation.
    ///
    /// TODO: The interface must be up when calling this function.
    pub fn enable_thread(&mut self, enable: bool) -> Result<(), OtError> {
        self.0.enable_thread(enable)
    }

    /// Gets the list of IPv6 addresses currently assigned to the Thread interface
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the IPv6 addresses will be stored.
    ///
    /// Returns:
    /// - The total number of IPv6 addresses available. If this number is greater than
    ///   the length of the buffer, only the first `buf.len()` addresses will be stored in the buffer.
    pub fn ipv6_addrs(&mut self, buf: &mut [(Ipv6Addr, u8)]) -> Result<usize, OtError> {
        self.0.ipv6_addrs(buf)
    }

    /// Wait for the OpenThread stack to change its state.
    pub async fn wait_changed(&mut self) {
        self.0.wait_changed().await
    }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_autostart(
    //     &mut self,
    //     callback: Option<
    //         unsafe extern "C" fn(aServerSockAddr: *const otSockAddr, aContext: *mut c_void),
    //     >,
    // ) -> Result<(), Error> {
    //     if !callback.is_some() {
    //         srp_client::enable_srp_autostart(self.instance);
    //         return Ok(());
    //     }
    //     srp_client::enable_srp_autostart_with_callback_and_context(
    //         self.instance,
    //         callback,
    //         core::ptr::null_mut(),
    //     );

    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_host_addr_autoconfig(&mut self) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_addresses_auto_config(self.instance)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_set_hostname(&mut self, host_name: &str) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_name(self.instance, host_name.as_ptr() as _)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_with_addr(
    //     &mut self,
    //     host_name: &str,
    //     addr: otSockAddr,
    // ) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_name(self.instance, host_name.as_ptr() as _)?;
    //     srp_client::srp_client_start(self.instance, addr)?;
    //     Ok(())
    // }

    // // For now, txt entries are expected to be provided as hex strings to avoid having to pull in the hex crate
    // // for example a key entry of 'abc' should be provided as '03616263'
    // #[cfg(feature = "srp-client")]
    // pub fn register_service_with_srp_client(
    //     &mut self,
    //     instance_name: &str,
    //     service_name: &str,
    //     service_labels: &[&str],
    //     txt_entry: &str,
    //     port: u16,
    //     priority: Option<u16>,
    //     weight: Option<u16>,
    //     lease: Option<u32>,
    //     key_lease: Option<u32>,
    // ) -> Result<(), Error> {
    //     if !srp_client::is_srp_client_running(self.instance) {
    //         self.setup_srp_client_autostart(None)?;
    //     }

    //     srp_client::add_srp_client_service(
    //         self.instance,
    //         instance_name.as_ptr() as _,
    //         instance_name.len() as _,
    //         service_name.as_ptr() as _,
    //         service_name.len() as _,
    //         service_labels,
    //         txt_entry.as_ptr() as _,
    //         txt_entry.len() as _,
    //         port,
    //         priority,
    //         weight,
    //         lease,
    //         key_lease,
    //     )?;

    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn set_srp_client_ttl(&mut self, ttl: u32) {
    //     srp_client::set_srp_client_ttl(self.instance, ttl);
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn get_srp_client_ttl(&mut self) -> u32 {
    //     srp_client::get_srp_client_ttl(self.instance)
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn stop_srp_client(&mut self) -> Result<(), Error> {
    //     srp_client::srp_client_stop(self.instance);
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn get_srp_client_state(&mut self) -> Result<Option<SrpClientItemState>, Error> {
    //     Ok(srp_client::get_srp_client_host_state(self.instance))
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn clear_srp_client_host_buffers(&mut self) {
    //     srp_client::srp_clear_all_client_services(self.instance)
    // }

    // /// If there are any services already registered, unregister them
    // #[cfg(feature = "srp-client")]
    // pub fn srp_unregister_all_services(
    //     &mut self,
    //     remove_keylease: bool,
    //     send_update: bool,
    // ) -> Result<(), Error> {
    //     srp_client::srp_unregister_and_remove_all_client_services(
    //         self.instance,
    //         remove_keylease,
    //         send_update,
    //     )?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_clear_service(&mut self, service: SrpClientService) -> Result<(), Error> {
    //     srp_client::srp_clear_service(self.instance, service)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_unregister_service(&mut self, service: SrpClientService) -> Result<(), Error> {
    //     srp_client::srp_unregister_service(self.instance, service)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_get_services(
    //     &mut self,
    // ) -> heapless::Vec<SrpClientService, { srp_client::MAX_SERVICES }> {
    //     srp_client::get_srp_client_services(self.instance)
    // }
}

/// A type that runs the OpenThread stack.
///
/// For the stack to operate, the user needs to constantly poll the future returned by this type.
pub struct OtRunner<'a>(OpenThread<'a>);

impl OtRunner<'_> {
    /// Run the OpenThread stack with the provided radio implementation.
    ///
    /// Arguments:
    /// - `radio`: The radio to be used by the OpenThread stack.
    pub async fn run<R>(&mut self, radio: R) -> !
    where
        R: Radio,
    {
        self.0.run(radio).await
    }
}

/// A type for receiving (egressing) IPv6 packets from the OpenThread stack and thus from the IEEE 802.15.4 network.
pub struct OtRx<'a>(OpenThread<'a>);

impl OtRx<'_> {
    /// Wait for an IPv6 packet to be available.
    pub async fn wait_available(&mut self) -> Result<(), OtError> {
        self.0.wait_rx_available().await
    }

    /// Receive an IPv6 packet.
    /// If there is no packet available, this function will async-wait until a packet is available.
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the received packet will be stored.
    ///
    /// Returns:
    /// - The length of the received packet.
    pub async fn rx(&mut self, buf: &mut [u8]) -> Result<usize, OtError> {
        self.0.rx(buf).await
    }
}

/// A type for transmitting (ingressing) IPv6 packets into the OpenThread stack and thus to the IEEE 802.15.4 network.
pub struct OtTx<'a>(OpenThread<'a>);

impl OtTx<'_> {
    /// Wait for the OpenThread stack to be ready to receive a new IPv6 packet (i.e. to have space for the packet).
    pub async fn wait_available(&mut self) -> Result<(), OtError> {
        self.0.wait_tx_available().await
    }

    /// Transmit an IPv6 packet.
    ///
    /// Arguments:
    /// - `packet`: The packet to be transmitted.
    pub async fn tx(&mut self, packet: &[u8]) -> Result<(), OtError> {
        self.0.tx(packet).await
    }
}

/// The resources (data) that is necessary for the OpenThread stack to operate.
///
/// A separate type so that it can be allocated outside of the OpenThread futures,
/// thus avoiding expensive mem-moves.
///
/// Can also be statically-allocated.
pub struct OtResources<const N: usize> {
    inner: MaybeUninit<OtResourcesInner<N>>,
}

impl<const N: usize> OtResources<N> {
    // TODO: Not ideal, as its content is not all-zeroes so it won't end up in the BSS segment
    // Ideally we should initialize it piece by piece
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: OtResourcesInner<N> = OtResourcesInner::new();

    /// Create a new `OtResources` instance.
    pub const fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }

    /// Initialize the resouces, as they start their life as `MaybeUninit` so as to avoid mem-moves.
    /// Also ingest the random number generator.
    ///
    /// Returns:
    /// - A mutable reference to an `OtState` value that represents the initialized OpenThread state.
    // TODO: Need to manually drop/reset the signals in OtSignals
    fn init(&mut self, rng: &'static mut dyn RngCore) -> Result<&mut OtResourcesInner<N>, OtError> {
        self.inner.write(Self::INIT);

        let inner = unsafe { self.inner.assume_init_mut() };

        inner.data.radio_resources.init();
        inner.init(rng)?;

        info!("OpenThread resources initialized");

        Ok(inner)
    }
}

impl<const N: usize> Default for OtResources<N> {
    fn default() -> Self {
        Self::new()
    }
}

struct OtResourcesInner<const N: usize> {
    /// The signals that are used for communication between the controller, the runner and the OpenThread C library
    signals: OtSignals,
    /// Shared data between the above components
    ///
    /// It is stored as a `RefCell` because it needs to be shared between the controller, the runner and the OpenThread C library
    /// Note that the futures generated by all of the above can only be polled from a single "thread" (i.e. they are not `Send`)
    data: OtData,
    udp_sockets_signals: [UdpSocketSignals; N],
    udp_sockets_data: [UdpSocketData; N],
}

impl<const N: usize> OtResourcesInner<N> {
    const INIT_UDP_SIGNALS: UdpSocketSignals = UdpSocketSignals::new();
    const INIT_UDP_DATA: UdpSocketData = UdpSocketData::new();

    const fn new() -> Self {
        Self {
            signals: OtSignals::new(),
            data: OtData::new(),
            udp_sockets_signals: [Self::INIT_UDP_SIGNALS; N],
            udp_sockets_data: [Self::INIT_UDP_DATA; N],
        }
    }

    fn init(&mut self, rng: &'static mut dyn RngCore) -> Result<(), OtError> {
        self.data.init(rng)
    }
}

/// The state of the OpenThread stack, from Rust POV.
struct OtState<'t> {
    /// The signals that are used for communication between the controller, the runner and the OpenThread C library
    signals: &'t OtSignals,
    /// Shared data between the above components
    ///
    /// It is stored as a `RefCell` because it needs to be shared between the controller, the runner and the OpenThread C library
    /// Note that the futures generated by all of the above can only be polled from a single "thread" (i.e. they are not `Send`)
    data: RefCell<&'t mut OtData>,
    udp_sockets_signals: &'t [UdpSocketSignals],
    udp_sockets_data: RefCell<&'t mut [UdpSocketData]>,
}

impl OtState<'static> {
}

impl<'t> OtState<'t> {
    /// Create a new `OtState` instance.
    const fn new<const N: usize>(resources: &'t mut OtResourcesInner<N>) -> Self {
        Self {
            signals: &resources.signals,
            data: RefCell::new(&mut resources.data),
            udp_sockets_signals: &resources.udp_sockets_signals,
            udp_sockets_data: RefCell::new(&mut resources.udp_sockets_data),
        }
    }
}

/// Represents an "activated" `OtState`.
/// An activated `OtState` is simply the same state but with all "data" mutably borrowed, for the duration
/// of the activation.
struct OtActiveState<'a> {
    signals: &'a OtSignals,
    data: RefMut<'a, &'static mut OtData>,
    udp_sockets_signals: &'a [UdpSocketSignals],
    udp_sockets_data: RefMut<'a, &'static mut [UdpSocketData]>,
}

impl<'a> OtActiveState<'a> {
    /// Create a new `OtActiveState` instance from an `OtState` instance.
    fn new(ot: &'a OtState<'static>) -> Self {
        Self {
            signals: &ot.signals,
            data: ot.data.borrow_mut(),
            udp_sockets_signals: &ot.udp_sockets_signals,
            udp_sockets_data: ot.udp_sockets_data.borrow_mut(),
        }
    }
}

// A hack so that we can store `OtActiveState` in the global `OT_ACTIVE_STATE` variable
// While it is not really `Send`-safe, we _do_ know that there a single C OpenThread instance, and it will
// always call us back from the thread on which we called it.
unsafe impl Send for OtActiveState<'_> {}

/// A thin wrapper around the OpenThread C library.
///
/// For the wrapper to operate, it needs to be activated by calling `activate_for`.
struct OtContext<'a> {
    callback: bool,
    _t: PhantomData<&'a mut ()>,
}

impl<'a> OtContext<'a> {
    /// Activates the OpenThread C wrapper by (temporarily) putting the OpenThread state
    /// in the global `OT_ACTIVE_STATE` variable, which allows the OpenThread C library to call us back.
    ///
    /// Activation is therefore a cheap operation which is expected to be done often, for a short duration
    /// (ideally, just to call one or a few OpenThread C functions) and should not persist across await points
    /// (see below).
    ///
    /// The reason to have the notion of activation in the first place is because there are mutiple async agents that
    /// are willing to operate on the same data, i.e.:
    /// - The radio async loop
    /// - The alarm async loop
    /// - The `OpenThread::process` method (the entry into the C OpenThread library)
    /// - The controller futures (which might call into OpenThread C by activating it shortly first)
    ///
    /// All of the above tasks operate on the same data (OtData::data) by mutably borrowing it first, either
    /// directly, or by activating (= creating an `OpenThread` type instance) and then calling an OpenThread C API.
    ///
    /// Activation is automacally finished when the `OpenThread` instance is dropped.
    ///
    /// NOTE: Do NOT hold references to the `OpenThread` instance across `.await` points!
    /// NOTE: Do NOT call `activate` twice without dropping the previous instance!
    ///
    /// The above ^^^ will not lead to a memory corruption, but the code will panic due to an attempt
    /// to mutably borrow the `OtState` `RefCell`d data twice.
    fn activate_for(ot: &'a OtState<'static>) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_none());

        // Needed so that we convert from the fake `'static` lifetime in `OT_ACTIVE_STATE` to the actual `'a` lifetime of `ot`
        #[allow(clippy::missing_transmute_annotations)]
        {
            *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() =
                Some(unsafe { core::mem::transmute(OtActiveState::new(ot)) });
        }

        Self {
            callback: false,
            _t: PhantomData,
        }
    }

    /// Obtain the already activated `OpenThread` instance when arriving
    /// back from C into our code, via some of the `otPlat*` wrappers.
    ///
    /// This method is called when the OpenThread C library calls us back.
    fn callback(_instance: *const otInstance) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_some());

        Self {
            callback: true,
            _t: PhantomData,
        }
    }

    /// Gets a reference to the `OtActiveState` instance owned by this `OpenThread` instance.
    fn state(&mut self) -> &mut OtActiveState<'a> {
        unsafe { core::mem::transmute(OT_ACTIVE_STATE.0.get().as_mut().unwrap().as_mut().unwrap()) }
    }

    /// Ingest an IPv6 packet into OpenThread.
    fn tx_ip6(&mut self, packet: &[u8]) -> Result<(), OtError> {
        let state = self.state();

        let msg = unsafe {
            otIp6NewMessageFromBuffer(
                state.data.instance,
                packet.as_ptr(),
                packet.len() as _,
                &otMessageSettings {
                    mLinkSecurityEnabled: true,
                    mPriority: otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL as _,
                },
            )
        };

        if !msg.is_null() {
            let res = unsafe { otIp6Send(state.data.instance, msg) };
            if res != otError_OT_ERROR_DROP {
                ot!(res)
            } else {
                // OpenThread will intentionally drop some multicast and ICMPv6 packets
                // which are not required for the Thread network.
                trace!("Message dropped");
                Ok(())
            }
        } else {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))
        }
    }

    /// Processes the OpenThread stack by:
    /// - Processing tasklets, if they are pending
    /// - Processing alarms, if they are pending
    fn process(&mut self) {
        loop {
            let mut processed = false;

            processed |= self.process_tasklets();
            processed |= self.process_alarm();

            if !processed {
                break;
            }
        }
    }

    /// Process the tasklets if they are pending.
    fn process_tasklets(&mut self) -> bool {
        let state = self.state();

        if state.data.run_tasklets {
            debug!("Process tasklets");

            state.data.run_tasklets = false;

            unsafe { otTaskletsProcess(state.data.instance) };

            true
        } else {
            false
        }
    }

    /// Process the alarm if it is pending.
    fn process_alarm(&mut self) -> bool {
        let state = self.state();

        if state
            .data
            .alarm_status
            .map(|when| when <= embassy_time::Instant::now())
            .unwrap_or(false)
        {
            debug!("Alarm fired, notifying OpenThread C");

            state.data.alarm_status = None;
            unsafe { otPlatAlarmMilliFired(state.data.instance) };

            true
        } else {
            false
        }
    }

    unsafe extern "C" fn plat_c_change_callback(flags: otChangedFlags, context: *mut c_void) {
        let instance = context as *mut otInstance;

        Self::callback(instance).plat_changed(flags);
    }

    unsafe extern "C" fn plat_c_ip6_receive_callback(msg: *mut otMessage, context: *mut c_void) {
        let instance = context as *mut otInstance;

        Self::callback(instance).plat_ipv6_received(msg);
    }

    // /// caller must call this prior to setting up the host config
    // #[cfg(feature = "srp-client")]
    // pub fn set_srp_state_callback(
    //     &mut self,
    //     callback: Option<&'a mut (dyn FnMut(otError, usize, usize, usize) + Send)>,
    // ) {
    //     critical_section::with(|cs| {
    //         let mut srp_change_callback = SRP_CHANGE_CALLBACK.borrow_ref_mut(cs);
    //         *srp_change_callback = unsafe { core::mem::transmute(callback) };
    //     });

    //     unsafe {
    //         otSrpClientSetCallback(
    //             self.instance,
    //             Some(srp_state_callback),
    //             core::ptr::null_mut(),
    //         )
    //     }
    // }

    //
    // All `plat_*` methods below represent the OpenThread C library calling us back.
    // Note that OpenThread C cannot call us back "randomly", as it is not multithreaded and
    // is completely passive.
    //
    // We can get a callback ONLY in the context of _us_ calling an `ot*` OpenThread C API method first.
    // Before the `ot*` method returns, we might get called back via one or more callbacks.
    //

    fn plat_reset(&mut self) -> Result<(), OtError> {
        todo!()
    }

    fn plat_entropy_get(&mut self, buf: &mut [u8]) -> Result<(), OtError> {
        self.state().data.rng.as_mut().unwrap().fill_bytes(buf);

        Ok(())
    }

    fn plat_tasklets_signal_pending(&mut self) {
        let state = self.state();

        state.data.run_tasklets = true;
        state.signals.ot.signal(());
    }

    fn plat_ipv6_received(&mut self, msg: *mut otMessage) {
        trace!("Got ipv6 packet");

        let state = self.state();

        if state.data.rcv_packet_ipv6.is_null() {
            state.data.rcv_packet_ipv6 = msg;
            state.signals.rx_ipv6.signal(());
        } else {
            unsafe {
                otMessageFree(msg);
            }
        }
    }

    fn plat_changed(&mut self, _flags: u32) {
        trace!("Plat changed callback");
        self.state().signals.controller.signal(());
    }

    fn plat_now(&mut self) -> u32 {
        trace!("Plat now callback");
        Instant::now().as_millis() as u32
    }

    fn plat_alarm_set(&mut self, at0_ms: u32, adt_ms: u32) -> Result<(), OtError> {
        trace!("Plat alarm set callback: {at0_ms}, {adt_ms}");

        let state = self.state();

        let instant = embassy_time::Instant::from_millis(at0_ms as _)
            + embassy_time::Duration::from_millis(adt_ms as _);

        state.data.alarm_status = Some(instant);
        state.signals.alarm.signal(instant);

        Ok(())
    }

    fn plat_alarm_clear(&mut self) -> Result<(), OtError> {
        trace!("Plat alarm clear callback");
        self.state().data.alarm_status = None;

        Ok(())
    }

    fn plat_radio_ieee_eui64(&mut self, mac: &mut [u8; 8]) {
        mac.fill(0);
        trace!("Plat radio IEEE EUI64 callback, MAC: {:02x?}", mac);
    }

    fn plat_radio_caps(&mut self) -> u8 {
        let caps = 0; // TODO
        trace!("Plat radio caps callback, caps: {caps}");

        caps
    }

    fn plat_radio_is_enabled(&mut self) -> bool {
        let enabled = true; // TODO
        trace!("Plat radio is enabled callback, enabled: {enabled}");

        enabled
    }

    fn plat_radio_get_rssi(&mut self) -> i8 {
        let rssi = -128; // TODO
        trace!("Plat radio get RSSI callback, RSSI: {rssi}");

        rssi
    }

    // from https://github.com/espressif/esp-idf/blob/release/v5.3/components/openthread/src/port/esp_openthread_radio.c#L35
    fn plat_radio_receive_sensititivy(&mut self) -> i8 {
        let sens = 0; // TODO
        trace!("Plat radio receive sensitivity callback, sensitivity: {sens}");

        sens
    }

    fn plat_radio_get_promiscuous(&mut self) -> bool {
        let promiscuous = false; // TODO
        trace!("Plat radio get promiscuous callback, promiscuous: {promiscuous}");

        promiscuous
    }

    fn plat_radio_enable(&mut self) -> Result<(), OtError> {
        info!("Plat radio enable callback");
        Ok(()) // TODO
    }

    fn plat_radio_disable(&mut self) -> Result<(), OtError> {
        info!("Plat radio disable callback");
        Ok(()) // TODO
    }

    fn plat_radio_set_promiscuous(&mut self, promiscuous: bool) {
        info!("Plat radio set promiscuous callback, promiscuous: {promiscuous}");

        let state = self.state();

        if state.data.radio_conf.promiscuous != promiscuous {
            state.data.radio_conf.promiscuous = promiscuous;
            state.data.radio_pending_conf = Some(state.data.radio_conf.clone());
            state.signals.radio.signal(RadioCommand::Conf);
        }
    }

    fn plat_radio_set_extended_address(&mut self, address: u64) {
        info!("Plat radio set extended address callback, addr: {address}");

        let state = self.state();

        if state.data.radio_conf.ext_addr != Some(address) {
            state.data.radio_conf.ext_addr = Some(address);
            state.data.radio_pending_conf = Some(state.data.radio_conf.clone());
            state.signals.radio.signal(RadioCommand::Conf);
        }
    }

    fn plat_radio_set_short_address(&mut self, address: u16) {
        info!("Plat radio set short address callback, addr: {address}");

        let state = self.state();

        if state.data.radio_conf.short_addr != Some(address) {
            state.data.radio_conf.short_addr = Some(address);
            state.data.radio_pending_conf = Some(state.data.radio_conf.clone());
            state.signals.radio.signal(RadioCommand::Conf);
        }
    }

    fn plat_radio_set_pan_id(&mut self, pan_id: u16) {
        info!("Plat radio set PAN ID callback, PAN ID: {pan_id}");

        let state = self.state();

        if state.data.radio_conf.pan_id != Some(pan_id) {
            state.data.radio_conf.pan_id = Some(pan_id);
            state.data.radio_pending_conf = Some(state.data.radio_conf.clone());
            state.signals.radio.signal(RadioCommand::Conf);
        }
    }

    fn plat_radio_energy_scan(&mut self, channel: u8, duration: u16) -> Result<(), OtError> {
        info!("Plat radio energy scan callback, channel {channel}, duration {duration}");
        unreachable!()
    }

    fn plat_radio_sleep(&mut self) -> Result<(), OtError> {
        info!("Plat radio sleep callback");
        Ok(()) // TODO
    }

    fn plat_radio_transmit_buffer(&mut self) -> *mut otRadioFrame {
        trace!("Plat radio transmit buffer callback");
        // TODO: This frame is private to us, perhaps don't store it in a RefCell?
        &mut self.state().data.radio_resources.tns_frame
    }

    fn plat_radio_transmit(&mut self, frame: &otRadioFrame) -> Result<(), OtError> {
        trace!(
            "Plat radio transmit callback: {}, {:02x?}",
            frame.mLength,
            frame.mPsdu
        );

        let state = self.state();

        let psdu = unsafe { core::slice::from_raw_parts_mut(frame.mPsdu, frame.mLength as _) };

        state.data.radio_resources.snd_frame = *frame;
        state.data.radio_resources.snd_psdu[..psdu.len()].copy_from_slice(psdu);
        state.data.radio_resources.snd_frame.mPsdu =
            addr_of_mut!(state.data.radio_resources.snd_psdu) as *mut _;

        state.signals.radio.signal(RadioCommand::Tx);

        Ok(())
    }

    fn plat_radio_receive(&mut self, channel: u8) -> Result<(), OtError> {
        trace!("Plat radio receive callback, channel: {channel}");
        self.state().signals.radio.signal(RadioCommand::Rx(channel));

        Ok(())
    }
}

impl Drop for OtContext<'_> {
    fn drop(&mut self) {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_some());

        if !self.callback {
            *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() = None;
        }
    }
}

/// The "data-carrier" (mostly buffers) portion of the `OtState` type.
///
/// This data lives behind a `RefCell` and is mutably borrowed each time
/// the OpenThread stack is activated, by creating an `OpenThread` instance.
///
/// It contains mostly native Openthread C data types.
struct OtData {
    /// The OpenThread instance associated with the `OtData` inztance.
    instance: *mut otInstance,
    /// The random number generator associated with the `OtData` instance.
    rng: Option<&'static mut dyn RngCore>,
    /// If not null, an Ipv6 packet egressed from OpenThread and waiting (via `OtRx`) to be ingressed somewhere else
    /// To be used together with `OtSignals::rx_ipv6`
    /// TODO: Maybe unite the two?
    rcv_packet_ipv6: *mut otMessage,
    /// Resources for the radio (PHY data frames and their descriptors)
    radio_resources: RadioResources,
    /// Resouces for dealing with the operational dataset
    dataset_resources: DatasetResources,
    /// `Some` in case there is a pending OpenThread awarm which is not due yet
    alarm_status: Option<embassy_time::Instant>,
    /// If `true`, the tasklets need to be run. Set by the OpenThread C library via the `otPlatTaskletsSignalPending` callback
    run_tasklets: bool,
    radio_conf: radio::Config,
    radio_pending_conf: Option<radio::Config>,
}

impl OtData {
    /// Create a new `OtData` instance.
    const fn new() -> Self {
        Self {
            instance: core::ptr::null_mut(),
            rng: None,
            rcv_packet_ipv6: core::ptr::null_mut(),
            radio_resources: RadioResources::new(),
            dataset_resources: DatasetResources::new(),
            alarm_status: None,
            run_tasklets: true,
            radio_conf: radio::Config::new(),
            radio_pending_conf: None,
        }
    }
}

/// The "signals" portion of the `OtState` type.
///
/// This state does not have to be mutably borrowed, as it has
/// interior mutability.
struct OtSignals {
    /// A signal for the latest command that the radio runner needs to process
    radio: Signal<NoopRawMutex, RadioCommand>,
    /// A signal for the latest alarm that the alarm runner needs to await to become due
    alarm: Signal<NoopRawMutex, embassy_time::Instant>,
    /// A signal for `OtController` that something had changed in the OpenThread stack (method `OtController::wait_changed`)
    controller: Signal<NoopRawMutex, ()>,
    /// A singal for `OpenThread` / `OtState` that it needs to call its `process` loop
    ot: Signal<NoopRawMutex, ()>,
    /// A signal for `OtRx` that an IPv6 packet is incoming from OpenThread
    rx_ipv6: Signal<NoopRawMutex, ()>,
}

impl OtSignals {
    /// Create a new `OtSignals` instance.
    const fn new() -> Self {
        Self {
            radio: Signal::new(),
            alarm: Signal::new(),
            controller: Signal::new(),
            ot: Signal::new(),
            rx_ipv6: Signal::new(),
        }
    }
}

/// A command for the radio runner to process.
#[derive(Debug)]
enum RadioCommand {
    Conf,
    /// Transmit a frame
    /// The data of the frame is in `OtData::radio_resources.snd_frame` and `OtData::radio_resources.snd_psdu`
    ///
    /// Once the frame is sent (or an error occurs) OpenThread C will be signalled by calling `otPlatRadioTxDone`
    Tx,
    /// Receive a frame on a specific channel
    ///
    /// Once the frame is received, it will be copied to `OtData::radio_resources.rcv_frame` and `OtData::radio_resources.rcv_psdu`
    /// and OpenThread C will be signalled by calling `otPlatRadioReceiveDone`
    Rx(u8),
}

/// Radio-related OpenThread C data carriers
///
/// Note that this structure is self-referential in that its `*_frame` members all
/// contain a pointer to its corresponding `*_psdu` member.
///
/// This is not modelled strictly (i.e. with pinning), because all of these structures are internal and not an API
/// the user can abuse. With that said, care should be taken the self-referencial struct to be properly initialized,
/// before using it and members of the struct should not be swapped-out after that.
///
/// With that said, the structure anyway cannot be moved omnce we hit the `openthread::new` function in this crate,
/// because of the signature of the `openthread::new` API which **mutably borrows** `OtResources` (and tus this structure too)
/// for the lifetime of the OpenThread Rust stack.
// TODO: Figure out how to init efficiently
struct RadioResources {
    /// The received frame from the radio
    rcv_frame: otRadioFrame,
    /// An empty ACK frame send to `otPlatRadioReceiveDone` TBD why we need that
    ack_frame: otRadioFrame,
    /// A buffer where OpenThread prepares the next frame to be send
    tns_frame: otRadioFrame,
    /// A frame which is to be send to the radio
    snd_frame: otRadioFrame,
    /// The PSDU of the received frame
    /// NOTE:
    rcv_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    tns_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    snd_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    ack_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
}

impl RadioResources {
    /// Create a new `RadioResources` instance.
    pub const fn new() -> Self {
        unsafe {
            Self {
                rcv_frame: MaybeUninit::zeroed().assume_init(),
                tns_frame: MaybeUninit::zeroed().assume_init(),
                snd_frame: MaybeUninit::zeroed().assume_init(),
                ack_frame: MaybeUninit::zeroed().assume_init(),
                rcv_psdu: MaybeUninit::zeroed().assume_init(),
                tns_psdu: MaybeUninit::zeroed().assume_init(),
                snd_psdu: MaybeUninit::zeroed().assume_init(),
                ack_psdu: MaybeUninit::zeroed().assume_init(),
            }
        }
    }

    /// Initialize the `RadioResources` instance by doing the self-referential magic.
    ///
    /// For this to work, `init` should be called from inside the `openthread::new` API method that creates
    /// all of the public-facing APIs, as at that time `OtResources` is already mutably borrowed and cannot move.
    ///
    /// This method should not be called e.g. from the constructor of `OtResources`, as the value can move once
    /// constructed and before being mutable borrowed into the `openthread::new` API method from above.
    fn init(&mut self) {
        self.rcv_frame.mPsdu = addr_of_mut!(self.rcv_psdu) as *mut _;
        self.tns_frame.mPsdu = addr_of_mut!(self.tns_psdu) as *mut _;
        self.snd_frame.mPsdu = addr_of_mut!(self.snd_psdu) as *mut _;
        self.ack_frame.mPsdu = addr_of_mut!(self.ack_psdu) as *mut _;
    }
}

/// Dataset-related OpenThread C data carriers
struct DatasetResources {
    /// The operational dataset
    dataset: otOperationalDataset,
}

impl DatasetResources {
    /// Create a new `DatasetResources` instance.
    pub const fn new() -> Self {
        unsafe {
            Self {
                dataset: MaybeUninit::zeroed().assume_init(),
            }
        }
    }
}
