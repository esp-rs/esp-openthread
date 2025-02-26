#![no_std]
#![allow(async_fn_in_trait)]
#![feature(c_variadic)] // TODO: otPlatLog

use core::cell::{RefCell, RefMut};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::net::Ipv6Addr;
use core::pin::pin;
use core::ptr::addr_of_mut;

use embassy_futures::select::{Either, Either3};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};

use embassy_time::Instant;

use platform::OT_ACTIVE_STATE;

use rand_core::RngCore;

use sys::{
    otMessageFree, otMessageGetLength, otMessageRead, otOperationalDataset, otPlatAlarmMilliFired,
    otPlatRadioEnergyScanDone, otTaskletsProcess,
};

pub use dataset::*;
pub use esp_openthread_sys as sys;
pub use radio::*;

mod dataset;
#[cfg(any(feature = "embassy-net-driver-channel"))]
pub mod enet;
#[cfg(any(feature = "esp32h2", feature = "esp32c6"))]
pub mod esp;
mod platform;
mod radio;
#[cfg(feature = "srp-client")]
mod srp_client;

use sys::{
    c_void, otChangedFlags, otDatasetSetActive, otError, otError_OT_ERROR_NONE, otInstance,
    otInstanceInitSingle, otIp6GetUnicastAddresses, otIp6NewMessageFromBuffer, otIp6Send,
    otIp6SetEnabled, otIp6SetReceiveCallback, otMessage,
    otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL, otMessageSettings, otPlatRadioReceiveDone,
    otPlatRadioTxDone, otPlatRadioTxStarted, otRadioFrame, otSetStateChangedCallback,
    otThreadSetEnabled, OT_RADIO_FRAME_MAX_SIZE,
};

/// https://github.com/espressif/esp-idf/blob/release/v5.3/components/ieee802154/private_include/esp_ieee802154_frame.h#L20
const IEEE802154_FRAME_TYPE_OFFSET: usize = 0; // .. as we have removed the PHR and we are indexing the PSDU
const IEEE802154_FRAME_TYPE_MASK: u8 = 0x07;
const IEEE802154_FRAME_TYPE_BEACON: u8 = 0x00;
const IEEE802154_FRAME_TYPE_DATA: u8 = 0x01;
const IEEE802154_FRAME_TYPE_ACK: u8 = 0x02;
const IEEE802154_FRAME_TYPE_COMMAND: u8 = 0x03;

// ed_rss for H2 and C6 is the same
const ENERGY_DETECT_RSS: i8 = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtError(otError);

impl OtError {
    pub const fn new(value: otError) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> otError {
        self.0
    }
}

impl From<u32> for OtError {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

macro_rules! ot {
    ($code: expr) => {{
        match $code {
            $crate::sys::otError_OT_ERROR_NONE => Ok(()),
            err => Err($crate::OtError::new(err)),
        }
    }};
}

pub trait IntoOtCode {
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

pub fn new<'a>(
    rng: &'a mut dyn RngCore,
    resources: &'a mut OtResources,
) -> Result<(OtController<'a>, OtRx<'a>, OtTx<'a>, OtRunner<'a>), OtError> {
    let state = &*resources.init(unsafe { core::mem::transmute(rng) })?;

    Ok((
        OtController(state),
        OtRx(state),
        OtTx(state),
        OtRunner(state),
    ))
}

pub struct OtController<'a>(&'a OtState);

impl OtController<'_> {
    pub fn set_dataset(&mut self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        let mut ot = self.0.activate();
        let state = ot.state();

        dataset.store_raw(&mut state.data.dataset_resources.dataset);

        ot!(unsafe {
            otDatasetSetActive(state.data.instance, &state.data.dataset_resources.dataset)
        })
    }

    /// Brings the IPv6 interface up or down.
    pub fn enable_ipv6(&mut self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.0.activate();
        let state = ot.state();

        ot!(unsafe { otIp6SetEnabled(state.data.instance, enable) })
    }

    /// This function starts Thread protocol operation.
    ///
    /// The interface must be up when calling this function.
    pub fn enable_thread(&mut self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.0.activate();
        let state = ot.state();

        ot!(unsafe { otThreadSetEnabled(state.data.instance, enable) })
    }

    /// Gets the list of IPv6 addresses assigned to the Thread interface.
    pub fn ipv6_addrs(&mut self, buf: &mut [Ipv6Addr]) -> Result<usize, OtError> {
        let mut ot = self.0.activate();
        let state = ot.state();

        let addrs = unsafe { otIp6GetUnicastAddresses(state.data.instance) };

        let mut offset = 0;

        while !addrs.is_null() {
            let addrs = unsafe { addrs.as_ref() }.unwrap();

            if offset < buf.len() {
                buf[offset] = unsafe { addrs.mAddress.mFields.m16 }.into();
            }

            offset += 1;
        }

        Ok(offset)
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

    pub async fn wait_changed(&mut self) {
        self.0.signals.controller.wait().await;
    }
}

pub struct OtRunner<'a>(&'a OtState);

impl OtRunner<'_> {
    pub async fn run<R>(&mut self, radio: R) -> !
    where
        R: Radio,
    {
        self.0.run(radio).await
    }
}

pub struct OtRx<'a>(&'a OtState);

impl OtRx<'_> {
    pub async fn wait_available(&mut self) -> Result<(), OtError> {
        loop {
            {
                let data = self.0.data.borrow_mut();

                if !data.rcv_packet_ipv6.is_null() {
                    break;
                }
            }

            self.0.signals.rx_ipv6.wait().await;
        }

        Ok(())
    }

    pub async fn rx(&mut self, buf: &mut [u8]) -> Result<usize, OtError> {
        loop {
            {
                let mut data = self.0.data.borrow_mut();

                if !data.rcv_packet_ipv6.is_null() {
                    let len = unsafe { otMessageGetLength(data.rcv_packet_ipv6) as usize };

                    unsafe {
                        otMessageRead(
                            data.rcv_packet_ipv6,
                            0,
                            buf.as_mut_ptr() as *mut _,
                            len.min(buf.len()) as _,
                        );
                        otMessageFree(data.rcv_packet_ipv6);
                    }

                    data.rcv_packet_ipv6 = core::ptr::null_mut();

                    return Ok(len);
                }
            }

            self.0.signals.rx_ipv6.wait().await;
        }
    }
}

pub struct OtTx<'a>(&'a OtState);

impl OtTx<'_> {
    pub async fn wait_available(&mut self) -> Result<(), OtError> {
        Ok(())
    }

    pub async fn tx(&mut self, packet: &[u8]) -> Result<(), OtError> {
        self.0.activate().tx_ip6(packet)
    }
}

pub struct OtResources {
    state: MaybeUninit<OtState>,
}

impl Default for OtResources {
    fn default() -> Self {
        Self::new()
    }
}

impl OtResources {
    // TODO: Not ideal, as its content is not all-zeroes so it won't end up in the BSS segment
    // Ideally we should initialize it piece by piece
    const INIT: OtState = OtState::new();

    pub const fn new() -> Self {
        Self {
            state: MaybeUninit::uninit(),
        }
    }

    // TODO: Need to manually drop/reset the signals in OtSignals
    fn init(&mut self, rng: &'static mut dyn RngCore) -> Result<&mut OtState, OtError> {
        self.state.write(Self::INIT);

        let state = unsafe { self.state.assume_init_mut() };

        state.data.borrow_mut().radio_resources.init();
        state.init(rng)?;

        Ok(state)
    }
}

struct OtState {
    signals: OtSignals,
    data: RefCell<OtData>,
}

impl OtState {
    const fn new() -> Self {
        Self {
            signals: OtSignals::new(),
            data: RefCell::new(OtData::new()),
        }
    }

    fn init(&mut self, rng: &'static mut dyn RngCore) -> Result<(), OtError> {
        let instance = unsafe { otInstanceInitSingle() };

        log::debug!("otInstanceInitSingle done, instance = {:p}", instance);

        {
            let mut data = self.data.borrow_mut();

            // TODO: Need to deinitialize the OT instance at some point?

            data.instance = instance;
            data.rng = Some(rng);
        }

        {
            let mut ot = self.activate();
            let state = ot.state();

            // TODO: Remove on drop

            ot!(unsafe {
                otSetStateChangedCallback(
                    state.data.instance,
                    Some(OpenThread::plat_c_change_callback),
                    state.data.instance as *mut _,
                )
            })?;

            unsafe {
                otIp6SetReceiveCallback(
                    state.data.instance,
                    Some(OpenThread::plat_c_ip6_receive_callback),
                    state.data.instance as *mut _,
                )
            }
        }

        Ok(())
    }

    fn activate(&self) -> OpenThread<'_> {
        OpenThread::activate_for(self)
    }

    async fn run<R>(&self, radio: R) -> !
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

    async fn run_alarm(&self) -> ! {
        loop {
            let mut when = self.signals.alarm.wait().await;

            loop {
                let result = embassy_futures::select::select(
                    self.signals.alarm.wait(),
                    embassy_time::Timer::at(when),
                )
                .await;

                match result {
                    Either::First(new_when) => when = new_when,
                    Either::Second(_) => {
                        self.signals.ot.signal(());
                        break;
                    }
                }
            }
        }
    }

    async fn run_radio<R>(&self, mut radio: R) -> !
    where
        R: Radio,
    {
        loop {
            let mut cmd = self.signals.radio.wait().await;

            // TODO: Borrow it from the resources
            let mut psdu_buf = [0_u8; OT_RADIO_FRAME_MAX_SIZE as usize];

            loop {
                match cmd {
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

                        let mut new_cmd = pin!(self.signals.radio.wait());
                        let mut tx = pin!(radio.transmit(&psdu_buf[..psdu_len]));

                        let result = embassy_futures::select::select(&mut new_cmd, &mut tx).await;

                        match result {
                            Either::First(new_cmd) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                unsafe {
                                    otPlatRadioTxDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.snd_frame,
                                        &mut state.data.radio_resources.ack_frame,
                                        otError_OT_ERROR_NONE, // TODO
                                    );
                                }

                                cmd = new_cmd;
                            }
                            Either::Second(result) => {
                                result.unwrap(); // TODO

                                let mut ot = self.activate();
                                let state = ot.state();

                                unsafe {
                                    otPlatRadioTxDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.snd_frame,
                                        &mut state.data.radio_resources.ack_frame,
                                        otError_OT_ERROR_NONE, // TODO
                                    );
                                }

                                break;
                            }
                        }
                    }
                    RadioCommand::Rx(channel) => {
                        let result = {
                            let mut new_cmd = pin!(self.signals.radio.wait());
                            let mut rx = pin!(radio.receive(channel, &mut psdu_buf));

                            embassy_futures::select::select(&mut new_cmd, &mut rx).await
                        };

                        match result {
                            Either::First(new_cmd) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                unsafe {
                                    otPlatRadioReceiveDone(
                                        state.data.instance,
                                        &mut state.data.radio_resources.rcv_frame,
                                        otError_OT_ERROR_NONE, // TODO
                                    );
                                }

                                cmd = new_cmd;
                            }
                            Either::Second(result) => {
                                let psdu_meta = result.unwrap(); // TODO

                                let mut ot = self.activate();
                                let state = ot.state();

                                state.data.radio_resources.rcv_psdu[..psdu_meta.len]
                                    .copy_from_slice(&psdu_buf[..psdu_meta.len]);

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

                                let psdu = &psdu_buf[..psdu_meta.len];

                                match frame_type(psdu) {
                                    IEEE802154_FRAME_TYPE_DATA => {
                                        log::debug!("RCV {:02x?}", psdu);

                                        let rssi = psdu_meta.rssi.unwrap_or(0);

                                        state.data.radio_resources.rcv_frame.mLength =
                                            psdu.len() as u16;
                                        state.data.radio_resources.rcv_frame.mRadioType = 1; // ????
                                        state.data.radio_resources.rcv_frame.mChannel = channel;
                                        state.data.radio_resources.rcv_frame.mInfo.mRxInfo.mRssi =
                                            rssi;
                                        state.data.radio_resources.rcv_frame.mInfo.mRxInfo.mLqi =
                                            rssi_to_lqi(rssi);
                                        state
                                            .data
                                            .radio_resources
                                            .rcv_frame
                                            .mInfo
                                            .mRxInfo
                                            .mTimestamp = Instant::now().as_micros();

                                        unsafe {
                                            otPlatRadioReceiveDone(
                                                state.data.instance,
                                                &mut state.data.radio_resources.rcv_frame,
                                                otError_OT_ERROR_NONE, // TODO
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_BEACON
                                    | IEEE802154_FRAME_TYPE_COMMAND => {
                                        log::warn!("Received beacon or MAC command frame, triggering scan done");

                                        unsafe {
                                            otPlatRadioEnergyScanDone(
                                                state.data.instance,
                                                ENERGY_DETECT_RSS,
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_ACK => {
                                        log::debug!("Received ack frame");
                                    }
                                    _ => {
                                        // Drop unsupported frames
                                        log::warn!("Unsupported frame type received");
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

    async fn run_openthread(&self) -> ! {
        loop {
            self.activate().process();
            self.signals.ot.wait().await;
        }
    }
}

struct OtActiveState<'a> {
    signals: &'a OtSignals,
    data: RefMut<'a, OtData>,
}

impl<'a> OtActiveState<'a> {
    fn new(ot: &'a OtState) -> Self {
        Self {
            signals: &ot.signals,
            data: ot.data.borrow_mut(),
        }
    }
}

unsafe impl Send for OtActiveState<'_> {}

struct OpenThread<'a> {
    callback: bool,
    _t: PhantomData<&'a mut ()>,
}

impl<'a> OpenThread<'a> {
    fn activate_for(ot: &'a OtState) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.is_none());

        *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() =
            Some(unsafe { core::mem::transmute(OtActiveState::new(ot)) });

        Self {
            callback: false,
            _t: PhantomData,
        }
    }

    fn callback(_instance: *const otInstance) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.is_some());

        Self {
            callback: true,
            _t: PhantomData,
        }
    }

    fn state(&mut self) -> &mut OtActiveState<'a> {
        unsafe { core::mem::transmute(OT_ACTIVE_STATE.0.get().as_mut().unwrap().as_mut().unwrap()) }
    }

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

        // TODO: Check if the message was allocated

        ot!(unsafe { otIp6Send(state.data.instance, msg) })
    }

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

    fn process_tasklets(&mut self) -> bool {
        let state = self.state();

        if state.data.run_tasklets {
            state.data.run_tasklets = false;

            unsafe { otTaskletsProcess(state.data.instance) };

            true
        } else {
            false
        }
    }

    fn process_alarm(&mut self) -> bool {
        let state = self.state();

        if state
            .data
            .alarm_status
            .take()
            .map(|when| when <= embassy_time::Instant::now())
            .unwrap_or(false)
        {
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
        let state = self.state();

        if !state.data.rcv_packet_ipv6.is_null() {
            state.data.rcv_packet_ipv6 = msg;
            state.signals.rx_ipv6.signal(());
        } else {
            unsafe {
                otMessageFree(msg);
            }
        }
    }

    fn plat_changed(&mut self, _flags: u32) {
        self.state().signals.controller.signal(());
    }

    fn plat_now(&mut self) -> u32 {
        Instant::now().as_millis() as u32
    }

    fn plat_alarm_set(&mut self, at0_ms: u32, adt_ms: u32) -> Result<(), OtError> {
        let state = self.state();

        let instant = embassy_time::Instant::from_millis(at0_ms as _)
            + embassy_time::Duration::from_millis(adt_ms as _);

        state.data.alarm_status = Some(instant);
        state.signals.alarm.signal(instant);

        Ok(())
    }

    fn plat_alarm_clear(&mut self) -> Result<(), OtError> {
        self.state().data.alarm_status = None;

        Ok(())
    }

    fn plat_radio_ieee_eui64(&mut self, mac: &mut [u8; 6]) {
        mac.fill(0);
    }

    fn plat_radio_caps(&mut self) -> u8 {
        0 // TODO
    }

    fn plat_radio_is_enabled(&mut self) -> bool {
        true // TODO
    }

    fn plat_radio_get_rssi(&mut self) -> i8 {
        -128 // TODO
    }

    // from https://github.com/espressif/esp-idf/blob/release/v5.3/components/openthread/src/port/esp_openthread_radio.c#L35
    fn plat_radio_receive_sensititivy(&mut self) -> i8 {
        0 // TODO
    }

    fn plat_radio_get_promiscuous(&mut self) -> bool {
        false // TODO
    }

    fn plat_radio_enable(&mut self) -> Result<(), OtError> {
        Ok(()) // TODO
    }

    fn plat_radio_disable(&mut self) -> Result<(), OtError> {
        Ok(()) // TODO
    }

    fn plat_radio_set_promiscuous(&mut self, _promiscuous: bool) {
        // TODO
    }

    fn plat_radio_set_extended_address(&mut self, _address: u64) {
        // TODO
    }

    fn plat_radio_set_short_address(&mut self, _address: u16) {
        // TODO
    }

    fn plat_radio_set_pan_id(&mut self, _pan_id: u16) {
        // TODO
    }

    fn plat_radio_energy_scan(&mut self, _channel: u8, _duration: u16) -> Result<(), OtError> {
        unreachable!()
    }

    fn plat_radio_sleep(&mut self) -> Result<(), OtError> {
        unreachable!()
    }

    fn plat_radio_transmit_buffer(&mut self) -> *mut otRadioFrame {
        // TODO: This frame is private to us, perhaps don't store it in a RefCell?
        &mut self.state().data.radio_resources.tns_frame
    }

    fn plat_radio_transmit(&mut self, frame: &otRadioFrame) -> Result<(), OtError> {
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
        self.state().signals.radio.signal(RadioCommand::Rx(channel));

        Ok(())
    }

    // /// Creates a new UDP socket
    // pub fn get_udp_socket<'s, const BUFFER_SIZE: usize>(
    //     &'s self,
    // ) -> Result<UdpSocket<'s, 'a, BUFFER_SIZE>, Error>
    // where
    //     'a: 's,
    // {
    //     let ot_socket = otUdpSocket {
    //         mSockName: otSockAddr {
    //             mAddress: otIp6Address {
    //                 mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
    //             },
    //             mPort: 0,
    //         },
    //         mPeerName: otSockAddr {
    //             mAddress: otIp6Address {
    //                 mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
    //             },
    //             mPort: 0,
    //         },
    //         mHandler: Some(udp_receive_handler),
    //         mContext: core::ptr::null_mut(),
    //         mHandle: core::ptr::null_mut(),
    //         mNext: core::ptr::null_mut(),
    //     };

    //     Ok(UdpSocket {
    //         ot_socket,
    //         ot: self,
    //         receive_len: 0,
    //         receive_from: [0u8; 16],
    //         receive_port: 0,
    //         max: BUFFER_SIZE,
    //         _pinned: PhantomPinned::default(),
    //         receive_buffer: [0u8; BUFFER_SIZE],
    //     })
    // }

    // pub fn get_eui(&self, out: &mut [u8]) {
    //     unsafe { otPlatRadioGetIeeeEui64(self.instance, out.as_mut_ptr()) }
    // }

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
}

impl Drop for OpenThread<'_> {
    fn drop(&mut self) {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_some());

        if !self.callback {
            *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() = None;
        }
    }
}

struct OtData {
    instance: *mut otInstance,
    rng: Option<&'static mut dyn RngCore>,
    rcv_packet_ipv6: *mut otMessage,
    radio_resources: RadioResources,
    dataset_resources: DatasetResources,
    alarm_status: Option<embassy_time::Instant>,
    run_tasklets: bool,
}

impl OtData {
    const fn new() -> Self {
        Self {
            instance: core::ptr::null_mut(),
            rng: None,
            rcv_packet_ipv6: core::ptr::null_mut(),
            radio_resources: RadioResources::new(),
            dataset_resources: DatasetResources::new(),
            alarm_status: None,
            run_tasklets: false,
        }
    }
}

struct OtSignals {
    radio: Signal<NoopRawMutex, RadioCommand>,
    alarm: Signal<NoopRawMutex, embassy_time::Instant>,
    controller: Signal<NoopRawMutex, ()>,
    ot: Signal<NoopRawMutex, ()>,
    rx_ipv6: Signal<NoopRawMutex, ()>,
}

impl OtSignals {
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

#[derive(Debug)]
enum RadioCommand {
    Tx,
    Rx(u8),
}

// TODO: Figure out how to init efficiently
struct RadioResources {
    rcv_frame: otRadioFrame,
    tns_frame: otRadioFrame,
    snd_frame: otRadioFrame,
    ack_frame: otRadioFrame,
    rcv_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    tns_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    snd_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    ack_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
}

impl RadioResources {
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

    fn init(&mut self) {
        self.rcv_frame.mPsdu = addr_of_mut!(self.rcv_psdu) as *mut _;
        self.tns_frame.mPsdu = addr_of_mut!(self.tns_psdu) as *mut _;
        self.snd_frame.mPsdu = addr_of_mut!(self.snd_psdu) as *mut _;
        self.ack_frame.mPsdu = addr_of_mut!(self.ack_psdu) as *mut _;
    }
}

struct DatasetResources {
    dataset: otOperationalDataset,
}

impl DatasetResources {
    pub const fn new() -> Self {
        unsafe {
            Self {
                dataset: MaybeUninit::zeroed().assume_init(),
            }
        }
    }
}

/// From https://github.com/espressif/esp-idf/blob/release/v5.3/components/ieee802154/driver/esp_ieee802154_frame.c#L45
#[allow(unused)]
fn is_supported_frame_type_raw(frame_type: u8) -> bool {
    frame_type == IEEE802154_FRAME_TYPE_BEACON
        || frame_type == IEEE802154_FRAME_TYPE_DATA
        || frame_type == IEEE802154_FRAME_TYPE_ACK
        || frame_type == IEEE802154_FRAME_TYPE_COMMAND // Are child nodes expected to respond to MacCommand frames?
}
