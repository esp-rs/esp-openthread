#![no_std]
#![allow(async_fn_in_trait)]
#![feature(c_variadic)] // TODO: otPlatLog

use core::cell::{RefCell, RefMut};
use core::mem::MaybeUninit;
use core::net::Ipv6Addr;
use core::pin::pin;
use core::ptr::addr_of_mut;

use embassy_futures::select::{Either, Either3};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};

use embassy_time::Instant;

use esp_openthread_sys::{otMessageFree, otMessageGetLength, otMessageRead};
use platform::{OtCallCProxy, OtCallback, OtPlatformCallback, OtPlatformRadioCallback};

use rand_core::RngCore;

use sys::{otOperationalDataset, otPlatAlarmMilliFired, otTaskletsProcess};

pub use dataset::*;
pub use esp_openthread_sys as sys;
pub use radio::*;

mod dataset;
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
const IEEE802154_FRAME_TYPE_OFFSET: usize = 1;
const IEEE802154_FRAME_TYPE_MASK: u8 = 0x07;
const IEEE802154_FRAME_TYPE_BEACON: u8 = 0x00;
const IEEE802154_FRAME_TYPE_DATA: u8 = 0x01;
const IEEE802154_FRAME_TYPE_ACK: u8 = 0x02;
const IEEE802154_FRAME_TYPE_COMMAND: u8 = 0x03;

// TODO
// // ed_rss for H2 and C6 is the same
// const ENERGY_DETECT_RSS: i8 = 16;

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

pub struct OtController<'a, C, F>(&'a OpenThread<C, F>);

impl<C, F> OtController<'_, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    pub fn set_dataset(&mut self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        let mut ot_active = self.0.activate();

        dataset.store_raw(&mut ot_active.data.dataset_resources.dataset);

        ot_active.call_c(|ot_active| {
            ot!(unsafe {
                otDatasetSetActive(
                    ot_active.data.instance,
                    &ot_active.data.dataset_resources.dataset,
                )
            })
        })
    }

    /// Brings the IPv6 interface up or down.
    pub fn enable_ipv6(&mut self, enable: bool) -> Result<(), OtError> {
        self.0
            .activate()
            .call_c(|ot_active| ot!(unsafe { otIp6SetEnabled(ot_active.data.instance, enable) }))
    }

    /// This function starts Thread protocol operation.
    ///
    /// The interface must be up when calling this function.
    pub fn enable_thread(&mut self, enable: bool) -> Result<(), OtError> {
        self.0
            .activate()
            .call_c(|ot_active| ot!(unsafe { otThreadSetEnabled(ot_active.data.instance, enable) }))
    }

    /// Gets the list of IPv6 addresses assigned to the Thread interface.
    pub fn ipv6_addrs(&mut self, buf: &mut [Ipv6Addr]) -> Result<usize, OtError> {
        let mut ot_active = self.0.activate();

        let addrs = ot_active
            .call_c(|ot_active| unsafe { otIp6GetUnicastAddresses(ot_active.data.instance) });

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

    pub async fn wait_changed(&mut self) {
        self.0.signals.controller.wait().await;
    }
}

pub struct OtRunner<'a, R, C, F> {
    radio: R,
    ot: &'a OpenThread<C, F>,
}

impl<R, C, F> OtRunner<'_, R, C, F>
where
    R: Radio,
    C: RngCore,
    F: FnMut(OtRx),
{
    pub async fn run(&mut self) -> ! {
        self.ot.run(&mut self.radio).await
    }
}

pub struct OtRx(*const otMessage);

impl OtRx {
    pub fn len(&self) -> usize {
        unsafe { otMessageGetLength(self.0) as _ }
    }

    pub fn copy_to(&self, buf: &mut [u8]) {
        let len = self.len();

        if len <= buf.len() {
            unsafe {
                otMessageRead(self.0, 0, buf.as_mut_ptr() as *mut _, len as _);
            }
        }
    }
}

pub struct OtTx<'a, C, F>(&'a OpenThread<C, F>);

impl<C, F> OtTx<'_, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    pub fn tx(&mut self, packet: &[u8]) -> Result<(), OtError> {
        self.0.activate().tx_ip6(packet)
    }
}

pub struct OpenThread<C, F> {
    signals: OtSignals,
    data: RefCell<OtData>,
    rng: RefCell<C>,
    rx_ipv6: RefCell<F>,
}

impl<C, F> OpenThread<C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    pub fn new(rng: C, rx: F) -> Result<Self, OtError> {
        // TODO: Optimize the memory of this
        let this = Self {
            signals: OtSignals::new(),
            data: RefCell::new(OtData::new()),
            rng: RefCell::new(rng),
            rx_ipv6: RefCell::new(rx),
        };

        let instance = unsafe { otInstanceInitSingle() };

        log::debug!("otInstanceInitSingle done, instance = {:p}", instance);

        this.data.borrow_mut().instance = instance;

        // TODO: Remove on drop
        this.activate().call_c(|ot_active| {
            unsafe {
                otIp6SetReceiveCallback(
                    ot_active.data.instance,
                    Some(ActiveOpenThread::<C, F>::ot_c_ip6_receive_callback),
                    ot_active.data.instance as *mut _,
                )
            }

            ot!(unsafe {
                otSetStateChangedCallback(
                    ot_active.data.instance,
                    Some(ActiveOpenThread::<C, F>::ot_c_change_callback),
                    ot_active.data.instance as *mut _,
                )
            })
        })?;

        Ok(this)
    }

    pub fn split<R>(
        &mut self,
        radio: R,
    ) -> (
        OtController<'_, C, F>,
        OtTx<'_, C, F>,
        OtRunner<'_, R, C, F>,
    )
    where
        R: Radio,
    {
        self.data.borrow_mut().radio_resources.init();

        (
            OtController(&*self),
            OtTx(&*self),
            OtRunner { radio, ot: &*self },
        )
    }

    fn activate(&self) -> ActiveOpenThread<'_, C, F> {
        ActiveOpenThread::new(self)
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
            let mut psdu = [0_u8; OT_RADIO_FRAME_MAX_SIZE as usize];

            loop {
                match cmd {
                    RadioCommand::Tx => {
                        {
                            let mut data = self.data.borrow_mut();
                            psdu.copy_from_slice(&data.radio_resources.snd_psdu);

                            data.radio_status = RadioStatus::TxPending;
                        }

                        self.signals.ot.signal(());

                        let mut new_cmd = pin!(self.signals.radio.wait());
                        let mut tx = pin!(radio.transmit(&psdu));

                        let result = embassy_futures::select::select(&mut new_cmd, &mut tx).await;

                        match result {
                            Either::First(new_cmd) => {
                                cmd = new_cmd;
                                self.data.borrow_mut().radio_status = RadioStatus::TxDone; // TODO
                                self.signals.ot.signal(());
                            }
                            Either::Second(result) => {
                                result.unwrap(); // TODO

                                self.data.borrow_mut().radio_status = RadioStatus::TxDone; // TODO
                                self.signals.ot.signal(());

                                break;
                            }
                        }
                    }
                    RadioCommand::Rx(channel) => {
                        self.data.borrow_mut().radio_status = RadioStatus::RxPending;
                        self.signals.ot.signal(());

                        let result = {
                            let mut new_cmd = pin!(self.signals.radio.wait());
                            let mut rx = pin!(radio.receive(channel, &mut psdu));

                            embassy_futures::select::select(&mut new_cmd, &mut rx).await
                        };

                        match result {
                            Either::First(new_cmd) => {
                                cmd = new_cmd;
                                self.data.borrow_mut().radio_status = RadioStatus::Idle;
                                self.signals.ot.signal(());
                            }
                            Either::Second(result) => {
                                result.unwrap(); // TODO

                                {
                                    let mut data = self.data.borrow_mut();
                                    data.radio_resources.rcv_psdu.copy_from_slice(&psdu);
                                    data.radio_status = RadioStatus::RxDone;
                                }
                                self.signals.ot.signal(());

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

struct ActiveOpenThread<'a, C, F> {
    signals: &'a OtSignals,
    data: RefMut<'a, OtData>,
    rng: RefMut<'a, C>,
    rx_ipv6: RefMut<'a, F>,
}

impl<'a, C, F> ActiveOpenThread<'a, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    fn new(ot: &'a OpenThread<C, F>) -> Self {
        Self {
            signals: &ot.signals,
            data: ot.data.borrow_mut(),
            rng: ot.rng.borrow_mut(),
            rx_ipv6: ot.rx_ipv6.borrow_mut(),
        }
    }

    fn tx_ip6(&mut self, packet: &[u8]) -> Result<(), OtError> {
        self.call_c(|ot_active| {
            let msg = unsafe {
                otIp6NewMessageFromBuffer(
                    ot_active.data.instance,
                    packet.as_ptr(),
                    packet.len() as _,
                    &otMessageSettings {
                        mLinkSecurityEnabled: true,
                        mPriority: otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL as _,
                    },
                )
            };

            // TODO: Check if the message was allocated

            ot!(unsafe { otIp6Send(ot_active.data.instance, msg) })
        })
    }

    fn process(&mut self) {
        loop {
            let mut processed = false;

            processed |= self.process_tasklets();
            processed |= self.process_alarm();
            processed |= self.process_radio();

            if !processed {
                break;
            }
        }
    }

    fn process_tasklets(&mut self) -> bool {
        if self.data.run_tasklets {
            self.data.run_tasklets = false;

            self.call_c(|ot_active| unsafe { otTaskletsProcess(ot_active.data.instance) });

            true
        } else {
            false
        }
    }

    fn process_alarm(&mut self) -> bool {
        if self
            .data
            .alarm_status
            .take()
            .map(|when| when <= embassy_time::Instant::now())
            .unwrap_or(false)
        {
            self.call_c(|ot_active| unsafe { otPlatAlarmMilliFired(ot_active.data.instance) });

            true
        } else {
            false
        }
    }

    fn process_radio(&mut self) -> bool {
        match self.data.radio_status {
            RadioStatus::TxPending => {
                self.call_c(|ot_active| unsafe {
                    otPlatRadioTxStarted(
                        ot_active.data.instance,
                        &mut ot_active.data.radio_resources.snd_frame,
                    )
                });
                self.data.radio_status = RadioStatus::Idle;

                true
            }
            RadioStatus::TxDone => {
                self.call_c(|ot_active| unsafe {
                    otPlatRadioTxDone(
                        ot_active.data.instance,
                        &mut ot_active.data.radio_resources.snd_frame,
                        &mut ot_active.data.radio_resources.ack_frame,
                        otError_OT_ERROR_NONE, /* TODO*/
                    )
                });
                self.data.radio_status = RadioStatus::Idle;

                true
            }
            RadioStatus::RxDone => {
                self.call_c(|ot_active| unsafe {
                    otPlatRadioReceiveDone(
                        ot_active.data.instance,
                        &mut ot_active.data.radio_resources.rcv_frame,
                        otError_OT_ERROR_NONE, /* TODO */
                    )
                });
                self.data.radio_status = RadioStatus::Idle;

                true
            }
            // TODO
            _ => false,
        }
    }

    unsafe extern "C" fn ot_c_change_callback(flags: otChangedFlags, context: *mut c_void) {
        let instance = context as *mut otInstance;

        OtCallCProxy::ot_c_callback(instance, |cb| cb.changed(flags));
    }

    unsafe extern "C" fn ot_c_ip6_receive_callback(msg: *mut otMessage, context: *mut c_void) {
        let instance = context as *mut otInstance;

        OtCallCProxy::ot_c_callback(instance, |cb| cb.ipv6_received(msg));
    }

    fn call_c<O, T>(&mut self, f: O) -> T
    where
        O: FnOnce(&mut ActiveOpenThread<'_, C, F>) -> T,
    {
        let mut proxy = unsafe { self.call_c_proxy() };

        proxy.call(|| f(self))
    }

    unsafe fn call_c_proxy(&mut self) -> OtCallCProxy {
        OtCallCProxy::new(self.data.instance, self)
    }

    // /// Run due timers, get and forward received messages
    // ///
    // /// Make sure to periodically call this function.
    // pub fn process(&self) {
    //     crate::timer::run_if_due(self.instance);
    //     if let Some(raw) = with_radio(|radio| radio.raw_received()).unwrap() {
    //         match frame_get_type(&raw.data) {
    //             IEEE802154_FRAME_TYPE_DATA => {
    //                 let rssi: i8 = {
    //                     let idx = match (raw.data[0] as usize).cmp(&raw.data.len()) {
    //                         core::cmp::Ordering::Less => {
    //                             // guard against attempting to access the (0 - 1)th index
    //                             if raw.data[0] == 0 {
    //                                 log::warn!("raw.data[0] is 0, RSSI may be invalid",);
    //                                 0
    //                             } else {
    //                                 raw.data[0] as usize - 1
    //                             }
    //                         }
    //                         core::cmp::Ordering::Greater | core::cmp::Ordering::Equal => {
    //                             raw.data.len() - 1
    //                         }
    //                     };
    //                     raw.data[idx] as i8
    //                 };

    //                 unsafe {
    //                     // len indexes into both the RCV_FRAME_PSDU and raw.data array
    //                     // so must be sized appropriately
    //                     let len = if raw.data[0] as usize > OT_RADIO_FRAME_MAX_SIZE as usize
    //                         && raw.data[1..].len() >= OT_RADIO_FRAME_MAX_SIZE as usize
    //                     {
    //                         log::warn!(
    //                             "raw.data[0] {:?} larger than rcv frame \
    //                             psdu len and raw.data.len()! RCV {:02x?}",
    //                             raw.data[0],
    //                             &raw.data[1..][..OT_RADIO_FRAME_MAX_SIZE as usize]
    //                         );
    //                         OT_RADIO_FRAME_MAX_SIZE as usize
    //                     } else if raw.data[0] as usize > OT_RADIO_FRAME_MAX_SIZE as usize
    //                         && raw.data[1..].len() < OT_RADIO_FRAME_MAX_SIZE as usize
    //                     {
    //                         log::warn!(
    //                             "raw.data[0] {:?} larger than raw.data.len()! \
    //                             RCV {:02x?}",
    //                             raw.data[0],
    //                             &raw.data[1..][..raw.data.len() - 1]
    //                         );
    //                         raw.data[1..].len()
    //                     } else {
    //                         raw.data[0] as usize
    //                     };

    //                     log::debug!("RCV {:02x?}", &raw.data[1..][..len as usize]);

    //                     RCV_FRAME_PSDU[..len as usize]
    //                         .copy_from_slice(&raw.data[1..][..len as usize]);
    //                     RCV_FRAME.mLength = len as u16;
    //                     RCV_FRAME.mRadioType = 1; // ????
    //                     RCV_FRAME.mChannel = raw.channel;
    //                     RCV_FRAME.mInfo.mRxInfo.mRssi = rssi;
    //                     RCV_FRAME.mInfo.mRxInfo.mLqi = rssi_to_lqi(rssi);
    //                     RCV_FRAME.mInfo.mRxInfo.mTimestamp = current_millis() * 1000;

    //                     otPlatRadioReceiveDone(
    //                         self.instance,
    //                         addr_of_mut!(RCV_FRAME),
    //                         otError_OT_ERROR_NONE,
    //                     );
    //                 }
    //             }
    //             IEEE802154_FRAME_TYPE_BEACON | IEEE802154_FRAME_TYPE_COMMAND => {
    //                 log::warn!("Received beacon or mac command frame, triggering scan done");
    //                 unsafe {
    //                     otPlatRadioEnergyScanDone(self.instance, ENERGY_DETECT_RSS);
    //                 }
    //             }
    //             IEEE802154_FRAME_TYPE_ACK => {
    //                 log::debug!("Received ack frame");
    //             }
    //             _ => {
    //                 // Drop unsupported frames
    //                 log::warn!("Unsupported frame type received");
    //             }
    //         };
    //     }
    // }

    // pub fn set_radio_config(&mut self, config: Config) -> Result<(), Error> {
    //     critical_section::with(|cs| {
    //         let mut radio = RADIO.borrow_ref_mut(cs);
    //         let radio = radio.borrow_mut();

    //         if let Some(radio) = radio.as_mut() {
    //             radio.set_config(config)
    //         }
    //     });
    //     Ok(())
    // }

    // /// Set the change callback
    // pub fn set_change_callback(
    //     &mut self,
    //     callback: Option<&'a mut (dyn FnMut(ChangedFlags) + Send)>,
    // ) {
    //     critical_section::with(|cs| {
    //         let mut change_callback = CHANGE_CALLBACK.borrow_ref_mut(cs);
    //         *change_callback = unsafe { core::mem::transmute(callback) };
    //     });
    // }

    // /// Brings the IPv6 interface up or down.
    // pub fn ipv6_set_enabled(&mut self, enabled: bool) -> Result<(), OtError> {
    //     self.ot_call(|instance| ot!(unsafe { otIp6SetEnabled(instance, enabled) }))
    // }

    // /// This function starts Thread protocol operation.
    // ///
    // /// The interface must be up when calling this function.
    // pub fn thread_set_enabled(&mut self, enabled: bool) -> Result<(), OtError> {
    //     self.ot_call(|instance| ot!(unsafe { otThreadSetEnabled(instance, enabled) }))
    // }

    // /// Gets the list of IPv6 addresses assigned to the Thread interface.
    // pub fn ipv6_get_unicast_addresses<const N: usize>(
    //     &self,
    // ) -> heapless::Vec<NetworkInterfaceUnicastAddress, N> {
    //     let mut result = heapless::Vec::new();
    //     let mut addr = unsafe { otIp6GetUnicastAddresses(self.instance) };

    //     loop {
    //         let a = unsafe { &*addr };

    //         let octets = unsafe { a.mAddress.mFields.m16 };

    //         if result
    //             .push(NetworkInterfaceUnicastAddress {
    //                 address: no_std_net::Ipv6Addr::new(
    //                     octets[0].to_be(),
    //                     octets[1].to_be(),
    //                     octets[2].to_be(),
    //                     octets[3].to_be(),
    //                     octets[4].to_be(),
    //                     octets[5].to_be(),
    //                     octets[6].to_be(),
    //                     octets[7].to_be(),
    //                 ),
    //                 prefix: a.mPrefixLength,
    //                 origin: a.mAddressOrigin,
    //             })
    //             .is_err()
    //         {
    //             break;
    //         }

    //         if a.mNext.is_null() {
    //             break;
    //         }

    //         addr = a.mNext;
    //     }

    //     result
    // }

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

impl<C, F> OtCallback for ActiveOpenThread<'_, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
}

impl<C, F> OtPlatformCallback for ActiveOpenThread<'_, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    fn reset(&mut self) -> Result<(), OtError> {
        todo!()
    }

    fn rand(&mut self, buf: &mut [u8]) -> Result<(), OtError> {
        self.rng.fill_bytes(buf);

        Ok(())
    }

    fn tasklets_pending(&mut self) {
        self.data.run_tasklets = true;
        self.signals.ot.signal(());
    }

    fn ipv6_received(&mut self, msg: *mut otMessage) {
        (self.rx_ipv6)(OtRx(msg as *const _));

        unsafe {
            otMessageFree(msg);
        }
    }

    fn changed(&mut self, _flags: u32) {
        self.signals.controller.signal(());
    }

    fn now(&mut self) -> u32 {
        Instant::now().as_millis() as u32
    }

    fn alarm_set(&mut self, at0_ms: u32, adt_ms: u32) -> Result<(), OtError> {
        // TODO
        let instant =
            embassy_time::Instant::now() + embassy_time::Duration::from_millis(at0_ms as u64);

        self.data.alarm_status = Some(instant);
        self.signals.alarm.signal(instant);

        Ok(())
    }

    fn alarm_clear(&mut self) -> Result<(), OtError> {
        self.data.alarm_status = None;

        Ok(())
    }
}

impl<C, F> OtPlatformRadioCallback for ActiveOpenThread<'_, C, F>
where
    C: RngCore,
    F: FnMut(OtRx),
{
    fn ieee_eui64(&mut self, mac: &mut [u8; 6]) {
        mac.fill(0);
    }

    fn caps(&mut self) -> u8 {
        0 // TODO
    }

    fn enabled(&mut self) -> bool {
        true // TODO
    }

    fn rssi(&mut self) -> i8 {
        -128 // TODO
    }

    fn receive_sensitivity(&mut self) -> i8 {
        0 // TODO
    }

    fn promiscuous(&mut self) -> bool {
        false // TODO
    }

    fn set_enabled(&mut self, _enabled: bool) -> Result<(), OtError> {
        Ok(()) // TODO
    }

    fn set_promiscuous(&mut self, _promiscuous: bool) {
        // TODO
    }

    fn set_extended_address(&mut self, _address: u64) {
        // TODO
    }

    fn set_short_address(&mut self, _address: u16) {
        // TODO
    }

    fn set_pan_id(&mut self, _pan_id: u16) {
        // TODO
    }

    fn energy_scan(&mut self, _channel: u8, _duration: u16) -> Result<(), OtError> {
        unreachable!()
    }

    fn sleep(&mut self) -> Result<(), OtError> {
        unreachable!()
    }

    fn transmit_buffer(&mut self) -> *mut otRadioFrame {
        // TODO: This frame is private to us, perhaps don't store it in a RefCell?
        &mut self.data.radio_resources.tns_frame
    }

    fn transmit(&mut self, frame: &otRadioFrame) -> Result<(), OtError> {
        let psdu = unsafe { core::slice::from_raw_parts_mut(frame.mPsdu, frame.mLength as _) };

        self.data.radio_resources.snd_frame = *frame;
        self.data.radio_resources.snd_psdu[..psdu.len()].copy_from_slice(psdu);
        self.data.radio_resources.snd_frame.mPsdu =
            addr_of_mut!(self.data.radio_resources.snd_psdu) as *mut _;

        self.signals.radio.signal(RadioCommand::Tx);

        Ok(())
    }

    fn receive(&mut self, channel: u8) -> Result<(), OtError> {
        self.signals.radio.signal(RadioCommand::Rx(channel));

        Ok(())
    }
}

struct OtData {
    instance: *mut otInstance,
    radio_resources: RadioResources,
    dataset_resources: DatasetResources,
    radio_status: RadioStatus,
    alarm_status: Option<embassy_time::Instant>,
    run_tasklets: bool,
}

impl OtData {
    const fn new() -> Self {
        Self {
            instance: core::ptr::null_mut(),
            radio_resources: RadioResources::new(),
            dataset_resources: DatasetResources::new(),
            radio_status: RadioStatus::Idle,
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
}

impl OtSignals {
    const fn new() -> Self {
        Self {
            radio: Signal::new(),
            alarm: Signal::new(),
            controller: Signal::new(),
            ot: Signal::new(),
        }
    }
}

#[derive(Debug)]
enum RadioCommand {
    Tx,
    Rx(u8),
}

#[derive(Debug)]
enum RadioStatus {
    Idle,
    TxPending,
    TxDone,
    RxPending,
    RxDone,
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
// TODO: Figure out how to initialise efficiently
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

fn frame_get_type(frame: &[u8]) -> u8 {
    if frame.len() <= IEEE802154_FRAME_TYPE_OFFSET {
        return 0;
    }
    frame[IEEE802154_FRAME_TYPE_OFFSET] & IEEE802154_FRAME_TYPE_MASK
}
