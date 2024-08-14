#![no_std]
#![feature(c_variadic)]

mod entropy;
mod platform;
mod radio;
mod timer;

use core::{
    borrow::BorrowMut,
    cell::RefCell,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    ptr::addr_of_mut,
};

use bitflags::bitflags;
use critical_section::Mutex;
use esp_hal::timer::systimer::{Alarm, Target};
use esp_ieee802154::{rssi_to_lqi, Ieee802154};

// for now just re-export all
pub use esp_openthread_sys as sys;
use no_std_net::Ipv6Addr;
use sys::{
    bindings::{
        __BindgenBitfieldUnit, otChangedFlags, otDatasetSetActive, otError_OT_ERROR_NONE,
        otExtendedPanId, otInstance, otInstanceInitSingle, otIp6Address,
        otIp6Address__bindgen_ty_1, otIp6GetUnicastAddresses, otIp6SetEnabled, otMeshLocalPrefix,
        otMessage, otMessageAppend, otMessageFree, otMessageGetLength, otMessageInfo,
        otMessageRead, otNetifIdentifier_OT_NETIF_THREAD, otNetworkKey, otNetworkName,
        otOperationalDataset, otOperationalDatasetComponents, otPlatRadioReceiveDone, otPskc,
        otRadioFrame, otRadioFrame__bindgen_ty_1, otRadioFrame__bindgen_ty_1__bindgen_ty_2,
        otSecurityPolicy, otSetStateChangedCallback, otSockAddr, otTaskletsArePending,
        otTaskletsProcess, otThreadSetEnabled, otTimestamp, otUdpBind, otUdpClose, otUdpNewMessage,
        otUdpOpen, otUdpSend, otUdpSocket, OT_NETWORK_NAME_MAX_SIZE, OT_RADIO_FRAME_MAX_SIZE,
    },
    c_types::c_void,
};

use crate::timer::current_millis;

static RADIO: Mutex<RefCell<Option<&'static mut Ieee802154>>> = Mutex::new(RefCell::new(None));

static NETWORK_SETTINGS: Mutex<RefCell<Option<NetworkSettings>>> = Mutex::new(RefCell::new(None));

static CHANGE_CALLBACK: Mutex<RefCell<Option<&'static mut (dyn FnMut(ChangedFlags) + Send)>>> =
    Mutex::new(RefCell::new(None));

static mut RCV_FRAME_PSDU: [u8; OT_RADIO_FRAME_MAX_SIZE as usize] =
    [0u8; OT_RADIO_FRAME_MAX_SIZE as usize];
static mut RCV_FRAME: otRadioFrame = otRadioFrame {
    mPsdu: unsafe { addr_of_mut!(RCV_FRAME_PSDU) as *mut u8 },
    mLength: 0,
    mChannel: 0,
    mRadioType: 0,
    mInfo: otRadioFrame__bindgen_ty_1 {
        mRxInfo: otRadioFrame__bindgen_ty_1__bindgen_ty_2 {
            mTimestamp: 0,
            mAckFrameCounter: 0,
            mAckKeyId: 0,
            mRssi: 0,
            mLqi: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
        },
    },
};

#[doc(hidden)]
#[macro_export]
macro_rules! checked {
    ($value:expr) => {
        if $value != 0 {
            Err(crate::Error::InternalError($value))
        } else {
            core::result::Result::<(), crate::Error>::Ok(())
        }
    };
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Error {
    InternalError(u32),
}

bitflags! {
    /// Specific state/configuration that has changed
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ChangedFlags: u32 {
        /// IPv6 address was added
        const Ipv6AddressAdded = 1;
        /// IPv6 address was removed
        const Ipv6AddressRemoved = 2;
        /// Role (disabled, detached, child, router, leader) changed
        const ThreadRoleChanged = 4;
        /// The link-local address changed
        const ThreadLlAddressChanged = 8;
        /// The mesh-local address changed
        const ThreadMeshLocalAddressChanged = 16;
        ///  RLOC was added
        const ThreadRlocAdded = 32;
        /// RLOC was removed
        const ThreadRlocRemoved = 64;
        /// Partition ID changed
        const ThreadPartitionIdChanged = 128;
        /// Thread Key Sequence changed
        const ThreadKeySequenceChanged = 256;
        /// Thread Network Data changed
        const ThreadNetworkDataChanged = 512;
        /// Child was added
        const ThreadChildAdded = 1024;
        /// Child was removed
        const ThreadChildRemoved = 2048;
        /// Subscribed to a IPv6 multicast address
        const Ipv6MulticastSubscribed = 4096;
        /// Unsubscribed from a IPv6 multicast address
        const Ipv6MulticastUnsubscribed = 8192;
        /// Thread network channel changed
        const ThreadNetworkChannelChanged = 16384;
        /// Thread network PAN Id changed
        const ThreadPanIdChanged = 32768;
        /// Thread network name changed
        const ThreadNetworkNameChanged = 65536;
        /// Thread network extended PAN ID changed
        const ThreadExtendedPanIdChanged = 131072;
        /// Network key changed
        const ThreadNetworkKeyChanged = 262144;
        /// PSKc changed
        const ThreadPskcChanged = 524288;
        /// Security Policy changed
        const ThreadSecurityPolicyChanged = 1048576;
        /// Channel Manager new pending Thread channel changed
        const ChannelManagerNewChannelChanged = 2097152;
        /// Supported channel mask changed
        const SupportedChannelMaskChanged = 4194304;
        /// Commissioner state changed
        const CommissionerStateChanged = 8388608;
        /// Thread network interface state changed
        const ThreadNetworkInterfaceStateChanged = 16777216;
        /// Backbone Router state changed
        const ThreadBackboneRouterStateChanged = 33554432;
        /// Local Backbone Router configuration changed
        const ThreadBackboneRouterLocalChanged = 67108864;
        /// Joiner state changed
        const JoinerStateChanged = 134217728;
        /// Active Operational Dataset changed
        const ActiveDatasetChanged = 268435456;
        /// Pending Operational Dataset changed
        const PendingDatasetChanged = 536870912;


    }
}

/// IPv6 network interface unicast address
#[derive(Debug, Clone, Copy)]
pub struct NetworkInterfaceUnicastAddress {
    /// The IPv6 unicast address
    pub address: no_std_net::Ipv6Addr,
    /// The Prefix length (in bits)
    pub prefix: u8,
    /// The IPv6 address origin
    pub origin: u8,
}

/// Thread Dataset timestamp
#[derive(Debug, Clone, Copy)]
pub struct ThreadTimestamp {
    pub seconds: u64,
    pub ticks: u16,
    pub authoritative: bool,
}

/// Security Policy
#[derive(Debug, Clone, Default)]
pub struct SecurityPolicy {
    /// The value for thrKeyRotation in units of hours.
    pub rotation_time: u16,
    /// Autonomous Enrollment is enabled.
    pub autonomous_enrollment_enabled: bool,
    /// Commercial Commissioning is enabled.
    pub commercial_commissioning_enabled: bool,
    /// External Commissioner authentication is allowed.
    pub external_commissioning_enabled: bool,
    /// Native Commissioning using PSKc is allowed.
    pub native_commissioning_enabled: bool,
    /// Network Key Provisioning is enabled.
    pub network_key_provisioning_enabled: bool,
    /// Non-CCM Routers enabled.
    pub non_ccm_routers_enabled: bool,
    /// Obtaining the Network Key for out-of-band commissioning is enabled.
    pub obtain_network_key_enabled: bool,
    /// Thread 1.0/1.1.x Routers are enabled.
    pub routers_enabled: bool,
    /// ToBLE link is enabled.
    pub toble_link_enabled: bool,
    /// Version-threshold for Routing.
    pub version_threshold_for_routing: u8,
}

/// Active or Pending Operational Dataset
#[derive(Debug, Clone, Default)]
pub struct OperationalDataset {
    /// Active Timestamp
    pub active_timestamp: Option<ThreadTimestamp>,
    /// Pending Timestamp
    pub pending_timestamp: Option<ThreadTimestamp>,
    /// Network Key
    pub network_key: Option<[u8; 16]>,
    /// Network name
    pub network_name: Option<heapless::String<{ OT_NETWORK_NAME_MAX_SIZE as usize }>>,
    /// Extended PAN ID
    pub extended_pan_id: Option<[u8; 8]>,
    /// Mesh Local Prefix
    pub mesh_local_prefix: Option<[u8; 8]>,
    /// Delay Timer
    pub delay: Option<u32>,
    /// PAN ID
    pub pan_id: Option<u16>,
    /// Channel
    pub channel: Option<u16>,
    /// PSKc
    pub pskc: Option<[u8; 16]>,
    /// Security Policy.
    pub security_policy: Option<SecurityPolicy>,
    /// Channel Mask
    pub channel_mask: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
struct NetworkSettings {
    promiscuous: bool,
    rx_when_idle: bool,
    ext_address: u64,
    short_address: u16,
    pan_id: u16,
    channel: u8,
}

/// Instance of OpenThread
#[non_exhaustive]
pub struct OpenThread<'a> {
    _phantom: PhantomData<&'a ()>,
    // pub for now
    pub instance: *mut otInstance,
}

impl<'a> OpenThread<'a> {
    pub fn new(
        radio: &'a mut Ieee802154,
        timer: Alarm<Target, esp_hal::Blocking, 0>,
        rng: esp_hal::rng::Rng,
    ) -> Self {
        timer::install_isr(timer);
        entropy::init_rng(rng);

        radio.set_tx_done_callback_fn(radio::trigger_tx_done);

        critical_section::with(|cs| {
            RADIO
                .borrow_ref_mut(cs)
                .replace(unsafe { core::mem::transmute(radio) });
        });

        let instance = unsafe { otInstanceInitSingle() };
        log::debug!("otInstanceInitSingle done, instance = {:p}", instance);

        let res = unsafe {
            otSetStateChangedCallback(instance, Some(change_callback), core::ptr::null_mut())
        };
        log::debug!("otSetStateChangedCallback {res}");

        Self {
            _phantom: PhantomData,
            instance,
        }
    }

    /// Sets the Active Operational Dataset
    pub fn set_active_dataset(&mut self, dataset: OperationalDataset) -> Result<(), Error> {
        let mut raw_dataset = otOperationalDataset {
            mActiveTimestamp: otTimestamp {
                mSeconds: 0,
                mTicks: 0,
                mAuthoritative: false,
            },
            mPendingTimestamp: otTimestamp {
                mSeconds: 0,
                mTicks: 0,
                mAuthoritative: false,
            },
            mNetworkKey: otNetworkKey { m8: [0u8; 16] },
            mNetworkName: otNetworkName { m8: [0i8; 17] },
            mExtendedPanId: otExtendedPanId { m8: [0u8; 8] },
            mMeshLocalPrefix: otMeshLocalPrefix { m8: [0u8; 8] },
            mDelay: 0,
            mPanId: 0,
            mChannel: 0,
            mPskc: otPskc { m8: [0u8; 16] },
            mSecurityPolicy: otSecurityPolicy {
                mRotationTime: 0,
                _bitfield_align_1: [0u8; 0],
                _bitfield_1: otSecurityPolicy::new_bitfield_1(
                    false, false, false, false, false, false, false, false, false, 0,
                ),
            },
            mChannelMask: 0,
            mComponents: otOperationalDatasetComponents {
                mIsActiveTimestampPresent: true,
                mIsPendingTimestampPresent: false,
                mIsNetworkKeyPresent: true,
                mIsNetworkNamePresent: true,
                mIsExtendedPanIdPresent: true,
                mIsMeshLocalPrefixPresent: false,
                mIsDelayPresent: false,
                mIsPanIdPresent: true,
                mIsChannelPresent: true,
                mIsPskcPresent: false,
                mIsSecurityPolicyPresent: false,
                mIsChannelMaskPresent: false,
            },
        };

        let mut active_timestamp_present = false;
        let mut pending_timestamp_present = false;
        let mut network_key_present = false;
        let mut network_name_present = false;
        let mut extended_pan_present = false;
        let mut mesh_local_prefix_present = false;
        let mut delay_present = false;
        let mut pan_id_present = false;
        let mut channel_present = false;
        let mut pskc_present = false;
        let mut security_policy_present = false;
        let mut channel_mask_present = false;

        if let Some(active_timestamp) = dataset.active_timestamp {
            raw_dataset.mActiveTimestamp = otTimestamp {
                mSeconds: active_timestamp.seconds,
                mTicks: active_timestamp.ticks,
                mAuthoritative: active_timestamp.authoritative,
            };
            active_timestamp_present = true;
        }

        if let Some(pending_timestamp) = dataset.pending_timestamp {
            raw_dataset.mActiveTimestamp = otTimestamp {
                mSeconds: pending_timestamp.seconds,
                mTicks: pending_timestamp.ticks,
                mAuthoritative: pending_timestamp.authoritative,
            };
            pending_timestamp_present = true;
        }

        if let Some(network_key) = dataset.network_key {
            raw_dataset.mNetworkKey = otNetworkKey { m8: network_key };
            network_key_present = true;
        }

        if let Some(network_name) = dataset.network_name {
            let mut raw = [0i8; 17];
            raw[..network_name.len()]
                .copy_from_slice(unsafe { core::mem::transmute(network_name.as_bytes()) });
            raw_dataset.mNetworkName = otNetworkName { m8: raw };
            network_name_present = true;
        }

        if let Some(extended_pan_id) = dataset.extended_pan_id {
            raw_dataset.mExtendedPanId = otExtendedPanId {
                m8: extended_pan_id,
            };
            extended_pan_present = true;
        }

        if let Some(mesh_local_prefix) = dataset.mesh_local_prefix {
            raw_dataset.mMeshLocalPrefix = otMeshLocalPrefix {
                m8: mesh_local_prefix,
            };
            mesh_local_prefix_present = true;
        }

        if let Some(delay) = dataset.delay {
            raw_dataset.mDelay = delay;
            delay_present = true;
        }

        if let Some(pan_id) = dataset.pan_id {
            raw_dataset.mPanId = pan_id;
            pan_id_present = true;
            let settings: NetworkSettings = get_settings();
            set_settings(NetworkSettings { pan_id, ..settings });
        }

        if let Some(channel) = dataset.channel {
            raw_dataset.mChannel = channel;
            channel_present = true;
            let settings: NetworkSettings = get_settings();
            set_settings(NetworkSettings {
                channel: channel as u8,
                ..settings
            });
        }

        if let Some(pskc) = dataset.pskc {
            raw_dataset.mPskc = otPskc { m8: pskc };
            pskc_present = true;
        }

        if let Some(security_policy) = dataset.security_policy {
            raw_dataset.mSecurityPolicy = otSecurityPolicy {
                mRotationTime: security_policy.rotation_time,
                _bitfield_align_1: [0u8; 0],
                _bitfield_1: otSecurityPolicy::new_bitfield_1(
                    security_policy.obtain_network_key_enabled,
                    security_policy.native_commissioning_enabled,
                    security_policy.routers_enabled,
                    security_policy.external_commissioning_enabled,
                    security_policy.commercial_commissioning_enabled,
                    security_policy.autonomous_enrollment_enabled,
                    security_policy.network_key_provisioning_enabled,
                    security_policy.toble_link_enabled,
                    security_policy.non_ccm_routers_enabled,
                    security_policy.version_threshold_for_routing,
                ),
            };
            security_policy_present = true;
        }

        if let Some(channel_mask) = dataset.channel_mask {
            raw_dataset.mChannelMask = channel_mask;
            channel_mask_present = true;
        }

        raw_dataset.mComponents = otOperationalDatasetComponents {
            mIsActiveTimestampPresent: active_timestamp_present,
            mIsPendingTimestampPresent: pending_timestamp_present,
            mIsNetworkKeyPresent: network_key_present,
            mIsNetworkNamePresent: network_name_present,
            mIsExtendedPanIdPresent: extended_pan_present,
            mIsMeshLocalPrefixPresent: mesh_local_prefix_present,
            mIsDelayPresent: delay_present,
            mIsPanIdPresent: pan_id_present,
            mIsChannelPresent: channel_present,
            mIsPskcPresent: pskc_present,
            mIsSecurityPolicyPresent: security_policy_present,
            mIsChannelMaskPresent: channel_mask_present,
        };

        checked!(unsafe { otDatasetSetActive(self.instance, &raw_dataset) })
    }

    /// Set the change callback
    pub fn set_change_callback(
        &mut self,
        callback: Option<&'a mut (dyn FnMut(ChangedFlags) + Send)>,
    ) {
        critical_section::with(|cs| {
            let mut change_callback = CHANGE_CALLBACK.borrow_ref_mut(cs);
            *change_callback = unsafe { core::mem::transmute(callback) };
        });
    }

    /// Brings the IPv6 interface up or down.
    pub fn ipv6_set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        checked!(unsafe { otIp6SetEnabled(self.instance, enabled) })
    }

    /// This function starts Thread protocol operation.
    ///
    /// The interface must be up when calling this function.
    pub fn thread_set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        checked!(unsafe { otThreadSetEnabled(self.instance, enabled) })
    }

    /// Gets the list of IPv6 addresses assigned to the Thread interface.
    pub fn ipv6_get_unicast_addresses<const N: usize>(
        &self,
    ) -> heapless::Vec<NetworkInterfaceUnicastAddress, N> {
        let mut result = heapless::Vec::new();
        let mut addr = unsafe { otIp6GetUnicastAddresses(self.instance) };

        loop {
            let a = unsafe { &*addr };

            let octets = unsafe { a.mAddress.mFields.m16 };

            if result
                .push(NetworkInterfaceUnicastAddress {
                    address: no_std_net::Ipv6Addr::new(
                        octets[0].to_be(),
                        octets[1].to_be(),
                        octets[2].to_be(),
                        octets[3].to_be(),
                        octets[4].to_be(),
                        octets[5].to_be(),
                        octets[6].to_be(),
                        octets[7].to_be(),
                    ),
                    prefix: a.mPrefixLength,
                    origin: a.mAddressOrigin,
                })
                .is_err()
            {
                break;
            }

            if a.mNext.is_null() {
                break;
            }

            addr = a.mNext;
        }

        result
    }

    /// Creates a new UDP socket
    pub fn get_udp_socket<'s, const BUFFER_SIZE: usize>(
        &'s self,
    ) -> Result<UdpSocket<'s, 'a, BUFFER_SIZE>, Error>
    where
        'a: 's,
    {
        let ot_socket = otUdpSocket {
            mSockName: otSockAddr {
                mAddress: otIp6Address {
                    mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
                },
                mPort: 0,
            },
            mPeerName: otSockAddr {
                mAddress: otIp6Address {
                    mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
                },
                mPort: 0,
            },
            mHandler: Some(udp_receive_handler),
            mContext: core::ptr::null_mut(),
            mHandle: core::ptr::null_mut(),
            mNext: core::ptr::null_mut(),
        };

        Ok(UdpSocket {
            ot_socket,
            ot: self,
            receive_len: 0,
            receive_from: [0u8; 16],
            receive_port: 0,
            max: BUFFER_SIZE,
            _pinned: PhantomPinned::default(),
            receive_buffer: [0u8; BUFFER_SIZE],
        })
    }

    /// Run tasks
    ///
    /// Make sure to periodically call this function.
    pub fn run_tasklets(&self) {
        unsafe {
            if otTaskletsArePending(self.instance) {
                otTaskletsProcess(self.instance);
            }
        }
    }

    /// Run due timers, get and forward received messages
    ///
    /// Make sure to periodically call this function.
    pub fn process(&self) {
        crate::timer::run_if_due();

        while let Some(raw) = with_radio(|radio| radio.get_raw_received()).unwrap() {
            let rssi: i8 = {
                let idx = match (raw.data[0] as usize).cmp(&raw.data.len()) {
                    core::cmp::Ordering::Less => {
                        // guard against attempting to access the (0 - 1)th index
                        if raw.data[0] == 0 {
                            log::warn!("raw.data[0] is 0, RSSI may be invalid",);
                            0
                        } else {
                            raw.data[0] as usize - 1
                        }
                    }
                    core::cmp::Ordering::Greater | core::cmp::Ordering::Equal => raw.data.len() - 1,
                };
                raw.data[idx] as i8
            };

            unsafe {
                // len indexes into both the RCV_FRAME_PSDU and raw.data array
                // so must be sized appropriately
                let len = if raw.data[0] as usize > RCV_FRAME_PSDU.len()
                    && raw.data[1..].len() >= RCV_FRAME_PSDU.len()
                {
                    log::warn!(
                        "raw.data[0] {:?} larger than rcv frame \
                        psdu len and raw.data.len()! RCV {:02x?}",
                        raw.data[0],
                        &raw.data[1..][..RCV_FRAME_PSDU.len()]
                    );
                    RCV_FRAME_PSDU.len()
                } else if raw.data[0] as usize > RCV_FRAME_PSDU.len()
                    && raw.data[1..].len() < RCV_FRAME_PSDU.len()
                {
                    log::warn!(
                        "raw.data[0] {:?} larger than raw.data.len()! \
                        RCV {:02x?}",
                        raw.data[0],
                        &raw.data[1..][..raw.data.len() - 1]
                    );
                    raw.data[1..].len()
                } else {
                    raw.data[0] as usize
                };

                log::debug!("RCV {:02x?}", &raw.data[1..][..len as usize]);

                RCV_FRAME_PSDU[..len as usize].copy_from_slice(&raw.data[1..][..len as usize]);
                RCV_FRAME.mLength = len as u16;
                RCV_FRAME.mRadioType = 1; // ????
                RCV_FRAME.mChannel = raw.channel;
                RCV_FRAME.mInfo.mRxInfo.mRssi = rssi;
                RCV_FRAME.mInfo.mRxInfo.mLqi = rssi_to_lqi(rssi);
                RCV_FRAME.mInfo.mRxInfo.mTimestamp = current_millis() * 1000;
                otPlatRadioReceiveDone(
                    self.instance,
                    addr_of_mut!(RCV_FRAME),
                    otError_OT_ERROR_NONE,
                );
            }
        }
    }
}

impl<'a> Drop for OpenThread<'a> {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            RADIO.borrow_ref_mut(cs).take();
            NETWORK_SETTINGS.borrow_ref_mut(cs).take();
            CHANGE_CALLBACK.borrow_ref_mut(cs).take();
        });
    }
}

unsafe extern "C" fn change_callback(
    flags: otChangedFlags,
    _context: *mut esp_openthread_sys::c_types::c_void,
) {
    log::debug!("change_callback otChangedFlags={:32b}", flags);
    critical_section::with(|cs| {
        let mut change_callback = CHANGE_CALLBACK.borrow_ref_mut(cs);
        let callback = change_callback.as_mut();

        if let Some(callback) = callback {
            if ChangedFlags::from_bits(flags).is_none() {
                log::warn!(
                    "change_callback otChangedFlags= {:?} would be None as flags",
                    flags
                );
            } else {
                callback(ChangedFlags::from_bits(flags).unwrap());
            }
        }
    });
}

fn with_radio<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&mut Ieee802154) -> T,
{
    critical_section::with(|cs| {
        let mut radio = RADIO.borrow_ref_mut(cs);
        let radio = radio.borrow_mut();

        if let Some(radio) = radio.as_mut() {
            Some(f(radio))
        } else {
            None
        }
    })
}

fn get_settings() -> NetworkSettings {
    critical_section::with(|cs| {
        let mut settings = NETWORK_SETTINGS.borrow_ref_mut(cs);
        let settings = settings.borrow_mut();

        if let Some(settings) = settings.as_mut() {
            settings.clone()
        } else {
            log::error!("Generating default settings");
            NetworkSettings::default()
        }
    })
}

fn set_settings(settings: NetworkSettings) {
    critical_section::with(|cs| {
        log::info!(
            "Setting settings to {:?}\nwere {:?}",
            settings,
            NETWORK_SETTINGS.borrow_ref(cs)
        );
        NETWORK_SETTINGS
            .borrow_ref_mut(cs)
            .borrow_mut()
            .replace(settings);
    });
}

/// A UdpSocket
///
/// To call functions on it you have to pin it.
/// ```no_run
/// let mut socket = openthread.get_udp_socket::<512>().unwrap();
/// let mut socket = pin!(socket);
/// socket.bind(1212).unwrap();
/// ```
pub struct UdpSocket<'s, 'n: 's, const BUFFER_SIZE: usize> {
    ot_socket: otUdpSocket,
    ot: &'s OpenThread<'n>,
    receive_len: usize,
    receive_from: [u8; 16],
    receive_port: u16,
    max: usize,
    _pinned: PhantomPinned,
    // must be last because the callback doesn't know about the actual const generic parameter
    receive_buffer: [u8; BUFFER_SIZE],
}

impl<'s, 'n: 's, const BUFFER_SIZE: usize> UdpSocket<'s, 'n, BUFFER_SIZE> {
    /// Open and bind a UDP/IPv6 socket
    pub fn bind(self: &mut Pin<&mut Self>, port: u16) -> Result<(), Error> {
        let mut sock_addr = otSockAddr {
            mAddress: otIp6Address {
                mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
            },
            mPort: 0,
        };
        sock_addr.mPort = port;

        unsafe {
            checked!(otUdpOpen(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
                Some(udp_receive_handler),
                self.as_mut().get_unchecked_mut() as *mut _ as *mut crate::sys::c_types::c_void,
            ))?;
        }

        unsafe {
            checked!(otUdpBind(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
                &mut sock_addr,
                otNetifIdentifier_OT_NETIF_THREAD,
            ))?;
        }

        Ok(())
    }

    /// Open a UDP/IPv6 socket
    pub fn open(self: &mut Pin<&mut Self>, port: u16) -> Result<(), Error> {
        let mut sock_addr = otSockAddr {
            mAddress: otIp6Address {
                mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
            },
            mPort: 0,
        };
        sock_addr.mPort = port;

        unsafe {
            checked!(otUdpOpen(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
                Some(udp_receive_handler),
                self.as_mut().get_unchecked_mut() as *mut _ as *mut crate::sys::c_types::c_void,
            ))?;
        }
        Ok(())
    }

    /// Get latest data received on this socket
    pub fn receive(
        self: &mut Pin<&mut Self>,
        data: &mut [u8],
    ) -> Result<(usize, Ipv6Addr, u16), Error> {
        critical_section::with(|_| {
            let len = self.receive_len as usize;
            if len == 0 {
                Ok((0, Ipv6Addr::UNSPECIFIED, 0))
            } else {
                unsafe { self.as_mut().get_unchecked_mut() }.receive_len = 0;
                data[..len].copy_from_slice(&self.receive_buffer[..len]);
                let ip = Ipv6Addr::from(self.receive_from);
                Ok((len, ip, self.receive_port))
            }
        })
    }

    /// Send data to the given peer
    pub fn send(
        self: &mut Pin<&mut Self>,
        dst: Ipv6Addr,
        port: u16,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut message_info = otMessageInfo {
            mSockAddr: otIp6Address {
                mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
            },
            mPeerAddr: otIp6Address {
                mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
            },
            mSockPort: 0,
            mPeerPort: 0,
            mHopLimit: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
        };
        message_info.mPeerAddr.mFields.m8 = dst.octets();
        message_info.mPeerPort = port;

        let message = unsafe { otUdpNewMessage(self.ot.instance, core::ptr::null()) };
        if message.is_null() {
            return Err(Error::InternalError(0));
        }

        unsafe {
            checked!(otMessageAppend(
                message,
                data.as_ptr() as *const c_void,
                data.len() as u16
            ))?;
        }

        unsafe {
            let err = otUdpSend(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
                message,
                &mut message_info,
            );

            if err != otError_OT_ERROR_NONE && !message.is_null() {
                otMessageFree(message);
                return Err(Error::InternalError(err));
            }
        }

        Ok(())
    }

    /// Close a UDP/IPv6 socket
    pub fn close(self: &mut Pin<&mut Self>) -> Result<(), Error> {
        unsafe {
            checked!(otUdpClose(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
            ))?;
        }

        Ok(())
    }

    fn close_internal(&mut self) -> Result<(), Error> {
        unsafe {
            checked!(otUdpClose(
                self.ot.instance,
                &self.ot_socket as *const _ as *mut otUdpSocket,
            ))?;
        }

        Ok(())
    }
}

impl<'s, 'n: 's, const BUFFER_SIZE: usize> Drop for UdpSocket<'s, 'n, BUFFER_SIZE> {
    fn drop(&mut self) {
        self.close_internal().ok();
    }
}

unsafe extern "C" fn udp_receive_handler(
    context: *mut crate::sys::c_types::c_void,
    message: *mut otMessage,
    message_info: *const otMessageInfo,
) {
    let socket = context as *mut UdpSocket<1024>;
    let len = u16::min((*socket).max as u16, otMessageGetLength(message));

    critical_section::with(|_| {
        otMessageRead(
            message,
            0,
            &mut (*socket).receive_buffer as *mut _ as *mut crate::sys::c_types::c_void,
            len,
        );
        (*socket).receive_port = (*message_info).mPeerPort;
        (*socket).receive_from = (*message_info).mPeerAddr.mFields.m8;
        (*socket).receive_len = len as usize;
    });
}
