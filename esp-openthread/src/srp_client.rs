#![allow(unused)]
use core::ptr::{null, null_mut};

use esp_openthread_sys::{self as sys};
use sys::{
    bindings::{
        otDnsTxtEntry, otError, otError_OT_ERROR_NO_BUFS, otInstance, otIp6Address, otSockAddr,
        otSrpClientAddService, otSrpClientAutoStartCallback, otSrpClientBuffersAllocateService,
        otSrpClientBuffersFreeAllServices, otSrpClientBuffersFreeService,
        otSrpClientBuffersGetHostAddressesArray, otSrpClientBuffersGetHostNameString,
        otSrpClientBuffersGetServiceEntryInstanceNameString,
        otSrpClientBuffersGetServiceEntryServiceNameString,
        otSrpClientBuffersGetServiceEntryTxtBuffer, otSrpClientBuffersGetSubTypeLabelsArray,
        otSrpClientBuffersServiceEntry, otSrpClientClearHostAndServices,
        otSrpClientEnableAutoHostAddress, otSrpClientEnableAutoStartMode, otSrpClientGetHostInfo,
        otSrpClientGetKeyLeaseInterval, otSrpClientGetLeaseInterval, otSrpClientGetServerAddress,
        otSrpClientGetServices, otSrpClientGetTtl, otSrpClientHostInfo,
        otSrpClientIsAutoStartModeEnabled, otSrpClientIsRunning, otSrpClientItemState,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_ADDING,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REFRESHING,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REGISTERED,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVED,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVING,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_ADD,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REFRESH,
        otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE, otSrpClientRemoveHostAndServices,
        otSrpClientService, otSrpClientSetHostAddresses, otSrpClientSetHostName,
        otSrpClientSetKeyLeaseInterval, otSrpClientSetLeaseInterval, otSrpClientSetTtl,
        otSrpClientStart, otSrpClientStop,
    },
    c_types,
};

use crate::{checked, Error};

pub const MAX_SRP_ADDRS: usize = 6;
// This matches the default config value
pub const MAX_SERVICES: usize = 5;
pub const MAX_DNS_TXT_ENTRIES: usize = 10;

#[derive(Debug, Clone, Copy)]
pub enum SrpClientState {
    ToAdd,
    Adding,
    ToRefresh,
    Refreshing,
    ToRemove,
    Removing,
    Removed,
    Registered,
}

#[allow(non_upper_case_globals)]
impl TryFrom<otSrpClientItemState> for SrpClientState {
    type Error = ();
    fn try_from(value: otSrpClientItemState) -> Result<SrpClientState, Self::Error> {
        match value {
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_ADD => Ok(SrpClientState::ToAdd),
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_ADDING => Ok(SrpClientState::Adding),
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REFRESH => {
                Ok(SrpClientState::ToRefresh)
            }
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REFRESHING => {
                Ok(SrpClientState::Refreshing)
            }
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE => Ok(SrpClientState::ToRemove),
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVING => Ok(SrpClientState::Removing),
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVED => Ok(SrpClientState::Removed),
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REGISTERED => {
                Ok(SrpClientState::Registered)
            }
            _ => Err(()),
        }
    }
}

pub struct DnsTxtEntry {
    pub key: *const c_types::c_char,
    pub value: *const u8,
    pub value_length: u16,
}

impl From<otDnsTxtEntry> for DnsTxtEntry {
    fn from(value: otDnsTxtEntry) -> Self {
        Self {
            key: value.mKey,
            value: value.mValue,
            value_length: value.mValueLength,
        }
    }
}

impl From<DnsTxtEntry> for otDnsTxtEntry {
    fn from(value: DnsTxtEntry) -> Self {
        Self {
            mKey: value.key,
            mValue: value.value,
            mValueLength: value.value_length,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SrpClientService {
    pub name: *const c_types::c_char,
    pub instance_name: *const c_types::c_char,
    pub sub_type_labels: *const *const c_types::c_char,
    pub txt_entries: *const otDnsTxtEntry,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub num_txt_entries: u8,
    pub state: SrpClientState,
    pub data: u32,
    pub lease: u32,
    pub key_lease: u32,
}

impl From<otSrpClientService> for SrpClientService {
    fn from(value: otSrpClientService) -> Self {
        Self {
            name: value.mName,
            instance_name: value.mInstanceName,
            sub_type_labels: value.mSubTypeLabels,
            txt_entries: value.mTxtEntries,
            port: value.mPort,
            priority: value.mPriority,
            weight: value.mWeight,
            num_txt_entries: value.mNumTxtEntries,
            state: value
                .mState
                .try_into()
                .unwrap_or(SrpClientState::Registered),
            data: value.mData,
            lease: value.mLease,
            key_lease: value.mKeyLease,
        }
    }
}

pub(crate) fn check_srp_autostart_enabled(instance: *mut otInstance) -> bool {
    unsafe { otSrpClientIsAutoStartModeEnabled(instance) }
}

pub(crate) fn enable_srp_autostart(instance: *mut otInstance) {
    unsafe {
        otSrpClientEnableAutoStartMode(instance, None, null_mut());
    };
}

pub(crate) fn enable_srp_autostart_with_callback_and_context(
    instance: *mut otInstance,
    callback: otSrpClientAutoStartCallback,
    context: *mut c_types::c_void,
) {
    unsafe {
        otSrpClientEnableAutoStartMode(instance, callback, context);
    };
}

pub(crate) fn get_srp_client_host_info(instance: *mut otInstance) -> *const otSrpClientHostInfo {
    unsafe { otSrpClientGetHostInfo(instance) }
}

pub(crate) fn set_srp_client_host_name(
    instance: *mut otInstance,
    host_name: *mut c_types::c_char,
) -> Result<(), Error> {
    checked!(unsafe { otSrpClientSetHostName(instance, host_name) })
}

pub(crate) fn get_srp_client_host_name(
    instance: *mut otInstance,
    size: &mut u16,
) -> *mut c_types::c_char {
    unsafe { otSrpClientBuffersGetHostNameString(instance, size) }
}

pub(crate) fn get_srp_client_host_state(instance: *mut otInstance) -> Option<SrpClientState> {
    let host_info = get_srp_client_host_info(instance);
    let state = unsafe { (*host_info).mState };
    if let Ok(state) = state.try_into() {
        Some(state)
    } else {
        None
    }
}

// may need to set OPENTHREAD_CONFIG_SRP_CLIENT_BUFFERS_MAX_HOST_ADDRESSES
pub(crate) fn get_srp_client_host_addresses(
    instance: *mut otInstance,
) -> Option<heapless::Vec<no_std_net::Ipv6Addr, MAX_SRP_ADDRS>> {
    let host_info = get_srp_client_host_info(instance);
    if unsafe { (*host_info).mAutoAddress } {
        None
    } else {
        let mut array_len: u8 = 0;
        let array: *mut otIp6Address =
            unsafe { otSrpClientBuffersGetHostAddressesArray(instance, &mut array_len) };
        let mut result = heapless::Vec::new();
        let mut index = 0;
        loop {
            let a = unsafe { &*array.offset(index) };
            let octets = unsafe { a.mFields.m16 };
            if result
                .push(no_std_net::Ipv6Addr::new(
                    octets[0].to_be(),
                    octets[1].to_be(),
                    octets[2].to_be(),
                    octets[3].to_be(),
                    octets[4].to_be(),
                    octets[5].to_be(),
                    octets[6].to_be(),
                    octets[7].to_be(),
                ))
                .is_err()
            {
                break;
            }

            index += 1;
            if index == array_len as isize {
                break;
            }
        }
        Some(result)
    }
}

// may need to set OPENTHREAD_CONFIG_SRP_CLIENT_BUFFERS_MAX_HOST_ADDRESSES
pub(crate) fn set_srp_client_host_addresses(
    instance: *mut otInstance,
    addrs: *mut otIp6Address,
    mut num_addr: u8,
) -> Result<(), Error> {
    if num_addr > MAX_SRP_ADDRS as u8 {
        num_addr = MAX_SRP_ADDRS as u8;
    }
    checked!(unsafe { otSrpClientSetHostAddresses(instance, addrs, num_addr) })
}

pub(crate) fn set_srp_client_host_addresses_auto_config(
    instance: *mut otInstance,
) -> Result<(), Error> {
    checked!(unsafe { otSrpClientEnableAutoHostAddress(instance) })
}

pub(crate) fn srp_client_host_remove(
    instance: *mut otInstance,
    remove_key_lease: bool,
    send_unreg_to_server: bool,
) -> Result<(), Error> {
    checked!(unsafe {
        otSrpClientRemoveHostAndServices(instance, remove_key_lease, send_unreg_to_server)
    })
}

pub(crate) fn srp_client_host_clear(instance: *mut otInstance) {
    unsafe {
        otSrpClientClearHostAndServices(instance);
        otSrpClientBuffersFreeAllServices(instance);
    };
}

pub(crate) fn get_srp_client_lease_interval(instance: *mut otInstance) -> u32 {
    unsafe { otSrpClientGetLeaseInterval(instance) }
}

pub(crate) fn set_srp_client_lease_interval(instance: *mut otInstance, interval: u32) {
    unsafe { otSrpClientSetLeaseInterval(instance, interval) }
}

pub(crate) fn get_srp_client_key_lease_interval(instance: *mut otInstance) -> u32 {
    unsafe { otSrpClientGetKeyLeaseInterval(instance) }
}

pub(crate) fn set_srp_client_key_lease_interval(instance: *mut otInstance, interval: u32) {
    unsafe { otSrpClientSetKeyLeaseInterval(instance, interval) }
}

// OT documentation notes that if client isnt running this
// will return the unspecified addr (0.0.0.0.0.0.0.0)
pub(crate) fn get_srp_client_server_addr(instance: *mut otInstance) -> no_std_net::SocketAddrV6 {
    let addr: *const otSockAddr = unsafe { otSrpClientGetServerAddress(instance) };

    unsafe {
        no_std_net::SocketAddrV6::new(
            no_std_net::Ipv6Addr::new(
                (*addr).mAddress.mFields.m16[0],
                (*addr).mAddress.mFields.m16[1],
                (*addr).mAddress.mFields.m16[2],
                (*addr).mAddress.mFields.m16[3],
                (*addr).mAddress.mFields.m16[4],
                (*addr).mAddress.mFields.m16[5],
                (*addr).mAddress.mFields.m16[6],
                (*addr).mAddress.mFields.m16[7],
            ),
            (*addr).mPort,
            0,
            0,
        )
    }
}

pub(crate) fn get_srp_client_services(
    instance: *mut otInstance,
) -> heapless::Vec<SrpClientService, MAX_SERVICES> {
    let mut result = heapless::Vec::new();

    let mut services: *const otSrpClientService = unsafe { otSrpClientGetServices(instance) };

    loop {
        let s = unsafe { &*services };

        if result.push(SrpClientService::from(*s)).is_err() {
            break;
        }

        if s.mNext.is_null() {
            break;
        }

        services = s.mNext;
    }
    result
}

pub(crate) fn add_srp_client_service(
    instance: *mut otInstance,
    instance_name: *const c_types::c_char,
    mut iname_bytes: u16,
    service_name: *const c_types::c_char,
    mut sname_bytes: u16,
    sub_types: &[&str], // must be array of strs with comma
    txt_entry: *const c_types::c_char,
    mut txt_entry_size: u16,
    port: u16,
    priority: Option<u16>,
    weight: Option<u16>,
    lease: Option<u32>,
    key_lease: Option<u32>,
) -> Result<(), Error> {
    let entry: *mut otSrpClientBuffersServiceEntry =
        unsafe { otSrpClientBuffersAllocateService(instance) };
    if entry.is_null() {
        return Err(Error::InternalError(otError_OT_ERROR_NO_BUFS));
    }

    let mut size: u16 = 0;

    let instance_name_buf: *mut c_types::c_char =
        unsafe { otSrpClientBuffersGetServiceEntryInstanceNameString(entry, &mut size) };
    if iname_bytes > size {
        iname_bytes = size;
    }
    unsafe { core::ptr::copy(instance_name, instance_name_buf, iname_bytes as usize) };

    let service_name_buf: *mut c_types::c_char =
        unsafe { otSrpClientBuffersGetServiceEntryServiceNameString(entry, &mut size) };
    if sname_bytes > size {
        sname_bytes = size;
    }
    unsafe { core::ptr::copy(service_name, service_name_buf, sname_bytes as usize) };

    if !sub_types.is_empty() {
        // Note to caller: subtype labels should be static due to how they are referenced
        // in OT stack
        let sub_types_buf: *mut *const c_types::c_char =
            unsafe { otSrpClientBuffersGetSubTypeLabelsArray(entry, &mut size) };
        let mut end_index = 0;

        sub_types.iter().for_each(|ptr| {
            if ptr.chars().next() == Some(',') {
                unsafe {
                    let mut addr_idx = sub_types_buf.add(end_index);
                    addr_idx = ptr.as_ptr() as _;
                };
                end_index += 1;
            }
        });

        if end_index + 1 > size as usize {
            return Err(Error::InternalError(otError_OT_ERROR_NO_BUFS));
        }
    }

    if txt_entry.is_null() {
        unsafe {
            (*entry).mService.mNumTxtEntries = 0;
        }
    } else {
        let txt_buf: *mut i8 =
            unsafe { otSrpClientBuffersGetServiceEntryTxtBuffer(entry, &mut size) } as *mut i8;
        if txt_entry_size > size {
            txt_entry_size = size;
        }
        unsafe {
            (*entry).mTxtEntry.mValueLength = txt_entry_size;
            core::ptr::copy(txt_entry, txt_buf, txt_entry_size as usize);
        }
    }

    unsafe {
        (*entry).mService.mPort = port;
    }

    if let Some(weight) = weight {
        unsafe {
            (*entry).mService.mWeight = weight;
        }
    }

    if let Some(priority) = priority {
        unsafe {
            (*entry).mService.mPriority = priority;
        }
    }

    if let Some(lease) = lease {
        unsafe {
            (*entry).mService.mLease = lease;
        }
    }

    if let Some(key_lease) = key_lease {
        unsafe {
            (*entry).mService.mKeyLease = key_lease;
        }
    }

    if let Err(e) = checked!(unsafe { otSrpClientAddService(instance, &mut (*entry).mService) }) {
        log::error!("Error adding service: {e:?}");
        unsafe { otSrpClientBuffersFreeService(instance, entry) };
        Err(e)
    } else {
        Ok(())
    }
}

pub(crate) fn srp_client_start(instance: *mut otInstance, addr: otSockAddr) -> Result<(), Error> {
    checked!(unsafe { otSrpClientStart(instance, &addr) })
}

pub(crate) fn srp_client_stop(instance: *mut otInstance) {
    unsafe { otSrpClientStop(instance) }
}

pub(crate) fn is_srp_client_running(instance: *mut otInstance) -> bool {
    unsafe { otSrpClientIsRunning(instance) }
}

pub(crate) fn set_srp_client_ttl(instance: *mut otInstance, ttl: u32) {
    unsafe { otSrpClientSetTtl(instance, ttl) }
}

pub(crate) fn get_srp_client_ttl(instance: *mut otInstance) -> u32 {
    unsafe { otSrpClientGetTtl(instance) }
}
