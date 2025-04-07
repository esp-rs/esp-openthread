use core::ffi::{c_void, CStr};
use core::future::poll_fn;

use bitflags::bitflags;

use crate::sys::{
    otActiveScanResult, otError_OT_ERROR_BUSY, otInstance, otLinkActiveScan,
    otLinkIsActiveScanInProgress, OT_CHANNEL_10_MASK, OT_CHANNEL_11_MASK, OT_CHANNEL_12_MASK,
    OT_CHANNEL_13_MASK, OT_CHANNEL_14_MASK, OT_CHANNEL_15_MASK, OT_CHANNEL_16_MASK,
    OT_CHANNEL_17_MASK, OT_CHANNEL_18_MASK, OT_CHANNEL_19_MASK, OT_CHANNEL_1_MASK,
    OT_CHANNEL_20_MASK, OT_CHANNEL_21_MASK, OT_CHANNEL_22_MASK, OT_CHANNEL_23_MASK,
    OT_CHANNEL_24_MASK, OT_CHANNEL_25_MASK, OT_CHANNEL_26_MASK, OT_CHANNEL_2_MASK,
    OT_CHANNEL_3_MASK, OT_CHANNEL_4_MASK, OT_CHANNEL_5_MASK, OT_CHANNEL_6_MASK, OT_CHANNEL_7_MASK,
    OT_CHANNEL_8_MASK, OT_CHANNEL_9_MASK,
};
use crate::{ot, OpenThread, OtContext, OtError};

bitflags! {
    /// Radio channels set.
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Channels: u32 {
        const CH_1 = OT_CHANNEL_1_MASK;
        const CH_2 = OT_CHANNEL_2_MASK;
        const CH_3 = OT_CHANNEL_3_MASK;
        const CH_4 = OT_CHANNEL_4_MASK;
        const CH_5 = OT_CHANNEL_5_MASK;
        const CH_6 = OT_CHANNEL_6_MASK;
        const CH_7 = OT_CHANNEL_7_MASK;
        const CH_8 = OT_CHANNEL_8_MASK;
        const CH_9 = OT_CHANNEL_9_MASK;
        const CH_10 = OT_CHANNEL_10_MASK;
        const CH_11 = OT_CHANNEL_11_MASK;
        const CH_12 = OT_CHANNEL_12_MASK;
        const CH_13 = OT_CHANNEL_13_MASK;
        const CH_14 = OT_CHANNEL_14_MASK;
        const CH_15 = OT_CHANNEL_15_MASK;
        const CH_16 = OT_CHANNEL_16_MASK;
        const CH_17 = OT_CHANNEL_17_MASK;
        const CH_18 = OT_CHANNEL_18_MASK;
        const CH_19 = OT_CHANNEL_19_MASK;
        const CH_20 = OT_CHANNEL_20_MASK;
        const CH_21 = OT_CHANNEL_21_MASK;
        const CH_22 = OT_CHANNEL_22_MASK;
        const CH_23 = OT_CHANNEL_23_MASK;
        const CH_24 = OT_CHANNEL_24_MASK;
        const CH_25 = OT_CHANNEL_25_MASK;
        const CH_26 = OT_CHANNEL_26_MASK;
    }
}

/// An active scan result
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScanResult<'a> {
    /// IEEE 802.15.4 Extended Address
    pub ext_address: u64,
    /// Thread Network Name
    pub network_name: &'a str,
    /// Thread Extended PAN ID
    pub extended_pan_id: u64,
    /// Steering Data
    pub steering_data: &'a [u8],
    /// IEEE 802.15.4 PAN ID
    pub pan_id: u16,
    /// Joiner UDP Port
    pub joiner_udp_port: u16,
    /// IEEE 802.15.4 Channel
    pub channel: u8,
    /// RSSI (dBm)
    pub rssi: i8,
    /// LQI
    pub lqi: u8,
    /// Version
    pub version: u8,
    /// Native Commissioner
    pub native_commissioner: bool,
    /// Discovery Response
    pub discover: bool,
}

impl<'a> From<&'a otActiveScanResult> for ScanResult<'a> {
    fn from(result: &'a otActiveScanResult) -> Self {
        let network_name = unsafe {
            core::slice::from_raw_parts(
                result.mNetworkName.m8.as_ptr() as *const _,
                result.mNetworkName.m8.len(),
            )
        };

        Self {
            ext_address: u64::from_be_bytes(result.mExtAddress.m8),
            network_name: CStr::from_bytes_until_nul(network_name)
                .unwrap()
                .to_str()
                .unwrap(),
            extended_pan_id: u64::from_be_bytes(result.mExtendedPanId.m8),
            steering_data: &result.mSteeringData.m8[..result.mSteeringData.mLength as _],
            pan_id: result.mPanId,
            joiner_udp_port: result.mJoinerUdpPort,
            channel: result.mChannel,
            rssi: result.mRssi,
            lqi: result.mLqi,
            version: result.mVersion() as _,
            native_commissioner: result.mIsNative(),
            discover: result.mDiscover(),
        }
    }
}

impl<'a> OpenThread<'a> {
    /// Perform an active scan for Thread networks.
    ///
    /// The scan will be performed on the specified channels for the specified duration.
    ///
    /// Arguments:
    /// - `channels`: The channel mask to scan.
    /// - `duration_millis`: The duration of the scan in milliseconds.
    /// - `f`: A closure that will be called for each scan result, and finally - with `None` - when the scan is complete.
    pub async fn scan<F>(
        &self,
        channels: Channels,
        duration_millis: u16,
        mut f: F,
    ) -> Result<(), OtError>
    where
        F: FnMut(Option<&ScanResult>),
    {
        {
            let mut ot = self.activate();
            let state = ot.state();

            let in_progress = unsafe { otLinkIsActiveScanInProgress(state.ot.instance) };

            if in_progress {
                return Err(OtError::new(otError_OT_ERROR_BUSY));
            }

            {
                let f: &mut dyn FnMut(Option<&ScanResult>) = &mut f;

                let scan_callback = &mut state.ot.scan_callback;
                *scan_callback = Some(unsafe {
                    core::mem::transmute::<
                        &mut dyn FnMut(Option<&ScanResult>),
                        &'a mut dyn FnMut(Option<&ScanResult>),
                    >(f)
                });

                let _guard = scopeguard::guard((), |_| {
                    *scan_callback = None;
                });
            }

            ot!(unsafe {
                otLinkActiveScan(
                    state.ot.instance,
                    channels.bits(),
                    duration_millis,
                    Some(Self::plat_c_scan_callback),
                    state.ot.instance as *mut _ as *mut _,
                )
            })?;
        }

        poll_fn(move |cx| self.activate().state().ot.scan_done.poll_wait(cx)).await;

        Ok(())
    }

    unsafe extern "C" fn plat_c_scan_callback(
        scan_result: *mut otActiveScanResult,
        context: *mut c_void,
    ) {
        let instance = context as *mut otInstance;

        let mut ot = OtContext::callback(instance);
        let state = ot.state();

        let scan_result = unsafe { scan_result.as_ref() };
        let last = scan_result.is_none();

        {
            if let Some(f) = state.ot.scan_callback.as_mut() {
                let scan_result = scan_result.map(|s| s.into());

                f(scan_result.as_ref());
            }
        }

        if last {
            state.ot.scan_callback = None;
            state.ot.scan_done.signal(());
        }
    }
}
