use core::ffi::{c_void, CStr};
use core::future::poll_fn;

use crate::sys::{
    otActiveScanResult, otError_OT_ERROR_BUSY, otInstance, otLinkActiveScan,
    otLinkIsActiveScanInProgress,
};
use crate::{ot, OpenThread, OtContext, OtError};

/// An active scan result
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScanResult<'a> {
    /// IEEE 802.15.4 Extended Address
    pub ext_address: &'a [u8; 8],
    /// Thread Network Name
    pub network_name: &'a str,
    /// Thread Extended PAN ID
    pub extended_pan_id: &'a [u8; 8],
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
        Self {
            ext_address: &result.mExtAddress.m8,
            network_name: CStr::from_bytes_until_nul(&result.mNetworkName.m8)
                .unwrap()
                .to_str()
                .unwrap(),
            extended_pan_id: &result.mExtendedPanId.m8,
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

impl OpenThread<'_> {
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
        channels: u32,
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

            let f: &mut dyn FnMut(Option<&ScanResult>) = &mut f;

            let scan_callback = &state.ot.scan_callback;
            #[allow(clippy::missing_transmute_annotations)]
            {
                *scan_callback.borrow_mut() = Some(unsafe { core::mem::transmute(f) });
            }

            let _guard = scopeguard::guard((), |_| {
                *scan_callback.borrow_mut() = None;
            });

            ot!(unsafe {
                otLinkActiveScan(
                    state.ot.instance,
                    channels,
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
            if let Some(f) = state.ot.scan_callback.borrow_mut().as_mut() {
                let scan_result = scan_result.map(|s| s.into());

                f(scan_result.as_ref());
            }
        }

        if last {
            *state.ot.scan_callback.borrow_mut() = None;
            state.ot.scan_done.signal(());
        }
    }
}
