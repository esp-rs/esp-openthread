//! The module contains the `Dataset` type and its related types.
//!
//! Basically, a way to configure the Thread network settings.

use crate::sys::{
    otExtendedPanId, otMeshLocalPrefix, otNetworkKey, otNetworkName, otOperationalDataset,
    otOperationalDatasetComponents, otPskc, otSecurityPolicy, otTimestamp,
};

/// Active or Pending Operational Dataset
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct OperationalDataset<'a> {
    /// Active Timestamp
    pub active_timestamp: Option<ThreadTimestamp>,
    /// Pending Timestamp
    pub pending_timestamp: Option<ThreadTimestamp>,
    /// Network Key
    pub network_key: Option<[u8; 16]>,
    /// Network name
    pub network_name: Option<&'a str>,
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

impl OperationalDataset<'_> {
    /// Store the dataset in the format the `OpenThread` C library expects.
    ///
    /// Arguments:
    /// - `raw_dataset`: A mutable reference to the `otOperationalDataset` struct where the dataset needs to be stored.
    pub(crate) fn store_raw(&self, raw_dataset: &mut otOperationalDataset) {
        let dataset_slice = unsafe {
            core::slice::from_raw_parts_mut(
                raw_dataset as *mut _ as *mut u8,
                core::mem::size_of::<otOperationalDataset>(),
            )
        };
        dataset_slice.fill(0);

        // TODO: What the...? Confirm and remove this later.
        // raw_dataset.mComponents.mIsActiveTimestampPresent = true;
        // raw_dataset.mComponents.mIsPendingTimestampPresent = true;
        // raw_dataset.mComponents.mIsNetworkKeyPresent = true;
        // raw_dataset.mComponents.mIsNetworkNamePresent = true;
        // raw_dataset.mComponents.mIsExtendedPanIdPresent = true;
        // raw_dataset.mComponents.mIsPanIdPresent = true;
        // raw_dataset.mComponents.mIsChannelPresent = true;

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

        let dataset = self;

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
            let mut raw = [0u8; 17];
            raw[..network_name.len()].copy_from_slice(network_name.as_bytes());
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
            // TODO: What the...? Confirm and remove this later.
            // let settings: NetworkSettings = get_settings();
            // set_settings(NetworkSettings { pan_id, ..settings });
        }

        if let Some(channel) = dataset.channel {
            raw_dataset.mChannel = channel;
            channel_present = true;
            // TODO: What the...? Confirm and remove this later.
            // let settings: NetworkSettings = get_settings();
            // set_settings(NetworkSettings {
            //     channel: channel as u8,
            //     ..settings
            // });
        }

        if let Some(pskc) = dataset.pskc {
            raw_dataset.mPskc = otPskc { m8: pskc };
            pskc_present = true;
        }

        if let Some(security_policy) = &dataset.security_policy {
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
            mIsWakeupChannelPresent: false, // we are not supporting Thread in Mobile in this lib right now
        };
    }
}

/// Security Policy
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
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

/// Thread Dataset timestamp
// TODO: Do we need both "seconds" and "ticks"? Revisit this later.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ThreadTimestamp {
    pub seconds: u64,
    pub ticks: u16,
    pub authoritative: bool,
}
