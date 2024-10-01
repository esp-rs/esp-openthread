use core::ptr::addr_of_mut;

use esp_ieee802154::Config;
use esp_openthread_sys::bindings::{
    __BindgenBitfieldUnit, otError, otError_OT_ERROR_NONE, otInstance, otPlatRadioTxDone,
    otPlatRadioTxStarted, otRadioFrame, otRadioFrame__bindgen_ty_1,
    otRadioFrame__bindgen_ty_1__bindgen_ty_1, OT_RADIO_FRAME_MAX_SIZE, OT_RADIO_FRAME_MIN_SIZE,
};

use crate::{
    get_settings, platform::CURRENT_INSTANCE, set_settings, with_radio, NetworkSettings,
    TASKLETS_SHOULD_RUN,
};

pub static mut PSDU: [u8; OT_RADIO_FRAME_MAX_SIZE as usize] =
    [0u8; OT_RADIO_FRAME_MAX_SIZE as usize];
pub static mut TRANSMIT_BUFFER: otRadioFrame = otRadioFrame {
    mPsdu: addr_of_mut!(PSDU) as *mut u8,
    mLength: 0,
    mChannel: 0,
    mRadioType: 0,
    mInfo: otRadioFrame__bindgen_ty_1 {
        mTxInfo: otRadioFrame__bindgen_ty_1__bindgen_ty_1 {
            mAesKey: core::ptr::null(),
            mIeInfo: core::ptr::null_mut(),
            mTxDelay: 0,
            mTxDelayBaseTime: 0,
            mMaxCsmaBackoffs: 0,
            mMaxFrameRetries: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
            mRxChannelAfterTxDone: 0,
            mTxPower: 0,
            mTimestamp: 0,
        },
    },
};

pub static mut SENT_FRAME_PSDU: [u8; OT_RADIO_FRAME_MAX_SIZE as usize] =
    [0u8; OT_RADIO_FRAME_MAX_SIZE as usize];
static mut SENT_FRAME: otRadioFrame = otRadioFrame {
    mPsdu: addr_of_mut!(SENT_FRAME_PSDU) as *mut u8,
    mLength: 0,
    mChannel: 0,
    mRadioType: 0,
    mInfo: otRadioFrame__bindgen_ty_1 {
        mTxInfo: otRadioFrame__bindgen_ty_1__bindgen_ty_1 {
            mAesKey: core::ptr::null(),
            mIeInfo: core::ptr::null_mut(),
            mTxDelay: 0,
            mTxDelayBaseTime: 0,
            mMaxCsmaBackoffs: 0,
            mMaxFrameRetries: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
            mRxChannelAfterTxDone: 0,
            mTxPower: 0,
            mTimestamp: 0,
        },
    },
};

pub static mut ACK_FRAME_PSDU: [u8; OT_RADIO_FRAME_MIN_SIZE as usize] = [0x2, 0x0, 0x0];
static mut ACK_FRAME: otRadioFrame = otRadioFrame {
    mPsdu: addr_of_mut!(ACK_FRAME_PSDU) as *mut u8,
    mLength: OT_RADIO_FRAME_MIN_SIZE as _,
    mChannel: 0,
    mRadioType: 0,
    mInfo: otRadioFrame__bindgen_ty_1 {
        mTxInfo: otRadioFrame__bindgen_ty_1__bindgen_ty_1 {
            mAesKey: core::ptr::null(),
            mIeInfo: core::ptr::null_mut(),
            mTxDelay: 0,
            mTxDelayBaseTime: 0,
            mMaxCsmaBackoffs: 0,
            mMaxFrameRetries: 0,
            _bitfield_align_1: [0u8; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
            mRxChannelAfterTxDone: 0,
            mTxPower: 0,
            mTimestamp: 0,
        },
    },
};

/// Caller is required to ensure mac arg is sufficient length (6 bytes)
#[no_mangle]
pub extern "C" fn otPlatRadioGetIeeeEui64(_instance: *const otInstance, mac: *mut u8) {
    let efuse_mac = esp_hal::efuse::Efuse::get_mac_address();
    let dest_slice = unsafe { core::slice::from_raw_parts_mut(mac, 6) };
    dest_slice[..6].copy_from_slice(&efuse_mac);
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetCaps(instance: *const otInstance) -> u8 {
    log::debug!("otPlatRadioGetCaps {:p}", instance);
    0 // Radio supports no capability. See OT_RADIO_CAPS_*
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetTransmitBuffer(instance: *const otInstance) -> *mut otRadioFrame {
    log::debug!("otPlatRadioGetTransmitBuffer {:p}", instance);
    addr_of_mut!(TRANSMIT_BUFFER)
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnable(instance: *const otInstance) -> otError {
    log::debug!("otPlatRadioEnable {:p}", instance);
    otError_OT_ERROR_NONE
}

#[no_mangle]
pub extern "C" fn otPlatRadioSleep(instance: *const otInstance) -> otError {
    log::debug!("otPlatRadioSleep {:p}", instance);
    otError_OT_ERROR_NONE
}

#[no_mangle]
pub extern "C" fn otPlatRadioDisable(_instance: *const otInstance) -> otError {
    todo!()
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPromiscuous(_instance: *const otInstance, enable: bool) {
    set_settings(NetworkSettings {
        promiscuous: enable,
        ..get_settings()
    });

    let settings = get_settings();
    with_radio(|radio| {
        radio.set_config(Config {
            channel: settings.channel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });
    });
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetRssi(_instance: *const otInstance) -> i8 {
    let rssi = unsafe { crate::RCV_FRAME.mInfo.mRxInfo.mRssi };
    log::debug!("otPlatRadioGetRssi {rssi:}");

    // If no rcv frame has set rssi yet, or if rssi is not valid,
    // then use a fake value instead of 0
    if rssi == 0 {
        33
    } else {
        rssi
    }
}

// from https://github.com/espressif/esp-idf/blob/release/v5.3/components/openthread/src/port/esp_openthread_radio.c#L35
#[no_mangle]
pub extern "C" fn otPlatRadioGetReceiveSensitivity(_instance: *const otInstance) -> i8 {
    log::debug!("otPlatRadioGetReceiveSensitivity");
    -120
}

#[no_mangle]
pub extern "C" fn otPlatRadioIsEnabled(_instance: *mut otInstance) -> bool {
    // todo
    true
}

#[no_mangle]
pub extern "C" fn otPlatRadioEnergyScan(
    _instance: *const otInstance,
    _channel: u8,
    _duration: u16,
) -> otError {
    todo!()
}

#[no_mangle]
pub extern "C" fn otPlatRadioGetPromiscuous(_instance: *const otInstance) -> bool {
    log::debug!("otPlatRadioGetPromiscuous");
    get_settings().promiscuous
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetExtendedAddress(instance: *const otInstance, address: *const u8) {
    log::debug!("otPlatRadioSetExtendedAddress {:p}", instance);
    let ext_addr = u64::from_be_bytes(
        unsafe { core::slice::from_raw_parts(address, 8) }
            .try_into()
            .unwrap(),
    );
    set_settings(NetworkSettings {
        ext_address: ext_addr,
        ..get_settings()
    });

    let settings = get_settings();
    with_radio(|radio| {
        radio.set_config(Config {
            channel: settings.channel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });
    });
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetShortAddress(instance: *const otInstance, address: u16) {
    log::debug!("otPlatRadioSetShortAddress {:p} {}", instance, address);
    set_settings(NetworkSettings {
        short_address: address,
        ..get_settings()
    });

    let settings = get_settings();
    with_radio(|radio| {
        radio.set_config(Config {
            channel: settings.channel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });
    });
}

#[no_mangle]
pub extern "C" fn otTaskletsSignalPending(_instance: *mut otInstance) {
    log::debug!("tasklets pending!!");
    critical_section::with(|cs| *TASKLETS_SHOULD_RUN.borrow_ref_mut(cs) = true);
}

#[no_mangle]
pub extern "C" fn otPlatRadioSetPanId(_instance: *const otInstance, pan_id: u16) {
    log::debug!("otPlatRadioSetPanId {pan_id}");
    set_settings(NetworkSettings {
        pan_id,
        ..get_settings()
    });

    let settings = get_settings();
    with_radio(|radio| {
        radio.set_config(Config {
            channel: settings.channel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });
    });
}

#[no_mangle]
pub extern "C" fn otPlatRadioTransmit(
    instance: *const otInstance,
    frame: *const otRadioFrame,
) -> otError {
    let frame = unsafe { &*frame };
    let data = unsafe { core::slice::from_raw_parts(frame.mPsdu, frame.mLength as usize) };

    log::debug!(
        "otPlatRadioTransmit channel={} {:02x?}",
        frame.mChannel,
        &data
    );

    let settings = get_settings();
    log::debug!("Settings {:x?}", settings);

    with_radio(|radio| {
        radio.set_config(Config {
            channel: frame.mChannel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });

        radio.transmit_raw(data).ok();
    });

    unsafe {
        SENT_FRAME_PSDU[..frame.mLength as usize].copy_from_slice(core::slice::from_raw_parts(
            frame.mPsdu,
            frame.mLength as usize,
        ));
        SENT_FRAME = *frame;
        SENT_FRAME.mPsdu = addr_of_mut!(SENT_FRAME_PSDU) as *mut u8;

        otPlatRadioTxStarted(instance as *mut otInstance, core::mem::transmute(frame));
    }

    log::debug!("TX done");

    otError_OT_ERROR_NONE
}

#[no_mangle]
pub extern "C" fn otPlatRadioReceive(_instance: *mut otInstance, channel: u8) -> otError {
    log::debug!("otPlatRadioReceive channel = {channel}");
    let settings: NetworkSettings = get_settings();
    log::debug!("Settings {:x?}", settings);

    set_settings(NetworkSettings {
        channel,
        ..settings
    });

    with_radio(|radio| {
        radio.set_config(Config {
            channel,
            promiscuous: settings.promiscuous,
            pan_id: Some(settings.pan_id),
            short_addr: Some(settings.short_address),
            ext_addr: Some(settings.ext_address),
            rx_when_idle: settings.rx_when_idle,
            auto_ack_rx: true,
            auto_ack_tx: true,
            ..Config::default()
        });
        radio.start_receive();
    });

    otError_OT_ERROR_NONE
}

pub(crate) fn trigger_tx_done() {
    log::warn!("trigger_tx_done");
    critical_section::with(|_cs| unsafe {
        otPlatRadioTxDone(
            CURRENT_INSTANCE as *mut otInstance,
            addr_of_mut!(SENT_FRAME),
            addr_of_mut!(ACK_FRAME),
            otError_OT_ERROR_NONE,
        );
    });
}
