/// Just holds settings in RAM

static mut SETTINGS: [(usize, [u8; 255]); 255] = [(0usize, [0u8; 255]); 255];

pub fn set_data(index: usize, data: &[u8]) {
    log::info!("{:02x?}", data);
    unsafe {
        SETTINGS[index].0 = data.len();
        SETTINGS[index].1[..data.len()].copy_from_slice(data);
    }
}

pub fn get_data(index: usize) -> &'static [u8] {
    unsafe {
        log::info!("{:02x?}", &SETTINGS[index].1[..SETTINGS[index].0]);
        &SETTINGS[index].1[..SETTINGS[index].0]
    }
}

// for now using OT_SETTINGS_RAM ... this implementation is very wrong apparently

// #[no_mangle]
// pub extern "C" fn otPlatSettingsInit(
//     instance: *const otInstance,
//     sens_keys: *const u16,
//     sens_keys_len: u16,
// ) {
//     log::info!("otPlatSettingsInit {:p} {}", instance, sens_keys_len);
//     for i in 0..sens_keys_len {
//         log::info!("{}", unsafe { sens_keys.add(i as usize).read_volatile() });
//     }
// }

// #[no_mangle]
// pub extern "C" fn otPlatSettingsDeinit() {
//     todo!()
// }

// #[no_mangle]
// pub extern "C" fn otPlatSettingsWipe() {
//     todo!()
// }

// #[no_mangle]
// pub extern "C" fn otPlatSettingsSet(
//     instance: *const otInstance,
//     key: u16,
//     value: *const u8,
//     len: u16,
// ) -> otError {
//     log::info!("otPlatSettingsSet {:p} {} {}", instance, key, len);

//     let d = unsafe { core::slice::from_raw_parts(value, len as usize) };
//     crate::settings::set_data(key as usize, d);
//     otError_OT_ERROR_NONE
// }

// #[no_mangle]
// pub extern "C" fn otPlatSettingsGet(
//     instance: *const u8,
//     key: u16,
//     index: i32,
//     val: *mut u8,
//     len: *mut u16,
// ) -> otError {
//     unsafe {
//         log::info!(
//             "otPlatSettingsGet {:p} {} {} {}",
//             instance,
//             key,
//             index,
//             *len
//         );
//         *len = 0;
//     }

//     let d = crate::settings::get_data(key as usize);
//     for i in 0..d.len() {
//         unsafe {
//             val.add(i).write_volatile(d[i]);
//         }
//     }

//     if d.len() == 0 {
//         otError_OT_ERROR_NOT_FOUND
//     } else {
//         otError_OT_ERROR_NONE
//     }
// }

// #[no_mangle]
// pub extern "C" fn otPlatSettingsDelete(
//     _instance: *const otInstance,
//     key: u16,
//     index: i32,
// ) -> otError {
//     log::info!("otPlatSettingsDelete {key} {index}");
//    // crate::settings::set_data(key as usize, &[]);

//     otError_OT_ERROR_NONE
// }
