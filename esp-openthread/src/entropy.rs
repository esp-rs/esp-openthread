use esp_openthread_sys::bindings::{otError, otError_OT_ERROR_NONE};

use esp_hal::rng::Rng;

pub(crate) static mut RANDOM_GENERATOR: Option<Rng> = None;

pub fn init_rng(rng: Rng) {
    unsafe {
        RANDOM_GENERATOR = Some(core::mem::transmute(rng));
    }
}

#[no_mangle]
pub extern "C" fn otPlatEntropyGet(output: *mut u8, len: u16) -> otError {
    log::trace!("otPlatEntropyGet");
    unsafe {
        let rng = crate::entropy::RANDOM_GENERATOR.as_mut().unwrap();

        for i in 0..len as usize {
            output.add(i).write_volatile(rng.random() as u8);
        }
    }

    otError_OT_ERROR_NONE
}
