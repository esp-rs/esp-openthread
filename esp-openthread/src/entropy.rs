use core::{borrow::BorrowMut, cell::RefCell};

use critical_section::Mutex;

use esp_openthread_sys::bindings::{otError, otError_OT_ERROR_NONE};

use esp_hal::rng::Rng;

pub(crate) static RANDOM_GENERATOR: Mutex<RefCell<Option<Rng>>> = Mutex::new(RefCell::new(None));

pub fn init_rng(rng: Rng) {
    unsafe {
        critical_section::with(|cs| {
            RANDOM_GENERATOR
                .borrow_ref_mut(cs)
                .borrow_mut()
                .replace(core::mem::transmute(rng));
        });
    }
}

#[no_mangle]
pub extern "C" fn otPlatEntropyGet(output: *mut u8, len: u16) -> otError {
    log::trace!("otPlatEntropyGet");
    unsafe {
        critical_section::with(|cs| {
            let mut rng = crate::entropy::RANDOM_GENERATOR.borrow_ref_mut(cs);
            let rng = rng.borrow_mut();

            if let Some(rng) = rng.as_mut() {
                for i in 0..len as usize {
                    output.add(i).write_volatile(rng.random() as u8);
                }
            }
        });
    }

    otError_OT_ERROR_NONE
}
