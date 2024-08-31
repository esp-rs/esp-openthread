use crate::platform::CURRENT_INSTANCE;
use core::cell::RefCell;
use critical_section::Mutex;
use esp_hal::peripherals::Interrupt;
use esp_hal::prelude::_esp_hal_timer_Timer;
use esp_hal::{
    timer::systimer::{Alarm, SpecificComparator, SpecificUnit, Target},
    Blocking,
};
use esp_hal_procmacros::handler;
use esp_openthread_sys::bindings::otError;
use esp_openthread_sys::bindings::otError_OT_ERROR_NONE;
use esp_openthread_sys::bindings::otInstance;
use esp_openthread_sys::bindings::otPlatAlarmMilliFired;

const TICKS_PER_SECOND: u64 = 16_000_000;

static TIMER: Mutex<
    RefCell<
        Option<
            Alarm<
                'static,
                Target,
                Blocking,
                SpecificComparator<'static, 0>,
                SpecificUnit<'static, 0>,
            >,
        >,
    >,
> = Mutex::new(RefCell::new(None));

static TIMER_CALLBACK_SHOULD_RUN: Mutex<RefCell<bool>> = Mutex::new(RefCell::new(false));

pub fn install_isr(
    timer: Alarm<
        'static,
        Target,
        Blocking,
        SpecificComparator<'static, 0>,
        SpecificUnit<'static, 0>,
    >,
) {
    timer.clear_interrupt();

    // otPlatAlarmMilliStartAt will set the target as needed
    critical_section::with(|cs| {
        timer.set_interrupt_handler(SYSTIMER_TARGET0);
        timer.enable_interrupt(true);
        TIMER.borrow_ref_mut(cs).replace(timer);
    });

    esp_hal::interrupt::enable(
        Interrupt::SYSTIMER_TARGET0,
        esp_hal::interrupt::Priority::Priority1,
    )
    .unwrap();
}

pub fn set_timer_target(when: u32) {
    let timestamp = when as u64 * (TICKS_PER_SECOND / 1000);
    log::trace!("Setting timer target {timestamp:}");
    critical_section::with(|cs| {
        let mut timer = TIMER.borrow_ref_mut(cs);
        let timer = timer.as_mut().unwrap();
        timer.set_target(timestamp);
        timer.enable_interrupt(true);
    });
}

pub fn stop() {
    critical_section::with(|cs| {
        let mut timer = TIMER.borrow_ref_mut(cs);
        let timer = timer.as_mut().unwrap();
        timer.clear_interrupt();
        timer.enable_interrupt(false);
    });
}

#[handler]
fn SYSTIMER_TARGET0() {
    log::warn!("timer interrupt triggered at {}", current_millis());
    // clear the interrupt
    critical_section::with(|cs| {
        TIMER.borrow_ref_mut(cs).as_mut().unwrap().clear_interrupt();
    });

    timer_triggered();
}

pub fn current_millis() -> u64 {
    esp_hal::timer::systimer::SystemTimer::now() / (TICKS_PER_SECOND / 1000)
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliGetNow(_instance: *const otInstance) -> u32 {
    log::trace!("otPlatAlarmMilliGetNow");
    crate::timer::current_millis() as u32
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStartAt(
    instance: *mut otInstance,
    at0: u32,
    adt: u32,
) -> otError {
    log::trace!("otPlatAlarmMilliStartAt {at0} {adt}");
    unsafe {
        CURRENT_INSTANCE = instance as usize;
    }
    crate::timer::set_timer_target(at0 + adt);
    otError_OT_ERROR_NONE
}

#[no_mangle]
pub extern "C" fn otPlatAlarmMilliStop(_instance: *const otInstance) -> otError {
    log::trace!("otPlatAlarmMilliStop");
    crate::timer::stop();
    otError_OT_ERROR_NONE
}

fn timer_triggered() {
    critical_section::with(|cs| *TIMER_CALLBACK_SHOULD_RUN.borrow_ref_mut(cs) = true);
}

pub(crate) fn run_if_due() {
    let should_run = critical_section::with(|cs| {
        let res = *TIMER_CALLBACK_SHOULD_RUN.borrow_ref_mut(cs);
        *TIMER_CALLBACK_SHOULD_RUN.borrow_ref_mut(cs) = false;
        res
    });

    if should_run {
        unsafe {
            let instance = CURRENT_INSTANCE as *mut otInstance;
            otPlatAlarmMilliFired(instance);
        }
    }
}
