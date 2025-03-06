//! A synchronization primitive for passing the latest value to a task.

use core::task::{Context, Poll, Waker};

pub struct Signal<T>(State<T>);

enum State<T> {
    None,
    Waiting(Waker),
    Signaled(T),
}

impl<T> Signal<T> {
    /// Create a new `Signal`.
    pub const fn new() -> Self {
        Self(State::None)
    }
}

impl<T> Default for Signal<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Signal<T> {
    /// Mark this Signal as signaled.
    pub fn signal(&mut self, val: T) {
        let state = core::mem::replace(&mut self.0, State::Signaled(val));
        if let State::Waiting(waker) = state {
            waker.wake();
        }
    }

    /// Remove the queued value in this `Signal`, if any.
    pub fn reset(&mut self) {
        self.0 = State::None;
    }

    pub fn poll_wait(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        let state = core::mem::replace(&mut self.0, State::None);
        match state {
            State::None => {
                self.0 = State::Waiting(cx.waker().clone());
                Poll::Pending
            }
            State::Waiting(w) if w.will_wake(cx.waker()) => {
                self.0 = State::Waiting(w);
                Poll::Pending
            }
            State::Waiting(w) => {
                self.0 = State::Waiting(cx.waker().clone());
                w.wake();
                Poll::Pending
            }
            State::Signaled(res) => Poll::Ready(res),
        }
    }

    pub fn poll_wait_triggered(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let state = core::mem::replace(&mut self.0, State::None);
        match state {
            State::None => {
                self.0 = State::Waiting(cx.waker().clone());
                Poll::Pending
            }
            State::Waiting(w) if w.will_wake(cx.waker()) => {
                self.0 = State::Waiting(w);
                Poll::Pending
            }
            State::Waiting(w) => {
                self.0 = State::Waiting(cx.waker().clone());
                w.wake();
                Poll::Pending
            }
            State::Signaled(res) => {
                self.0 = State::Signaled(res);
                Poll::Ready(())
            }
        }
    }

    /// non-blocking method to try and take the signal value.
    pub fn try_take(&mut self) -> Option<T> {
        let state = core::mem::replace(&mut self.0, State::None);
        match state {
            State::Signaled(res) => Some(res),
            state => {
                self.0 = state;
                None
            }
        }
    }

    /// non-blocking method to check whether this signal has been signaled. This does not clear the signal.  
    pub fn signaled(&self) -> bool {
        matches!(self.0, State::Signaled(_))
    }
}
