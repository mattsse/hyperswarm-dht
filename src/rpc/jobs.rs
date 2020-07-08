use std::pin::Pin;
use std::time::Duration;

use futures::task::{Context, Poll};
use futures::Future;
use wasm_timer::{Delay, Instant};

/// Periodic job.
#[derive(Debug)]
pub struct PeriodicJob {
    pub next_publish: Instant,
    pub interval: Duration,
    pub inner: Delay,
}

impl PeriodicJob {
    pub fn new(interval: Duration) -> Self {
        Self {
            next_publish: Instant::now() + interval,
            interval,
            inner: Delay::new(interval),
        }
    }

    pub fn poll(&mut self, cx: &mut Context, now: Instant) -> Poll<()> {
        let mut ready = self.next_publish > now;
        if let Poll::Ready(Ok(_)) = Delay::poll(Pin::new(&mut self.inner), cx) {
            ready = true;
        }
        if ready {
            let deadline = now + self.interval;
            self.inner = Delay::new_at(deadline);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
