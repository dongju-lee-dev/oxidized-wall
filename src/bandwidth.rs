use bytes::Bytes;
use dashmap::DashMap;
use hyper::body::{Body, Frame};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Implementation of the Token Bucket algorithm for rate limiting byte streams.
struct TokenBucket {
    tokens: f64,
    last_fill: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: 0.0,
            last_fill: Instant::now(),
        }
    }

    /// Refills tokens based on time elapsed and tries to consume the requested amount.
    fn consume(&mut self, rate: f64, amount: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_fill).as_secs_f64();
        self.tokens += elapsed * rate;

        // Cap tokens at 2x rate to allow small bursts but prevent massive accumulation
        if self.tokens > rate * 2.0 {
            self.tokens = rate * 2.0;
        }
        self.last_fill = now;

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Global manager for per-IP bandwidth quotas.
pub struct BandwidthLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
}

impl BandwidthLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
        }
    }

    /// Attempt to consume quota for a specific IP.
    pub fn try_consume(&self, ip: IpAddr, rate: u64, amount: u64) -> bool {
        let mut bucket = self.buckets.entry(ip).or_insert(TokenBucket::new());
        bucket.consume(rate as f64, amount as f64)
    }
}

/// A Hyper body wrapper that pauses streaming when the bandwidth quota is exceeded.
pub struct ThrottledBody<B> {
    inner: B,
    limiter: Arc<BandwidthLimiter>,
    ip: IpAddr,
    rate: u64,
    pending_amount: u64,
}

impl<B> ThrottledBody<B> {
    pub fn new(inner: B, limiter: Arc<BandwidthLimiter>, ip: IpAddr, rate: u64) -> Self {
        Self {
            inner,
            limiter,
            ip,
            rate,
            pending_amount: 0,
        }
    }
}

impl<B> Body for ThrottledBody<B>
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin,
{
    type Data = Bytes;
    type Error = hyper::Error;

    /// Polls the inner body and applies token bucket checks to each data frame.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let (rate, ip, limiter) = (self.rate, self.ip, self.limiter.clone());
        if rate == 0 {
            return Pin::new(&mut self.inner).poll_frame(cx);
        }

        let this = self.get_mut();
        // If we had a chunk waiting from the last poll, try to consume it first
        if this.pending_amount > 0 {
            if limiter.try_consume(ip, rate, this.pending_amount) {
                this.pending_amount = 0;
            } else {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let amount = data.len() as u64;
                    if limiter.try_consume(ip, rate, amount) {
                        Poll::Ready(Some(Ok(frame)))
                    } else {
                        this.pending_amount = amount;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                } else {
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            res => res,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
