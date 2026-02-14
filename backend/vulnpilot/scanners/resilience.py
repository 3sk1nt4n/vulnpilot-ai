"""
VulnPilot AI - Scanner Resilience Layer
Rate limiting, retry with exponential backoff, and circuit breaker
for all scanner providers.

Usage:
    from vulnpilot.scanners.resilience import RateLimiter, retry_with_backoff
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    await limiter.acquire()
"""

import asyncio
import functools
import logging
import time
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)


class RateLimiter:
    """Sliding window rate limiter for API calls."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and (now - self._timestamps[0]) > self.window_seconds:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.max_requests:
                wait_time = self.window_seconds - (now - self._timestamps[0]) + 0.1
                logger.debug(f"Rate limit hit ({self.max_requests}/{self.window_seconds}s). Waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                now = time.monotonic()
                while self._timestamps and (now - self._timestamps[0]) > self.window_seconds:
                    self._timestamps.popleft()
            self._timestamps.append(time.monotonic())


class CircuitBreaker:
    """CLOSED → OPEN → HALF_OPEN circuit breaker."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._state = "CLOSED"

    @property
    def state(self) -> str:
        if self._state == "OPEN" and self._last_failure_time and \
           (time.monotonic() - self._last_failure_time) > self.recovery_timeout:
            self._state = "HALF_OPEN"
        return self._state

    def record_success(self):
        self._failure_count = 0
        self._state = "CLOSED"

    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self.failure_threshold:
            self._state = "OPEN"
            logger.warning(f"Circuit breaker OPEN after {self._failure_count} failures")

    def is_available(self) -> bool:
        return self.state != "OPEN"


def retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=60.0, retry_on=(Exception,)):
    """Decorator: retry async functions with exponential backoff + retry-after header respect."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if attempt == max_retries:
                        logger.error(f"{func.__name__} failed after {max_retries+1} attempts: {e}")
                        raise
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    resp = getattr(e, 'response', None)
                    if resp and hasattr(resp, 'headers'):
                        ra = resp.headers.get('retry-after') or resp.headers.get('X-RateLimit-ToWait-Sec')
                        if ra:
                            try: delay = max(delay, float(ra))
                            except (ValueError, TypeError): pass
                    logger.warning(f"{func.__name__} attempt {attempt+1}/{max_retries+1} failed. Retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
            raise last_exc
        return wrapper
    return decorator


# Pre-configured per-scanner
SCANNER_RATE_LIMITS = {
    "tenable": RateLimiter(max_requests=8, window_seconds=60),
    "qualys": RateLimiter(max_requests=2, window_seconds=1),
    "rapid7": RateLimiter(max_requests=50, window_seconds=60),
    "openvas": RateLimiter(max_requests=5, window_seconds=10),
    "wazuh": RateLimiter(max_requests=200, window_seconds=60),
    "nvd": RateLimiter(max_requests=4, window_seconds=30),
    "epss": RateLimiter(max_requests=20, window_seconds=60),
    "abusech": RateLimiter(max_requests=10, window_seconds=60),
}
SCANNER_CIRCUIT_BREAKERS = {
    "tenable": CircuitBreaker(failure_threshold=5, recovery_timeout=120),
    "qualys": CircuitBreaker(failure_threshold=3, recovery_timeout=180),
    "rapid7": CircuitBreaker(failure_threshold=5, recovery_timeout=120),
    "openvas": CircuitBreaker(failure_threshold=3, recovery_timeout=60),
    "wazuh": CircuitBreaker(failure_threshold=5, recovery_timeout=60),
}

def get_rate_limiter(provider: str) -> RateLimiter:
    return SCANNER_RATE_LIMITS.get(provider, RateLimiter(max_requests=10, window_seconds=60))

def get_circuit_breaker(provider: str) -> CircuitBreaker:
    return SCANNER_CIRCUIT_BREAKERS.get(provider, CircuitBreaker())
