import time
import threading


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_requests: int, per_seconds: int = 60):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """Try to acquire a request slot. Returns False if rate limited."""
        now = time.time()
        with self._lock:
            self._timestamps = [
                t for t in self._timestamps if now - t < self.per_seconds
            ]
            if len(self._timestamps) >= self.max_requests:
                return False
            self._timestamps.append(now)
            return True
