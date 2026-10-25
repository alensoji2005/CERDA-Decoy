"""Resource limits so a flood of connections/requests can't exhaust the decoy host."""
import time
from collections import Counter, OrderedDict, deque


class ConnectionLimiter:
    """Caps concurrent connections per source IP and in total."""

    def __init__(self, per_ip: int, total: int):
        self.per_ip, self.total = per_ip, total
        self.by_ip = Counter()

    def acquire(self, ip: str) -> bool:
        if sum(self.by_ip.values()) >= self.total or self.by_ip[ip] >= self.per_ip:
            return False
        self.by_ip[ip] += 1
        return True

    def release(self, ip: str):
        self.by_ip[ip] -= 1
        if self.by_ip[ip] <= 0:
            del self.by_ip[ip]


class RateLimiter:
    """At most `limit` events per `window_s` seconds per key (sliding window)."""

    def __init__(self, limit: int, window_s: float = 60.0, max_keys: int = 10_000):
        self.limit, self.window_s, self.max_keys = limit, window_s, max_keys
        self.events = OrderedDict()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        stamps = self.events.pop(key, None) or deque()
        while stamps and now - stamps[0] > self.window_s:
            stamps.popleft()
        allowed = len(stamps) < self.limit
        if allowed:
            stamps.append(now)
        self.events[key] = stamps
        while len(self.events) > self.max_keys:
            self.events.popitem(last=False)
        return allowed
