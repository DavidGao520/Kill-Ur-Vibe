"""Per-run budget — bounds a runaway agent.

The egress engine charges the budget on every request, so the cap covers ALL agent
activity (the tool-call count is what correlates with token cost). Once exhausted,
every further request is refused and the agent, unable to act, summarizes and stops.
The clock is injected for testability.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RunBudget:
    max_requests: int = 200          # tool-call cap (the main bound on token cost)
    max_wall_seconds: float = 600.0
    max_writes: int | None = None    # optional cap on state-changing requests
    clock: Callable[[], float] = time.monotonic

    _requests: int = field(default=0, init=False)
    _writes: int = field(default=0, init=False)
    _start: float | None = field(default=None, init=False)

    @property
    def requests_used(self) -> int:
        return self._requests

    @property
    def writes_used(self) -> int:
        return self._writes

    @property
    def elapsed(self) -> float:
        return 0.0 if self._start is None else self.clock() - self._start

    def charge(self, is_write: bool = False) -> str | None:
        """Charge one request. Returns a refusal reason if the budget is exhausted
        (without consuming further), else None and increments the counters."""
        if self._start is None:
            self._start = self.clock()
        elapsed = self.clock() - self._start
        if elapsed > self.max_wall_seconds:
            return f"run budget exhausted: {elapsed:.0f}s wall-clock > {self.max_wall_seconds:.0f}s cap"
        if self._requests >= self.max_requests:
            return f"run budget exhausted: {self.max_requests} tool-call cap reached"
        if is_write and self.max_writes is not None and self._writes >= self.max_writes:
            return f"run budget exhausted: {self.max_writes} write cap reached"
        self._requests += 1
        if is_write:
            self._writes += 1
        return None
