from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BudgetExhausted(RuntimeError):
    limit: int

    def __str__(self) -> str:
        return f"request budget exhausted at {self.limit} requests"


@dataclass(slots=True)
class RequestBudget:
    """Mutable counter because each real HTTP attempt consumes shared target state."""

    limit: int
    _consumed: int = 0

    @property
    def remaining(self) -> int:
        return self.limit - self._consumed

    @property
    def consumed(self) -> int:
        return self._consumed

    def consume(self) -> None:
        if self._consumed >= self.limit:
            raise BudgetExhausted(self.limit)
        self._consumed += 1
