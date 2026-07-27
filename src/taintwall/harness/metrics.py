"""Proportions with Wilson confidence intervals.

Every rate this project reports carries its sample size and an interval, because
at roughly thirteen records per family a ten-to-fifteen point swing is noise. A
point estimate with no interval is the single most misleading thing a security
evaluation can print.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

_Z = 1.959963984540054  # two-sided 95%

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Proportion:
    successes: int
    trials: int

    @property
    def rate(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    def ci95(self) -> tuple[float, float]:
        """Wilson score interval. Wide on small samples, which is the point."""
        n = self.trials
        if n == 0:
            return (0.0, 1.0)
        p = self.rate
        denominator = 1.0 + _Z**2 / n
        centre = (p + _Z**2 / (2 * n)) / denominator
        spread = _Z * math.sqrt(p * (1 - p) / n + _Z**2 / (4 * n**2)) / denominator
        return (max(0.0, centre - spread), min(1.0, centre + spread))

    def format(self) -> str:
        low, high = self.ci95()
        return f"{self.rate:.1%} [{low:.1%}-{high:.1%}] n={self.trials}"


def aggregate(
    rows: Iterable[T],
    *,
    key: Callable[[T], str],
    success: Callable[[T], bool],
) -> dict[str, Proportion]:
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        bucket = counts[key(row)]
        bucket[1] += 1
        if success(row):
            bucket[0] += 1
    return {name: Proportion(s, t) for name, (s, t) in counts.items()}
