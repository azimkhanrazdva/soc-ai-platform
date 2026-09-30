from __future__ import annotations

from collections import Counter


def increment_bounded(counter: Counter[str], value: str, limit: int) -> bool:
    """Increment a counter and periodically discard its least frequent keys."""
    counter[value] += 1
    if len(counter) <= limit:
        return False
    retained = counter.most_common(max(1, limit - 1))
    counter.clear()
    counter.update(dict(retained))
    return True