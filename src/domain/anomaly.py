from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class ObservedEvent:
    actor_id: str | None
    action: str
    result: str


@dataclass(frozen=True)
class Alert:
    kind: str
    actor_id: str | None
    count: int


def detect(
    events: list[ObservedEvent],
    *,
    denial_threshold: int = 5,
    notfound_threshold: int = 10,
) -> list[Alert]:
    """Flag actors whose recent activity looks like probing:
    - many denied requests (brute-forcing access)
    - many not_found reads (path enumeration)
    """
    denials: Counter[str | None] = Counter()
    notfound: Counter[str | None] = Counter()
    for event in events:
        if event.result == "denied":
            denials[event.actor_id] += 1
        elif event.result == "not_found":
            notfound[event.actor_id] += 1

    alerts: list[Alert] = []
    for actor_id, count in denials.items():
        if count >= denial_threshold:
            alerts.append(Alert("excessive_denials", actor_id, count))
    for actor_id, count in notfound.items():
        if count >= notfound_threshold:
            alerts.append(Alert("path_enumeration", actor_id, count))
    return alerts
