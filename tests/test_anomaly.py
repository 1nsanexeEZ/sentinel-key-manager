from src.domain.anomaly import ObservedEvent, detect


def _events(actor: str, result: str, n: int) -> list[ObservedEvent]:
    return [ObservedEvent(actor, "read", result) for _ in range(n)]


def test_no_alerts_below_threshold():
    assert detect(_events("u1", "denied", 4)) == []


def test_excessive_denials_flagged():
    alerts = detect(_events("u1", "denied", 6))
    assert len(alerts) == 1
    assert alerts[0].kind == "excessive_denials"
    assert alerts[0].actor_id == "u1"
    assert alerts[0].count == 6


def test_path_enumeration_flagged():
    alerts = detect(_events("u2", "not_found", 12))
    assert len(alerts) == 1
    assert alerts[0].kind == "path_enumeration"


def test_success_events_never_alert():
    assert detect(_events("u1", "success", 100)) == []


def test_per_actor_counting():
    events = _events("u1", "denied", 6) + _events("u2", "denied", 2)
    alerts = detect(events)
    assert {a.actor_id for a in alerts} == {"u1"}
