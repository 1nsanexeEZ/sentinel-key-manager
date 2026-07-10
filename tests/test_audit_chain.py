from src.domain.audit_chain import AuditEvent, compute_hash, verify_chain


def _event(action: str, result: str = "success") -> AuditEvent:
    return AuditEvent(
        actor_id="user-1",
        action=action,
        resource="app/db",
        result=result,
        client_ip="127.0.0.1",
    )


def _build_chain(events: list[AuditEvent]) -> list:
    rows = []
    prev = ""
    for i, event in enumerate(events, start=1):
        h = compute_hash(prev, event)
        rows.append((i, event, prev, h))
        prev = h
    return rows


def test_valid_chain_passes():
    rows = _build_chain([_event("read"), _event("write"), _event("delete")])
    check = verify_chain(rows)
    assert check.valid is True
    assert check.checked == 3
    assert check.broken_at is None


def test_empty_chain_is_valid():
    assert verify_chain([]).valid is True


def test_tampered_record_is_detected():
    rows = _build_chain([_event("read"), _event("write"), _event("delete")])
    # tamper with the middle event's stored fields, keeping its hash
    rid, _event_old, prev, stored_hash = rows[1]
    rows[1] = (rid, _event("write", result="denied"), prev, stored_hash)
    check = verify_chain(rows)
    assert check.valid is False
    assert check.broken_at == rid


def test_deleted_record_breaks_chain():
    rows = _build_chain([_event("read"), _event("write"), _event("delete")])
    del rows[1]  # remove middle record; third's prev_hash no longer matches
    check = verify_chain(rows)
    assert check.valid is False
