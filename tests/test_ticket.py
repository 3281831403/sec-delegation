import pytest

from deleg.ticket import (
    chain_ok,
    flag_ok,
    issue_delegated,
    parse_ticket,
    scope_narrow,
    ticket_batch,
    time_ok,
    validate_policy,
)

NOW = 1_000_000.0
WINDOW = 60.0
POLICY = {
    "max_hops": 4,
    "allow_scope_expansion": False,
    "require_delegatable_flag": True,
    "window": WINDOW,
    "now": NOW,
}


def _ticket(
    subject="alice",
    service="svc-a",
    scopes=("read",),
    delegatable=True,
    chain=("root",),
    issued=NOW,
):
    flags = {} if delegatable is None else {"delegatable": delegatable}
    return {
        "subject": subject,
        "service": service,
        "scopes": list(scopes),
        "flags": flags,
        "chain": list(chain),
        "issued": issued,
    }


def test_defect_01_flag_must_be_explicitly_true():
    missing = _ticket(delegatable=None)
    disabled = _ticket(delegatable=False)
    enabled = _ticket(delegatable=True)
    assert flag_ok(missing, True) is False
    assert flag_ok(disabled, True) is False
    assert flag_ok(enabled, True) is True
    assert flag_ok(enabled, False) is False
    with pytest.raises(ValueError):
        issue_delegated(missing, "svc-b", ["read"], POLICY)


def test_defect_02_scope_narrow_rejects_union():
    assert scope_narrow(["read", "write"], ["write"]) == ["write"]
    assert scope_narrow(["read", "write"], ["write", "read", "read"]) == [
        "read",
        "write",
    ]
    with pytest.raises(ValueError):
        scope_narrow(["read"], ["read", "write"])
    with pytest.raises(ValueError):
        scope_narrow(["read"], ["admin"])


def test_defect_03_missing_requested_scope_is_empty():
    assert scope_narrow(["read", "write"], None) == []
    assert scope_narrow(["read", "write"], []) == []
    child = issue_delegated(
        _ticket(scopes=["read", "write"]), "svc-b", None, POLICY
    )
    assert child["scopes"] == []


def test_defect_04_chain_limit_is_strict():
    assert chain_ok(["a", "b"], 3) is True
    assert chain_ok(["a", "b", "c"], 3) is False
    with pytest.raises(ValueError):
        issue_delegated(
            _ticket(service="svc-a", chain=["a", "b"]),
            "svc-b",
            ["read"],
            {**POLICY, "max_hops": 3},
        )


def test_defect_05_duplicate_service_in_chain_rejected():
    assert chain_ok(["a", "b"], 5) is True
    assert chain_ok(["a", "b", "a"], 5) is False
    assert chain_ok(["a", "a"], 5) is False


def test_defect_06_time_window_checks_both_ends():
    issued = 1000.0
    window = 10.0
    assert time_ok(issued, issued, window) is True
    assert time_ok(issued, issued + window, window) is True
    assert time_ok(issued, issued + window + 0.001, window) is False
    assert time_ok(issued, issued - 0.001, window) is False


def test_defect_07_zero_length_window_rejected():
    assert time_ok(1000.0, 1000.0, 0.0) is False
    assert time_ok(1000.0, 1000.0, -5.0) is False
    assert time_ok(1000.0, 1000.0, 0.5) is True


def test_defect_08_issued_chain_appends_current_service():
    child = issue_delegated(
        _ticket(service="svc-a", chain=["root"], scopes=["read", "write"]),
        "svc-b",
        ["read"],
        POLICY,
    )
    assert child["chain"] == ["root", "svc-a"]
    assert child["service"] == "svc-b"
    assert child["subject"] == "alice"
    assert child["scopes"] == ["read"]
    assert child["flags"] == {"delegatable": False}
    assert child["issued"] == NOW


def test_defect_09_policy_scope_expansion_is_reported():
    only_expansion = {
        "max_hops": 4,
        "allow_scope_expansion": True,
        "require_delegatable_flag": True,
    }
    assert validate_policy(only_expansion) == ["scope_expansion_allowed"]
    all_bad = {"allow_scope_expansion": True}
    assert validate_policy(all_bad) == [
        "missing_max_hops",
        "scope_expansion_allowed",
        "delegatable_flag_not_required",
    ]
    assert validate_policy(POLICY) == []


def test_defect_10_batch_keeps_requests_independent():
    requests = [
        {
            "id": "r1",
            "parent": _ticket(service="svc-a", chain=["root-a"], scopes=["read"]),
            "target": "svc-b",
            "scopes": ["read"],
        },
        {
            "id": "r2",
            "parent": _ticket(
                service="svc-x", chain=["root-x", "mid-x"], scopes=["write"]
            ),
            "target": "svc-y",
            "scopes": ["write"],
        },
    ]
    result = ticket_batch(requests, POLICY, NOW)
    assert result["r1"]["ok"] is True
    assert result["r2"]["ok"] is True
    assert result["r1"]["ticket"]["chain"] == ["root-a", "svc-a"]
    assert result["r2"]["ticket"]["chain"] == ["root-x", "mid-x", "svc-x"]
    assert result["r1"]["ticket"]["scopes"] == ["read"]
    assert result["r2"]["ticket"]["scopes"] == ["write"]


def test_legal_delegation_narrows_scope():
    parent = _ticket(
        service="svc-a", chain=["root"], scopes=["read", "write", "admin"]
    )
    parsed = parse_ticket(parent)
    assert parsed["subject"] == "alice"
    assert parsed["service"] == "svc-a"
    assert parsed["scopes"] == ["read", "write", "admin"]
    assert parsed["flags"] == {"delegatable": True}
    assert parsed["chain"] == ["root"]
    assert parsed["issued"] == NOW
    child = issue_delegated(parsed, "svc-b", ["write", "read"], POLICY)
    assert child["subject"] == "alice"
    assert child["service"] == "svc-b"
    assert child["scopes"] == ["read", "write"]
    assert child["chain"] == ["root", "svc-a"]
    assert child["flags"] == {"delegatable": False}
    assert child["issued"] == NOW


def test_non_delegatable_ticket_rejected():
    with pytest.raises(ValueError):
        issue_delegated(
            _ticket(delegatable=False), "svc-b", ["read"], POLICY
        )
    with pytest.raises(ValueError):
        issue_delegated(_ticket(delegatable=None), "svc-b", ["read"], POLICY)
    child = issue_delegated(
        _ticket(delegatable=True), "svc-b", ["read"], POLICY
    )
    assert child["flags"] == {"delegatable": False}
    with pytest.raises(ValueError):
        issue_delegated(child, "svc-c", ["read"], POLICY)


def test_scope_expansion_rejected():
    parent = _ticket(scopes=["read"])
    with pytest.raises(ValueError):
        issue_delegated(parent, "svc-b", ["read", "write"], POLICY)
    with pytest.raises(ValueError):
        issue_delegated(parent, "svc-b", ["admin"], POLICY)


def test_chain_over_limit_rejected():
    ok_parent = _ticket(service="svc-c", chain=["a", "b"], scopes=["read"])
    child = issue_delegated(ok_parent, "svc-d", ["read"], POLICY)
    assert child["chain"] == ["a", "b", "svc-c"]
    bad_parent = _ticket(service="svc-d", chain=["a", "b", "c"], scopes=["read"])
    with pytest.raises(ValueError):
        issue_delegated(bad_parent, "svc-e", ["read"], POLICY)


def test_two_batches_independent_match_individual():
    requests = [
        {
            "id": "r1",
            "parent": _ticket(
                service="svc-a", chain=["root-a"], scopes=["read", "write"]
            ),
            "target": "svc-b",
            "scopes": ["read"],
        },
        {
            "id": "r2",
            "parent": _ticket(
                service="svc-x", chain=["root-x", "mid-x"], scopes=["write", "admin"]
            ),
            "target": "svc-y",
            "scopes": ["admin"],
        },
    ]
    first = ticket_batch(requests, POLICY, NOW)
    second = ticket_batch(requests, POLICY, NOW)
    assert first == second
    assert set(first) == {"r1", "r2"}
    for request in requests:
        single = issue_delegated(
            request["parent"], request["target"], request["scopes"], POLICY
        )
        assert first[request["id"]]["ok"] is True
        assert first[request["id"]]["ticket"] == single