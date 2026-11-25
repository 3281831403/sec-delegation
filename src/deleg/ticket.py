"""Delegation ticket core for the security exercise.

A ticket is a plain dict with these fields:

    subject: str
        Principal on whose behalf the ticket is used.
    service: str
        Audience service that receives the ticket.
    scopes: list[str]
        Permissions carried by the ticket.
    flags: dict[str, bool]
        Must carry an explicit delegatable entry before any further delegation.
    chain: list[str]
        Services already traversed, oldest first.
    issued: float
        Issuance time in epoch seconds.

A policy is a plain dict with these fields:

    max_hops: int
        Exclusive chain bound: a chain with len(chain) >= max_hops is too long.
    allow_scope_expansion: bool
        Must be False.
    require_delegatable_flag: bool
        Must be True.
    window: float
        Ticket lifetime in seconds, used by ticket_batch.
    now: float
        Optional issuance timestamp used by issue_delegated.
"""

from collections.abc import Mapping

_REQUIRED_FIELDS = (
    "subject",
    "service",
    "scopes",
    "flags",
    "chain",
    "issued",
)


def parse_ticket(ticket: dict) -> dict:
    """Return a normalized copy of ticket.

    Require the six fields documented above. Scopes and chain must be lists of
    strings, flags must be a mapping, and issued must be a non-boolean number.
    A missing delegatable entry is preserved so that flag_ok can reject it.
    Raise ValueError for malformed input.
    """
    if not isinstance(ticket, Mapping):
        raise ValueError("ticket must be a mapping")

    for field in _REQUIRED_FIELDS:
        if field not in ticket:
            raise ValueError(f"ticket is missing required field: {field}")

    subject = ticket["subject"]
    service = ticket["service"]
    if not isinstance(subject, str):
        raise ValueError("ticket subject must be a string")
    if not isinstance(service, str):
        raise ValueError("ticket service must be a string")

    scopes = ticket["scopes"]
    if not isinstance(scopes, list) or not all(
        isinstance(scope, str) for scope in scopes
    ):
        raise ValueError("ticket scopes must be a list of strings")

    chain = ticket["chain"]
    if not isinstance(chain, list) or not all(
        isinstance(name, str) for name in chain
    ):
        raise ValueError("ticket chain must be a list of strings")

    flags = ticket["flags"]
    if not isinstance(flags, Mapping):
        raise ValueError("ticket flags must be a mapping")

    issued = ticket["issued"]
    if isinstance(issued, bool) or not isinstance(issued, (int, float)):
        raise ValueError("ticket issued must be a non-boolean number")

    # Fresh containers: callers can never mutate the source ticket through
    # the normalized copy. A missing flags["delegatable"] stays missing.
    return {
        "subject": subject,
        "service": service,
        "scopes": list(scopes),
        "flags": dict(flags),
        "chain": list(chain),
        "issued": issued,
    }


def flag_ok(ticket: dict, delegatable: bool) -> bool:
    """Return True only when the ticket carries an explicit boolean
    delegatable flag whose value equals the requested delegatable value.

    An absent flag is never acceptable. A ticket that is not explicitly marked
    delegatable must not be used to issue another delegation ticket.
    """
    # Defect 01: an explicit, boolean flag equal to the requested value is
    # mandatory. Missing flags, non-boolean values and mismatches all fail.
    if not isinstance(ticket, Mapping):
        return False
    flags = ticket.get("flags")
    if not isinstance(flags, Mapping):
        return False
    if "delegatable" not in flags:
        return False
    flag = flags["delegatable"]
    return isinstance(flag, bool) and flag is delegatable


def scope_narrow(original, requested) -> list:
    """Return the delegated scopes, which must stay inside the original set.

    None or an empty requested list means no scopes were requested and yields
    an empty list, never the full parent scope. Any requested scope outside the
    original scopes is a scope expansion and must raise ValueError. The result
    is deduplicated and keeps the order of the original scopes.
    """
    # Defect 03: an undeclared/empty request grants *no* scopes instead of
    # inheriting the parent's full scope set.
    if requested is None:
        return []
    try:
        requested_list = list(requested)
    except TypeError as exc:
        raise ValueError("requested scopes must be a list of strings") from exc
    if not requested_list:
        return []

    original_list = list(original)
    allowed = set(original_list)

    # Defect 02: delegation is an intersection/subset, never a union. Every
    # requested scope must already exist on the parent ticket.
    for scope in requested_list:
        if not isinstance(scope, str):
            raise ValueError("requested scope must be a string")
        if scope not in allowed:
            raise ValueError(f"requested scope is not held by parent: {scope!r}")

    requested_set = set(requested_list)
    result = []
    seen = set()
    for scope in original_list:
        if scope in requested_set and scope not in seen:
            result.append(scope)
            seen.add(scope)
    return result


def _valid_positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def chain_ok(chain, max_hops) -> bool:
    """Return True only when the forwarding chain is acceptable.

    The chain must be a list of non-empty service names with no duplicates.
    It must satisfy len(chain) < max_hops: equality is already too long, so a
    max_hops of 3 allows at most two entries. Invalid max_hops means False.
    """
    if not isinstance(chain, list):
        return False
    if not _valid_positive_int(max_hops):
        return False

    # Defect 05: the same service appearing twice in one chain is a replay /
    # loop indicator and must be rejected rather than deduplicated silently.
    seen = set()
    for name in chain:
        if not isinstance(name, str) or name == "":
            return False
        if name in seen:
            return False
        seen.add(name)

    # Defect 04: the bound is exclusive. len(chain) == max_hops is already
    # one hop too many, hence strict < instead of <= / loose > comparison.
    return len(chain) < max_hops


def time_ok(issued, now, window) -> bool:
    """Return True only when now is inside the inclusive ticket window.

    Both ends are inclusive: issued <= now <= issued + window. A window of
    zero or less is invalid and must be rejected. A now before issued is also
    outside the window, so clock skew is checked in both directions.
    """
    for value in (issued, now, window):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False

    # Defect 07: a zero/negative lifetime defines no valid window.
    if window <= 0:
        return False

    # Defect 06: check both ends of the window, not just the start. The upper
    # bound is inclusive so a ticket is valid exactly through issued + window.
    return issued <= now <= issued + window


def issue_delegated(parent, target, scopes, policy) -> dict:
    """Issue a child delegation ticket and return it.

    Parse the parent, require an explicit delegatable flag, reject a chain
    that is too long after appending the current service, and reject any scope
    expansion. The child keeps the parent subject, targets the requested
    service, receives only the narrowed scopes, is explicitly marked
    non-delegatable, and appends the current service to the forwarding chain.
    Its issued time is policy.now when present, otherwise parent.issued.
    Raise ValueError on any refusal.
    """
    ticket = parse_ticket(parent)

    # Defect 01 (issuance side): a ticket without an explicit
    # delegatable=true flag can never mint a child ticket.
    if not flag_ok(ticket, True):
        raise ValueError("parent ticket is not explicitly delegatable")

    if not isinstance(policy, Mapping):
        raise ValueError("policy must be a mapping")

    # Defect 08: the chain records the delegating (current) service, so the
    # audit trail stays unbroken. Build a fresh list; never mutate parent.
    candidate_chain = ticket["chain"] + [ticket["service"]]

    max_hops = policy.get("max_hops")
    if not chain_ok(candidate_chain, max_hops):
        raise ValueError("forwarding chain is duplicated, invalid, or too long")

    # Defects 02/03: strict subset narrowing; absent scopes mean empty.
    child_scopes = scope_narrow(ticket["scopes"], scopes)

    issued_at = policy.get("now")
    if issued_at is None:
        issued_at = ticket["issued"]

    return {
        "subject": ticket["subject"],
        "service": target,
        "scopes": child_scopes,
        # Children are always born non-delegatable: delegation cannot be
        # propagated further unless a caller explicitly re-flags a ticket.
        "flags": {"delegatable": False},
        "chain": candidate_chain,
        "issued": issued_at,
    }


def validate_policy(policy) -> list[str]:
    """Return policy problem codes in a stable order, empty when valid.

    Codes:
        missing_max_hops
        scope_expansion_allowed
        delegatable_flag_not_required

    A policy is invalid when max_hops is absent or not a positive integer,
    when allow_scope_expansion is not exactly False, or when
    require_delegatable_flag is not exactly True.
    """
    if not isinstance(policy, Mapping):
        policy = {}

    problems = []

    # Defect 09: policy review must flag a configuration that permits scope
    # expansion, alongside the other two baseline misconfigurations. Codes
    # are emitted in this fixed, test-required order.
    max_hops = policy.get("max_hops")
    if not _valid_positive_int(max_hops):
        problems.append("missing_max_hops")

    if policy.get("allow_scope_expansion") is not False:
        problems.append("scope_expansion_allowed")

    if policy.get("require_delegatable_flag") is not True:
        problems.append("delegatable_flag_not_required")

    return problems


def ticket_batch(requests, policy, now) -> dict:
    """Validate and issue a batch of independent delegation requests.

    Each request is a dict with id, parent, target and scopes. Return a dict
    keyed by request id. A successful entry is {"ok": True, "ticket": child};
    a refused entry is {"ok": False, "error": text}. Every request starts from
    its own parent chain, and no mutable state may leak between requests.
    Parent time windows are checked against now before issuance.
    """
    window = policy.get("window") if isinstance(policy, Mapping) else None
    results = {}

    for request in requests:
        request_id = request.get("id") if isinstance(request, Mapping) else None
        try:
            if not isinstance(request, Mapping):
                raise ValueError("request must be a mapping")

            parent = request["parent"]

            # Defect 06/07 at the batch boundary: refuse parents whose
            # lifetime does not cover the batch's validation instant.
            issued = parent["issued"] if isinstance(parent, Mapping) else None
            if not time_ok(issued, now, window):
                raise ValueError("parent ticket is outside its validity window")

            # Defect 10: every request goes through the pure issue_delegated
            # path from its own parent dict. Nothing (chain, scopes, flags)
            # is stored on a shared/cursor object between iterations, so the
            # second request can never inherit the first request's chain.
            child = issue_delegated(
                parent,
                request["target"],
                request["scopes"],
                policy,
            )
            results[request_id] = {"ok": True, "ticket": child}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            message = str(exc)
            if not message:
                message = exc.__class__.__name__
            results[request_id] = {"ok": False, "error": message}

    return results
