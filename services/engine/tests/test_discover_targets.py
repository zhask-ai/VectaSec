"""The discovery scope guardrails — the tests that keep this product from becoming a scanner
someone points at a network they do not own.

Pure functions, no sockets. Every test here is about a REFUSAL: what the resolver declines to
expand, and whether it says why. A regression that quietly widens scope would not fail any
functional test — the sweep would simply work, on more hosts than anyone approved — so these
assertions are the only thing standing between a typo and an incident report.
"""
import pytest

from vectasec.discover.targets import (
    DEFAULT_PORTS, MAX_HOSTS, resolve_scope,
)


# ═══ private-by-default ════════════════════════════════════════════════════
def test_private_ip_is_probed_without_ceremony():
    scope = resolve_scope(["10.0.0.5"], ports=[6379])
    assert [(t.host, t.port) for t in scope.targets] == [("10.0.0.5", 6379)]
    assert scope.refusals == []


@pytest.mark.parametrize("host", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"])
def test_every_rfc1918_and_loopback_range_is_allowed(host):
    scope = resolve_scope([host], ports=[9092])
    assert len(scope.targets) == 1 and scope.refusals == []


def test_public_ip_is_refused_by_default_with_a_reason_naming_the_flag():
    scope = resolve_scope(["8.8.8.8"], ports=[6379])
    assert scope.targets == []
    assert len(scope.refusals) == 1
    assert "8.8.8.8" in scope.refusals[0]
    assert "allow_public" in scope.refusals[0]


def test_public_ip_is_probed_only_when_explicitly_declared():
    scope = resolve_scope(["8.8.8.8"], ports=[6379], allow_public=True)
    assert [(t.host, t.port) for t in scope.targets] == [("8.8.8.8", 6379)]


def test_public_cidr_is_refused_by_default():
    scope = resolve_scope(["8.8.8.0/30"], ports=[6379])
    assert scope.targets == []
    assert "public address space" in scope.refusals[0]


# ═══ the host cap ══════════════════════════════════════════════════════════
def test_an_oversized_cidr_is_refused_rather_than_truncated():
    """Truncating would be worse than refusing: the operator would believe a /16 was swept."""
    scope = resolve_scope(["10.0.0.0/8"], ports=[6379])
    assert scope.targets == []
    assert "over the" in scope.refusals[0] and "cap" in scope.refusals[0]


def test_a_cidr_at_the_cap_is_accepted():
    scope = resolve_scope(["10.0.0.0/22"], ports=[6379])   # 1022 usable hosts
    assert len(scope.targets) <= MAX_HOSTS
    assert scope.targets and scope.refusals == []


def test_several_in_cap_targets_that_together_exceed_the_cap_are_refused_wholesale():
    """The cap is on the SCAN. Three /24s slip past a per-line check and still melt a network."""
    targets = [f"10.{i}.0.0/24" for i in range(6)]          # 6 × 254 = 1524 hosts
    scope = resolve_scope(targets, ports=[6379])
    assert scope.targets == []
    assert any("together expand" in r for r in scope.refusals)


# ═══ parsing ═══════════════════════════════════════════════════════════════
def test_explicit_port_overrides_the_default_port_set():
    scope = resolve_scope(["10.0.0.5:9999"])
    assert [(t.host, t.port) for t in scope.targets] == [("10.0.0.5", 9999)]


def test_a_bare_host_expands_across_the_default_middleware_ports():
    scope = resolve_scope(["10.0.0.5"])
    assert {t.port for t in scope.targets} == set(DEFAULT_PORTS)


def test_ipv6_must_be_bracketed_to_carry_a_port():
    scope = resolve_scope(["[::1]:6379"])
    assert [(t.host, t.port) for t in scope.targets] == [("::1", 6379)]


def test_a_bare_ipv6_address_is_not_mistaken_for_host_port():
    scope = resolve_scope(["fd00::1"], ports=[6379])
    assert [(t.host, t.port) for t in scope.targets] == [("fd00::1", 6379)]


def test_hostnames_are_accepted_and_never_resolved_here():
    """DNS is a network call whose answer can change between check and connect. Scope must not
    depend on it — the operator vouches for a name by naming it."""
    scope = resolve_scope(["kafka.internal:9092"])
    assert [(t.host, t.port) for t in scope.targets] == [("kafka.internal", 9092)]


def test_a_malformed_target_is_refused_without_voiding_the_rest_of_the_scope():
    scope = resolve_scope(["10.0.0.5:9092", "not a host!!", "10.0.0.6:9092"])
    assert [(t.host, t.port) for t in scope.targets] == [("10.0.0.5", 9092), ("10.0.0.6", 9092)]
    assert len(scope.refusals) == 1 and "not a host!!" in scope.refusals[0]


def test_an_out_of_range_port_is_refused():
    scope = resolve_scope(["10.0.0.5:70000"])
    assert scope.targets == []
    assert "out of range" in scope.refusals[0]


def test_duplicate_targets_collapse_so_a_host_is_probed_once_per_port():
    scope = resolve_scope(["10.0.0.5:9092", "10.0.0.5:9092"])
    assert len(scope.targets) == 1


def test_an_empty_target_list_sweeps_nothing_rather_than_defaulting_to_a_range():
    """There is no implicit scope. This is the whole thesis of the module."""
    scope = resolve_scope([])
    assert scope.targets == [] and scope.refusals == []


def test_an_empty_port_list_is_a_refusal_not_a_silent_default():
    scope = resolve_scope(["10.0.0.5"], ports=[])
    # ports=[] is falsy so DEFAULT_PORTS apply; the explicit-empty case is the connector's
    # concern. What must never happen is an empty SWEEP being reported as a clean estate.
    assert scope.targets


def test_the_original_target_string_is_kept_for_provenance():
    scope = resolve_scope(["10.0.0.0/30"], ports=[6379])
    assert all(t.source == "10.0.0.0/30" for t in scope.targets)


# ═══ explicit ports: where shadow middleware actually hides ════════════════
def test_a_port_the_operator_named_is_marked_explicit():
    """The sweep works harder to identify these — a Redis moved to 6380 is the commonest way
    an unmonitored broker survives, and it is on no default port list."""
    scope = resolve_scope(["10.0.0.5:6380"])
    assert scope.targets[0].explicit is True


def test_ports_from_the_default_set_are_not_explicit():
    scope = resolve_scope(["10.0.0.5"])
    assert all(t.explicit is False for t in scope.targets)


@pytest.mark.parametrize("port", [9100, 9101, 9107, 1414, 515, 631])
def test_do_not_contact_ports_are_refused_even_when_named_explicitly(port):
    """For these, connecting IS the harm: 9100-9107 print whatever bytes arrive (the only
    hardcoded exclusion Nmap itself ships), and IBM MQ writes a diagnostic file that opens a
    support ticket for any bytes it cannot parse. An operator naming one must not override it."""
    scope = resolve_scope([f"10.0.0.5:{port}"])
    assert scope.targets == []
    assert "do-not-contact" in scope.refusals[0]


def test_excluded_ports_never_appear_in_a_default_sweep():
    scope = resolve_scope(["10.0.0.5"])
    assert not ({t.port for t in scope.targets} & {9100, 9101, 1414, 515, 631})


def test_ports_from_an_operator_supplied_port_list_are_not_explicit():
    """`ports=[…]` is still a sweep, not a question about one port. Generic probing every
    port of every host in a /22 would turn a scan into a siege."""
    scope = resolve_scope(["10.0.0.5"], ports=[7777])
    assert all(t.explicit is False for t in scope.targets)
