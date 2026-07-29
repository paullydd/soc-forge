import pytest

from soc_forge.correlate.rules import correlate_alerts
from soc_forge.rules.engine import load_rules, run_rules


RULES = load_rules([
    "soc_forge/rules/SOCF-003.yml",
    "soc_forge/rules/SOCF-008.yml",
])


def _event(event_id: int, group_name: str, message: str) -> dict:
    return {
        "timestamp": "2026-07-17T12:00:00Z",
        "event_id": event_id,
        "host": "DC1",
        "actor": "admin01",
        "username": "alice",
        "target_user": "alice",
        "group_name": group_name,
        "message": message,
    }


def _rule_ids(event: dict) -> list[str]:
    return [alert["rule_id"] for alert in run_rules([event], RULES)]


def test_socf_003_owns_privileged_domain_global_group_additions():
    event = _event(4728, "Domain Admins", "A member was added to the Domain Admins group.")

    assert _rule_ids(event) == ["SOCF-003"]


def test_socf_008_owns_privileged_local_group_additions():
    event = _event(4732, "Administrators", "A member was added to the local Administrators group.")

    assert _rule_ids(event) == ["SOCF-008"]


def test_socf_008_owns_privileged_universal_group_additions():
    event = _event(4756, "Enterprise Admins", "A member was added to the Enterprise Admins group.")

    assert _rule_ids(event) == ["SOCF-008"]


def test_privileged_group_message_on_unrelated_event_does_not_alert():
    event = _event(4624, "Administrators", "User logged on as an Administrators group member.")

    assert _rule_ids(event) == []


def test_generic_group_addition_requires_a_privileged_group_name():
    event = _event(4732, "Marketing", "A member was added to a security-enabled local group.")

    assert _rule_ids(event) == []


@pytest.mark.parametrize("admin_rule_id", ["SOCF-003", "SOCF-008"])
def test_rdp_privileged_group_correlation_accepts_each_owner(admin_rule_id):
    alerts = [
        {
            "rule_id": "SOCF-006",
            "timestamp": "2026-07-17T12:00:00Z",
            "details": {"host": "DC1", "username": "alice", "ip": "203.0.113.10"},
        },
        {
            "rule_id": admin_rule_id,
            "timestamp": "2026-07-17T12:05:00Z",
            "details": {"host": "DC1", "username": "alice", "group_name": "Domain Admins"},
        },
    ]

    correlated = correlate_alerts(
        alerts,
        bruteforce_lockout_enabled=False,
        rdp_schtask_enabled=False,
    )

    correlation_ids = [alert["rule_id"] for alert in correlated if alert["rule_id"].startswith("SOCF-CORR")]
    assert correlation_ids == ["SOCF-CORR-003"]
