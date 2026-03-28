from soc_forge.simulator.attack_simulator import generate_scenario


def test_generate_password_spray_returns_events():
    events = generate_scenario("password_spray")
    assert len(events) == 9


def test_generate_password_spray_contains_failed_logons():
    events = generate_scenario("password_spray")
    failed = [e for e in events if e.get("event_id") == 4625]
    assert len(failed) == 8


def test_generate_password_spray_contains_success_logon():
    events = generate_scenario("password_spray")
    success = [e for e in events if e.get("event_id") == 4624]
    assert len(success) == 1


def test_generate_password_spray_has_multiple_usernames():
    events = generate_scenario("password_spray")
    usernames = {e.get("username") for e in events if e.get("event_id") == 4625}
    assert len(usernames) == 8


def test_generate_password_spray_uses_same_ip_and_host():
    events = generate_scenario("password_spray")
    ips = {e.get("src_ip") for e in events}
    hosts = {e.get("host") for e in events}
    assert ips == {"203.0.113.55"}
    assert hosts == {"DC1"}