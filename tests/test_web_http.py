import json
import threading
from http.client import HTTPConnection

import pytest

import soc_forge.web.app as web_app
from soc_forge.web.app import make_server, warn_if_non_loopback


SCENARIO_EXPECTATIONS = {
    "attack_chain": {"events": 5, "alerts": 10, "correlations": 4, "cases": 5, "hunts": 1},
    "detection_lab": {"events": 6, "alerts": 8, "correlations": 3, "cases": 3, "hunts": 1},
}


@pytest.fixture
def web_server(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield {"host": host, "port": port, "out_dir": tmp_path}
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def request(server_info, method, path, body=None, headers=None):
    conn = HTTPConnection(server_info["host"], server_info["port"], timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data
    finally:
        conn.close()


def json_request(server_info, method, path, payload=None, raw_body=None, headers=None):
    if raw_body is not None:
        body = raw_body
    elif payload is not None:
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    status, response_headers, data = request(server_info, method, path, body=body, headers=request_headers)
    parsed = json.loads(data.decode("utf-8")) if data else None
    return status, response_headers, parsed


def assert_workspace_shape(workspace, expected):
    assert {"summary", "detection_scorecard", "cases", "alerts", "hunts", "reconstructions"}.issubset(workspace)
    assert workspace["summary"]["alert_count"] == expected["alerts"]
    assert workspace["summary"]["correlated_alert_count"] == expected["correlations"]
    assert workspace["summary"]["case_count"] == expected["cases"]
    assert workspace["summary"]["hunt_count"] == expected["hunts"]
    assert len(workspace["alerts"]) == expected["alerts"]
    assert len(workspace["cases"]) == expected["cases"]
    assert len(workspace["hunts"]) == expected["hunts"]
    assert len(workspace["reconstructions"]) == expected["cases"]


@pytest.mark.parametrize("scenario,expected", sorted(SCENARIO_EXPECTATIONS.items()))
def test_post_scenario_then_get_workspace_and_scorecard_over_http(web_server, scenario, expected):
    status, headers, payload = json_request(web_server, "POST", "/api/scenario", {"scenario": scenario})

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert payload["scenario"] == scenario
    assert payload["workspace"]["active_scenario"] == scenario
    assert payload["workspace"]["generated_event_count"] == expected["events"]
    assert_workspace_shape(payload["workspace"], expected)

    status, headers, workspace = json_request(web_server, "GET", "/api/workspace")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert_workspace_shape(workspace, expected)

    status, headers, scorecard = json_request(web_server, "GET", "/api/detection-scorecard")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert scorecard["quality_gate"] is True
    assert scorecard["enabled_rule_count"] >= 19
    assert scorecard["correlation_alert_count"] == expected["correlations"]

    for filename, content_type in [
        ("report.html", "text/html"),
        ("alerts.json", "application/json"),
        ("cases.json", "application/json"),
        ("hunts.json", "application/json"),
        ("reconstructions.json", "application/json"),
    ]:
        status, headers, body = request(web_server, "GET", f"/artifact?file={filename}")
        assert status == 200
        assert headers["Content-Type"].startswith(content_type)
        assert body


def test_workspace_over_http_is_empty_without_existing_artifacts(web_server):
    status, headers, workspace = json_request(web_server, "GET", "/api/workspace")

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert workspace["summary"]["alert_count"] == 0
    assert workspace["summary"]["case_count"] == 0
    assert workspace["alerts"] == []
    assert workspace["cases"] == []
    assert workspace["hunts"] == []
    assert workspace["reconstructions"] == []


@pytest.mark.parametrize(
    "body,expected_error_fragment",
    [
        (json.dumps({"scenario": "not-a-scenario"}).encode("utf-8"), "Invalid scenario"),
        (b"{not-json", "Invalid JSON request body"),
        (None, "Invalid scenario"),
    ],
)
def test_post_scenario_negative_paths_over_http(web_server, body, expected_error_fragment):
    status, headers, payload = json_request(web_server, "POST", "/api/scenario", raw_body=body)

    assert status == 400
    assert headers["Content-Type"].startswith("application/json")
    assert expected_error_fragment in payload["error"]


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
    ],
)
def test_post_scenario_rejects_missing_or_unsupported_content_type(web_server, headers):
    status, response_headers, data = request(
        web_server,
        "POST",
        "/api/scenario",
        body=json.dumps({"scenario": "detection_lab"}).encode("utf-8"),
        headers=headers,
    )
    payload = json.loads(data.decode("utf-8"))

    assert status == 415
    assert response_headers["Content-Type"].startswith("application/json")
    assert payload == {"error": "Content-Type must be application/json"}


def test_malformed_json_error_is_generic_but_diagnostic_is_local(web_server, capsys):
    status, _headers, payload = json_request(web_server, "POST", "/api/scenario", raw_body=b"{not-json")

    assert status == 400
    assert payload == {"error": "Invalid JSON request body"}
    assert "Expecting property name" not in json.dumps(payload)
    captured = capsys.readouterr()
    assert "Invalid JSON for /api/scenario" in captured.out
    assert "Expecting property name" in captured.out


def test_non_loopback_warning_is_printed_without_binding_externally(capsys):
    warn_if_non_loopback("0.0.0.0")

    captured = capsys.readouterr()
    assert "no authentication" in captured.out
    assert "may expose investigation data" in captured.out


def test_loopback_warning_is_not_printed(capsys):
    warn_if_non_loopback("127.0.0.1")
    warn_if_non_loopback("localhost")

    captured = capsys.readouterr()
    assert captured.out == ""


def test_internal_scenario_exception_is_generic_to_client(tmp_path, monkeypatch, capsys):
    def broken_scenario(_scenario, _out_dir):
        raise RuntimeError("secret filesystem detail /tmp/private-case")

    monkeypatch.setattr(web_app, "run_demo_scenario", broken_scenario)
    server = make_server("127.0.0.1", 0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status, _headers, payload = json_request(
            {"host": host, "port": port, "out_dir": tmp_path},
            "POST",
            "/api/scenario",
            {"scenario": "detection_lab"},
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert status == 500
    assert payload == {"error": "Unable to run scenario"}
    assert "secret filesystem detail" not in json.dumps(payload)
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.out
    assert "secret filesystem detail /tmp/private-case" in captured.out


def test_unsupported_methods_and_missing_routes_over_http(web_server):
    status, _headers, _body = request(web_server, "GET", "/api/does-not-exist")
    assert status == 404

    status, _headers, _body = request(web_server, "POST", "/api/workspace", body=b"{}", headers={"Content-Type": "application/json"})
    assert status == 404

    status, _headers, _body = request(web_server, "PUT", "/api/scenario", body=b"{}", headers={"Content-Type": "application/json"})
    assert status == 501


def test_artifact_negative_paths_over_http(web_server):
    status, _headers, _body = request(web_server, "GET", "/artifact?file=report.html")
    assert status == 404

    status, _headers, _body = request(web_server, "GET", "/artifact?file=../README.md")
    assert status == 404

    status, _headers, _body = request(web_server, "GET", "/artifact?file=missing.json")
    assert status == 404