import base64
import json
import threading
from http.client import HTTPConnection

import pytest

import soc_forge.web.app as web_app
from soc_forge.web.app import make_server, warn_if_non_loopback


SCENARIO_EXPECTATIONS = {
    "attack_chain": {"events": 7, "alerts": 14, "correlations": 5, "cases": 6, "hunts": 1},
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
    assert {"summary", "detection_scorecard", "detection_rules", "cases", "alerts", "hunts", "reconstructions"}.issubset(workspace)
    assert workspace["summary"]["alert_count"] == expected["alerts"]
    assert workspace["summary"]["correlated_alert_count"] == expected["correlations"]
    assert workspace["summary"]["case_count"] == expected["cases"]
    assert workspace["summary"]["hunt_count"] == expected["hunts"]
    assert len(workspace["alerts"]) == expected["alerts"]
    assert len(workspace["cases"]) == expected["cases"]
    assert len(workspace["hunts"]) == expected["hunts"]
    assert len(workspace["reconstructions"]) == expected["cases"]
    assert workspace["detection_rules"]
    assert all(rule["rule_id"] for rule in workspace["detection_rules"])


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
    warn_if_non_loopback("0.0.0.0", None)

    captured = capsys.readouterr()
    assert "no authentication" in captured.out
    assert "may expose investigation data" in captured.out


def test_loopback_warning_is_not_printed(capsys):
    warn_if_non_loopback("127.0.0.1", None)
    warn_if_non_loopback("localhost", None)

    captured = capsys.readouterr()
    assert captured.out == ""


def test_non_loopback_warning_is_suppressed_when_auth_token_is_set(capsys):
    warn_if_non_loopback("0.0.0.0", "some-secret-token")

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




def test_empty_api_collections_over_http(web_server):
    for route in ["/api/cases", "/api/alerts", "/api/hunts", "/api/reconstructions"]:
        status, headers, payload = json_request(web_server, "GET", route)

        assert status == 200
        assert headers["Content-Type"].startswith("application/json")
        assert payload == []

    status, headers, scorecard = json_request(web_server, "GET", "/api/detection-scorecard")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert scorecard["enabled_rule_count"] >= 19
    assert scorecard["correlation_alert_count"] == 0
    assert scorecard["demo_signal_count"] == 0


def test_responses_carry_security_headers(web_server):
    status, headers, _payload = json_request(web_server, "GET", "/api/summary")

    assert status == 200
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in headers


def test_auth_token_required_when_configured(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path, auth_token="s3cret")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    server_info = {"host": host, "port": port, "out_dir": tmp_path}
    try:
        status, headers, _body = request(server_info, "GET", "/api/summary")
        assert status == 401
        assert headers["WWW-Authenticate"] == 'Basic realm="SOC-Forge"'

        wrong_credentials = base64.b64encode(b"analyst:wrong").decode("ascii")
        status, _headers, _body = request(
            server_info, "GET", "/api/summary",
            headers={"Authorization": f"Basic {wrong_credentials}"},
        )
        assert status == 401

        correct_credentials = base64.b64encode(b"analyst:s3cret").decode("ascii")
        status, _headers, _payload = json_request(
            server_info, "GET", "/api/summary",
            headers={"Authorization": f"Basic {correct_credentials}"},
        )
        assert status == 200
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_head_requests_return_headers_without_response_body(web_server):
    for route, content_type in [
        ("/", "text/html"),
        ("/index.html", "text/html"),
        ("/api/workspace", "application/json"),
        ("/api/detection-scorecard", "application/json"),
    ]:
        status, headers, body = request(web_server, "HEAD", route)

        assert status == 200
        assert headers["Content-Type"].startswith(content_type)
        assert body == b""

    status, _headers, body = request(web_server, "HEAD", "/artifact?file=report.html")
    assert status == 404
    assert body == b""


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_unsupported_scenario_verbs_over_http(web_server, method):
    status, _headers, body = request(
        web_server,
        method,
        "/api/scenario",
        body=b"{}",
        headers={"Content-Type": "application/json"},
    )

    assert status == 501
    assert body

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


def test_post_ingest_jsonl_file_replaces_workspace_over_http(web_server):
    events = [
        {
            "event_id": 4625,
            "timestamp": "2026-08-28T10:00:00Z",
            "host": "WIN-01",
            "username": "bob",
            "src_ip": "10.0.0.5",
            "message": "An account failed to log on.",
        }
        for _ in range(3)
    ]
    body = "\n".join(json.dumps(event) for event in events).encode("utf-8")

    status, _headers, data = request(
        web_server, "POST", "/api/ingest",
        body=body,
        headers={"X-Filename": "mydata.jsonl"},
    )

    assert status == 200
    payload = json.loads(data.decode("utf-8"))
    assert payload["filename"] == "mydata.jsonl"
    assert payload["workspace"]["generated_event_count"] == 3
    assert payload["workspace"]["active_scenario"] is None
    assert payload["workspace"]["scenario_label"] == "mydata.jsonl"

    saved = web_server["out_dir"] / "uploads" / "mydata.jsonl"
    assert saved.exists()
    assert (web_server["out_dir"] / "alerts.json").exists()

    status, _headers, workspace = json_request(web_server, "GET", "/api/workspace")
    assert status == 200
    assert workspace["summary"]["alert_count"] == 0


@pytest.mark.parametrize(
    "filename,body,expected_status,expected_error_fragment",
    [
        ("data.exe", b"{}", 400, "Unsupported file type"),
        ("", b"{}", 400, "valid filename"),
        ("bad.jsonl", b"{not-json", 400, None),
    ],
)
def test_post_ingest_negative_paths_over_http(web_server, filename, body, expected_status, expected_error_fragment):
    headers = {"X-Filename": filename} if filename else {}
    status, _headers, data = request(web_server, "POST", "/api/ingest", body=body, headers=headers)
    assert status == expected_status
    payload = json.loads(data.decode("utf-8"))
    if expected_error_fragment:
        assert expected_error_fragment in payload["error"]


def test_post_ingest_sanitizes_traversal_filename_over_http(web_server):
    body = json.dumps(
        {"event_id": 4625, "timestamp": "2026-08-28T10:00:00Z", "host": "WIN-01"}
    ).encode("utf-8")

    status, _headers, _data = request(
        web_server, "POST", "/api/ingest",
        body=body,
        headers={"X-Filename": "../../etc/passwd.jsonl"},
    )

    assert status == 200
    saved = list((web_server["out_dir"] / "uploads").iterdir())
    assert [p.name for p in saved] == ["passwd.jsonl"]


def test_post_ingest_rejects_oversized_upload_over_http(web_server, monkeypatch):
    monkeypatch.setattr(web_app, "MAX_UPLOAD_BYTES", 10)

    status, _headers, data = request(
        web_server, "POST", "/api/ingest",
        body=b"x" * 100,
        headers={"X-Filename": "big.jsonl"},
    )

    assert status == 413
    assert b"exceeds the maximum" in data


def test_post_ingest_rejects_unsupported_format_override_over_http(web_server):
    status, _headers, data = request(
        web_server, "POST", "/api/ingest?format=xml",
        body=b"{}",
        headers={"X-Filename": "data.jsonl"},
    )

    assert status == 400
    assert b"Unsupported format override" in data


def test_post_ingest_malformed_evtx_surfaces_diagnostics_over_http(web_server):
    status, _headers, data = request(
        web_server, "POST", "/api/ingest",
        body=b"not a real evtx file",
        headers={"X-Filename": "bad.evtx"},
    )

    assert status == 422
    payload = json.loads(data.decode("utf-8"))
    assert "diagnostics" in payload

    status, _headers, _body = request(web_server, "GET", "/artifact?file=../README.md")
    assert status == 404

    status, _headers, _body = request(web_server, "GET", "/artifact?file=missing.json")
    assert status == 404
