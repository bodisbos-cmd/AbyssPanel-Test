import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_nginx_connection_capacity_is_bounded_and_above_default():
    config = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert "worker_processes 1;" in config
    assert "worker_connections 4096;" in config
    assert "keepalive_timeout 60s;" in config
    assert "keepalive_requests 10000;" in config
    # Each request-based XHTTP inbound gets its own bounded upstream keepalive pool.
    for upstream in (
        "xray_xhttp_auto",
        "xray_xhttp_packet",
        "xray_xhttp_stream_up",
        "xray_xhttp_stream_one",
        "xray_xhttp_stream_up_alt",
        "xray_xhttp_stream_one_alt",
    ):
        assert f"upstream {upstream} {{" in config
        assert "keepalive 16;" in config


def test_nginx_xhttp_routes_use_matching_upstreams():
    config = (ROOT / "nginx" / "default.conf").read_text(encoding="utf-8")
    for route, upstream in (
        ("/xhttp-stream-up-alt", "xray_xhttp_stream_up_alt"),
        ("/xhttp-stream-one-alt", "xray_xhttp_stream_one_alt"),
        ("/xhttp-stream-up", "xray_xhttp_stream_up"),
        ("/xhttp-stream-one", "xray_xhttp_stream_one"),
        ("/xhttp-packet", "xray_xhttp_packet"),
        ("/xhttp", "xray_xhttp_auto"),
    ):
        assert f"location ^~ {route}" in config
        assert f"proxy_pass http://{upstream};" in config
    assert config.count("proxy_request_buffering off;") >= 6
    assert config.count('proxy_set_header Connection "";') >= 6


def test_railway_restarts_failed_or_stopped_service_and_waits_for_health():
    config = json.loads((ROOT / "railway.json").read_text(encoding="utf-8"))
    assert config["deploy"]["healthcheckPath"] == "/health"
    assert config["deploy"]["healthcheckTimeout"] == 300
    assert config["deploy"]["restartPolicyType"] == "ALWAYS"
