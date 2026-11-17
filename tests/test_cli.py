import json
from unittest import mock

from fetch_nvd import cli


def _response(payload):
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def test_main_uses_named_parameters_and_paginates(tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text("secret\n")
    out_dir = tmp_path / "out"
    ts_file = tmp_path / "state" / "ts.txt"
    log_file = tmp_path / "logs" / "run.log"

    pages = [
        _response({"totalResults": 3, "vulnerabilities": [{"id": 1}, {"id": 2}]}),
        _response({"totalResults": 3, "vulnerabilities": [{"id": 3}]}),
    ]
    with mock.patch.object(cli.requests, "get", side_effect=pages) as get, \
            mock.patch.object(cli.time, "sleep"):
        rc = cli.main([
            "--api-key-file", str(key_file),
            "--output-dir", str(out_dir),
            "--timestamp-file", str(ts_file),
            "--nvd-api-url", "https://example.test/api",
            "--log", str(log_file),
        ])

    assert rc == 0
    assert get.call_args.args[0] == "https://example.test/api"
    assert get.call_args.kwargs["headers"] == {"apiKey": "secret"}
    files = list(out_dir.glob("cve_delta_*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text(encoding="utf-8"))
    assert data["export_metadata"]["total_records"] == 3
    assert ts_file.read_text() == data["export_metadata"]["end_time"]
    log_text = log_file.read_text(encoding="utf-8")
    assert "Successfully generated delta file" in log_text
    assert "Run finished: success" in log_text
    assert "secret" not in log_text


def test_failure_does_not_update_timestamp(tmp_path):
    ts_file = tmp_path / "ts.txt"
    ts_file.write_text("2026-01-01T00:00:00.000")
    with mock.patch.object(cli.requests, "get", side_effect=cli.requests.exceptions.ConnectionError("boom")):
        ok = cli.fetch_nvd_delta(timestamp_file=str(ts_file), output_dir=str(tmp_path / "out"))

    assert ok is False
    assert ts_file.read_text() == "2026-01-01T00:00:00.000"


def test_placeholder_api_key_is_ignored(tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(cli.PLACEHOLDER_API_KEY)
    assert cli.read_api_key(str(key_file)) is None
    assert cli.read_api_key(str(tmp_path / "missing.txt")) is None
