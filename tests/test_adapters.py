import json
import pytest

from agentproof import generate_key, verify_log
from agentproof.adapters import wrap_tool_call, record_openai_tool_call, record_http_call


@pytest.fixture
def key():
    raw, b64 = generate_key()
    return raw, b64


def test_wrap_tool_call_records_success(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    @wrap_tool_call(log, signing_key=raw)
    def add(a, b):
        return a + b

    result = add(2, 3)
    assert result == 5

    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["type"] == "tool_call"
    assert entry["data"]["tool"] == "add"
    assert entry["data"]["status"] == "ok"

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True


def test_wrap_tool_call_records_failure_and_reraises(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    @wrap_tool_call(log, signing_key=raw)
    def divide(a, b):
        return a / b

    with pytest.raises(ZeroDivisionError):
        divide(1, 0)

    entry = json.loads(log.read_text().strip())
    assert entry["data"]["status"] == "error"
    assert entry["data"]["error_type"] == "ZeroDivisionError"

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True  # a recorded failure is still a validly signed log


def test_wrap_tool_call_hashes_args_not_raw(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    @wrap_tool_call(log, signing_key=raw)
    def take_secret(password):
        return "ok"

    take_secret("hunter2")

    raw_log_text = log.read_text()
    assert "hunter2" not in raw_log_text  # the raw arg must never appear


def test_wrap_tool_call_multiple_calls_chain_correctly(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    @wrap_tool_call(log, signing_key=raw)
    def step(i):
        return i * 2

    for i in range(4):
        step(i)

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True
    assert "4 entries verified" in msg


def test_record_openai_tool_call(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    tool_call = {
        "id": "call_abc123",
        "type": "function",
        "function": {"name": "get_weather", "arguments": '{"city": "Chicago"}'},
    }
    entry = record_openai_tool_call(log, tool_call, {"temp_f": 72}, signing_key=raw)

    assert entry["data"]["tool"] == "get_weather"
    assert entry["data"]["tool_call_id"] == "call_abc123"

    raw_log_text = log.read_text()
    assert "Chicago" not in raw_log_text  # args must be hashed, not raw

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True


def test_record_openai_tool_call_handles_malformed_arguments(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    tool_call = {
        "id": "call_bad",
        "function": {"name": "broken_tool", "arguments": "not valid json{{"},
    }
    # must not raise -- malformed arguments from the model itself are a
    # real thing that happens and still need to be auditable
    entry = record_openai_tool_call(log, tool_call, None, signing_key=raw)
    assert entry["data"]["tool"] == "broken_tool"


def test_record_http_call(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    entry = record_http_call(
        log, "POST", "https://api.example.com/payments",
        status_code=200,
        request_body={"amount": 100, "card": "4111111111111111"},
        response_body={"id": "pay_123", "status": "succeeded"},
        signing_key=raw,
    )

    assert entry["data"]["method"] == "POST"
    assert entry["data"]["url"] == "https://api.example.com/payments"
    assert entry["data"]["status_code"] == 200

    raw_log_text = log.read_text()
    assert "4111111111111111" not in raw_log_text  # card number must never appear raw

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True


def test_record_http_call_no_body(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"

    entry = record_http_call(log, "GET", "https://api.example.com/health",
                              status_code=200, signing_key=raw)
    assert entry["data"]["request_hash"] is None
    assert entry["data"]["response_hash"] is None
