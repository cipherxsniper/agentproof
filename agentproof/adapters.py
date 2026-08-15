"""
agentproof.adapters -- framework adapters that wrap tool/function calls
and emit signed agentproof events recording what was called, what was
sent, and what came back, without agentproof depending on any specific
agent framework.

Same caveat as agentproof.core throughout: this proves an agent called
a tool with a given request and received a given response. It does NOT
prove the response was true, or that the tool did what its name claims
-- if a tool lies and the agent signs that lie, the signature is still
valid. That's a fundamental limit of signing, not a bug here.
"""

import functools
import hashlib
import json
from typing import Any, Callable, Optional, Union
from pathlib import Path

from .core import sign_event, ProofChainError


def _hash_json(obj: Any) -> str:
    """Deterministic SHA-256 hash of a JSON-serializable object (or its
    repr(), if it isn't one)."""
    try:
        msg = json.dumps(obj, sort_keys=True, default=str).encode()
    except (TypeError, ValueError):
        msg = repr(obj).encode()
    return hashlib.sha256(msg).hexdigest()


def wrap_tool_call(
    log_path: Union[str, Path],
    signing_key=None,
    keyfile=None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
):
    """
    Decorator factory: wraps a Python function so every call is signed
    and appended to log_path as a "tool_call" event, recording the tool
    name, a hash of (args, kwargs), a hash of the return value, and
    whether it succeeded or raised -- the exception type/message is
    recorded on failure too, so failed calls are auditable, not just
    successful ones.

    Raw arguments and return values are hashed, not stored verbatim --
    the log is meant to be shareable for verification without also
    leaking whatever was in the call.

        @wrap_tool_call("agent_run.log", signing_key=my_key)
        def read_file(path):
            return open(path).read()
    """
    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            request_hash = _hash_json({"args": args, "kwargs": kwargs})
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                sign_event(
                    log_path, "tool_call",
                    {
                        "tool": fn.__name__,
                        "request_hash": request_hash,
                        "status": "error",
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                    signing_key=signing_key, keyfile=keyfile,
                    env_var=env_var, keyfile_env_var=keyfile_env_var,
                )
                raise
            sign_event(
                log_path, "tool_call",
                {
                    "tool": fn.__name__,
                    "request_hash": request_hash,
                    "response_hash": _hash_json(result),
                    "status": "ok",
                },
                signing_key=signing_key, keyfile=keyfile,
                env_var=env_var, keyfile_env_var=keyfile_env_var,
            )
            return result
        return wrapper
    return decorator


def record_openai_tool_call(
    log_path: Union[str, Path],
    tool_call: dict,
    result: Any,
    signing_key=None,
    keyfile=None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> dict:
    """
    Record one OpenAI-style function/tool call.

    tool_call is expected to look like what the OpenAI API returns in
    message.tool_calls[i]:
        {"id": "...", "type": "function",
         "function": {"name": "...", "arguments": "<json string>"}}

    result is whatever your tool execution produced (will be hashed,
    not stored raw). Returns the signed entry.
    """
    fn = tool_call.get("function", {})
    name = fn.get("name", "<unknown>")
    try:
        parsed_args = json.loads(fn.get("arguments", "{}"))
    except json.JSONDecodeError:
        parsed_args = fn.get("arguments")

    return sign_event(
        log_path, "openai_tool_call",
        {
            "tool_call_id": tool_call.get("id"),
            "tool": name,
            "request_hash": _hash_json(parsed_args),
            "response_hash": _hash_json(result),
            "status": "ok",
        },
        signing_key=signing_key, keyfile=keyfile,
        env_var=env_var, keyfile_env_var=keyfile_env_var,
    )


def record_http_call(
    log_path: Union[str, Path],
    method: str,
    url: str,
    status_code: Optional[int],
    request_body: Any = None,
    response_body: Any = None,
    signing_key=None,
    keyfile=None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> dict:
    """
    Record one outbound HTTP call an agent made. Framework-agnostic --
    pass whatever your HTTP client gave you (requests.Response,
    urllib, httpx, etc.) already pulled apart into these plain values.

    URL is stored verbatim (useful for audit review), but bodies are
    hashed, not stored -- request/response payloads often carry
    credentials or PII that shouldn't end up in a shareable log.
    """
    return sign_event(
        log_path, "http_call",
        {
            "method": method.upper(),
            "url": url,
            "status_code": status_code,
            "request_hash": _hash_json(request_body) if request_body is not None else None,
            "response_hash": _hash_json(response_body) if response_body is not None else None,
        },
        signing_key=signing_key, keyfile=keyfile,
        env_var=env_var, keyfile_env_var=keyfile_env_var,
    )
