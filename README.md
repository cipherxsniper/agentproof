# agentproof

Cryptographically signed, tamper-evident audit logs for autonomous agents.

As more tools let AI agents run code, call APIs, and modify files
autonomously, there's usually no way to verify — after the fact, or from
outside the agent's own self-report — what it actually did. `agentproof`
gives any agent a way to sign every action it takes into a hash-chained
log, so the record can be independently verified by anyone, without
trusting the agent's own summary of events.

Each log entry is signed with Ed25519 and references the SHA-256 hash of
the entry before it. Editing, deleting, or inserting an entry breaks the
chain in a way `verify()` will always catch.

## Install

```bash
pip install agentproof
```

## Quick start

```python
from agentproof import sign_event, verify_log

sign_event(
    "agent.log",
    "tool_call",
    {"tool": "read_file", "args": {"path": "config.yaml"}},
)

ok, message = verify_log("agent.log")
print(ok, message)  # True, "1 entries verified, chain intact"
```

Or with the class wrapper, if you're signing many events against the
same log and key:

```python
from agentproof import ProofChain

chain = ProofChain("agent.log", signing_key=my_key_bytes)
chain.sign_event("tool_call", {"tool": "run_bash", "cmd": "pytest"})
chain.sign_event("model_decision", {"chose": "retry", "reason": "timeout"})
ok, msg = chain.verify()
```

## Keys

Generate a key:

```bash
agentproof keygen
# AGENTPROOF_SIGNING_KEY=<base64 string>
```

`agentproof` resolves a signing key in this order:

1. `signing_key=` passed directly to a function call (raw bytes or base64 str)
2. `AGENTPROOF_SIGNING_KEY` environment variable (base64) — works on
   platforms with no persistent filesystem (Render, Fly, Lambda, etc.)
3. `keyfile=` passed directly (path to a JSON file: `{"secret": [...]}`
   or a raw JSON array of 32 ints)
4. `AGENTPROOF_KEYFILE` environment variable (path to the same format)

No placeholder key is ever silently substituted — if none of the above
resolve, you get a clear `ProofChainError`.

## Verifying someone else's log

If you didn't sign the log yourself, verify it against the signer's
published public key instead of your own private key:

```python
from agentproof import verify_log
import base64

pubkey = base64.b64decode("their-published-public-key==")
ok, msg = verify_log("their_agent.log", pubkey_bytes=pubkey)
```

Publish your own public key with:

```bash
agentproof pubkey
```

## CLI

```bash
agentproof keygen                          # generate a new key
agentproof verify path/to/agent.log        # verify using your own resolved key
agentproof verify log.jsonl --pubkey B64   # verify against a specific public key
agentproof pubkey                          # print your public key to share
```

## What this doesn't do

`agentproof` proves that a specific key signed a specific sequence of
events, and that the sequence hasn't been altered since. It does **not**
verify that the *content* of an event is true — if an agent lies about
what a tool call returned and then signs that lie, the signature is
still valid. Signing happens at the point your code calls `sign_event`,
so the honesty guarantee is only as strong as what you choose to log and
when.

## License

MIT
