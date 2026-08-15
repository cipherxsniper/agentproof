"""
agentproof CLI.

Usage:
    agentproof keygen
    agentproof verify <log_path> [--pubkey BASE64] [--history]
    agentproof pubkey
    agentproof rotate <old_log_path> <new_log_path> [--old-pubkey-check BASE64]
"""

import argparse
import sys

from .core import (
    ProofChainError,
    export_public_key,
    generate_key,
    rotate_key,
    verify_chain_history,
    verify_log,
)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentproof")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="Generate a new Ed25519 signing key")

    p_verify = sub.add_parser("verify", help="Verify a signed log's hash chain and signatures")
    p_verify.add_argument("log_path")
    p_verify.add_argument(
        "--pubkey",
        default=None,
        help="Base64 public key to verify against (omit to use the resolved private key's public half)",
    )
    p_verify.add_argument(
        "--history",
        action="store_true",
        help="Also walk and verify any linked prior segments from key rotation (see 'rotate'). "
             "Without this flag, verify only checks the given log as a standalone segment.",
    )

    sub.add_parser("pubkey", help="Print the base64 public key for the resolved signing key")

    p_rotate = sub.add_parser(
        "rotate",
        help="Close an old chain segment and start a new one under a freshly generated key, "
             "linked back to the old segment's final hash",
    )
    p_rotate.add_argument("old_log_path", help="Path to the existing log signed under the key being retired")
    p_rotate.add_argument("new_log_path", help="Path for the new log; must not already exist")

    args = parser.parse_args(argv)

    if args.command == "keygen":
        raw, b64 = generate_key()
        print("New Ed25519 key generated.")
        print(f"AGENTPROOF_SIGNING_KEY={b64}")
        print("\nStore this somewhere safe (env var or secrets manager).")
        print("It will never be printed again.")
        return 0

    if args.command == "verify":
        pubkey_bytes = None
        if args.pubkey:
            import base64
            pubkey_bytes = base64.b64decode(args.pubkey)
        try:
            if args.history:
                ok, msg = verify_chain_history(args.log_path, pubkey_bytes=pubkey_bytes)
            else:
                ok, msg = verify_log(args.log_path, pubkey_bytes=pubkey_bytes)
        except ProofChainError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1

    if args.command == "pubkey":
        try:
            print(export_public_key())
        except ProofChainError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        return 0

    if args.command == "rotate":
        try:
            new_raw, new_b64 = generate_key()
            entry = rotate_key(
                args.old_log_path,
                args.new_log_path,
                new_signing_key=new_raw,
            )
        except ProofChainError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        print(f"Rotated. New chain segment started at {args.new_log_path}")
        print(f"Linked to prior segment final hash: {entry['data']['prev_chain_final_hash']}")
        print(f"\nAGENTPROOF_SIGNING_KEY={new_b64}")
        print("Store this somewhere safe. The OLD key is no longer needed for signing new events,")
        print("but keep it available if you need to verify the old segment standalone.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
