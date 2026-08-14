"""
agentproof CLI.

Usage:
    agentproof keygen
    agentproof verify <log_path> [--pubkey BASE64]
    agentproof pubkey
"""

import argparse
import sys

from .core import ProofChainError, export_public_key, generate_key, verify_log


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

    sub.add_parser("pubkey", help="Print the base64 public key for the resolved signing key")

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


if __name__ == "__main__":
    sys.exit(main())
