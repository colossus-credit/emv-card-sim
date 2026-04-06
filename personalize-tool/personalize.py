#!/usr/bin/env python3
"""EMV Card Personalization Tool — CLI entry point.

Replaces the 1664-line personalize.sh with a declarative YAML profile system.

Usage:
    python personalize.py --profile profiles/default.yaml [--dry-run] [--reader "..."]
    python personalize.py --profile profiles/default.yaml --gen-keys
    python personalize.py --profile profiles/default.yaml --pan 6690750012345678
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import yaml

from emv_personalize.apdu import DryRunTransport, PcscTransport
from emv_personalize.card import (
    Card, personalize_payment_app, personalize_pse, personalize_ppse,
)
from emv_personalize.crypto import CertificateHierarchy
from emv_personalize.luhn import luhn_validate, generate_pan

log = logging.getLogger("personalize")


def load_profile(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def resolve_keys(
    profile: dict, *, pan: str, expiry: str, keys_dir: str | None, gen_keys: bool,
) -> CertificateHierarchy:
    """Load existing keys or generate new ones."""
    keys_cfg = profile.get("keys", {})
    capk_index = keys_cfg.get("capk_index", "92")
    key_size = keys_cfg.get("key_size", 1984)

    if keys_dir and os.path.exists(os.path.join(keys_dir, "capk", "capk_private.pem")):
        log.info("Loading existing keys from %s", keys_dir)
        return CertificateHierarchy.from_keys_dir(
            keys_dir, pan=pan, expiry=expiry, capk_index=capk_index,
        )

    if gen_keys or keys_dir is None:
        log.info("Generating new certificate hierarchy (RSA-%d)...", key_size)
        certs = CertificateHierarchy.generate(
            pan=pan, expiry=expiry, key_size=key_size, capk_index=capk_index,
        )
        if keys_dir:
            log.info("Saving keys to %s", keys_dir)
            certs.save_to_dir(keys_dir)
        return certs

    raise FileNotFoundError(
        f"Keys directory '{keys_dir}' does not contain expected key files. "
        "Use --gen-keys to generate new keys."
    )


def run_personalization(
    profile: dict, transport, *,
    pan: str, expiry: str, keys_dir: str | None, gen_keys: bool,
    use_store_data: bool = False,
) -> None:
    """Execute full personalization from a profile."""
    card = Card(transport, use_store_data=use_store_data)

    label = profile.get("application_label", "COLOSSUS")
    preferred_name = profile.get("preferred_name", label)
    rid = profile.get("rid", "A000000951")
    contact_aid = rid + profile.get("contact_aid_suffix", "0001")
    contactless_aid = rid + profile.get("contactless_aid_suffix", "1010")

    certs = resolve_keys(
        profile, pan=pan, expiry=expiry,
        keys_dir=keys_dir, gen_keys=gen_keys,
    )

    # 1. PSE (contact directory)
    log.info("=== Personalizing PSE ===")
    personalize_pse(card, contact_aid=contact_aid, label=label)

    # 2. PPSE (contactless directory)
    log.info("=== Personalizing PPSE ===")
    personalize_ppse(card, contactless_aid=contactless_aid, label=label,
                     preferred_name=preferred_name)

    # 3. Contact payment app
    log.info("=== Personalizing Contact Payment App (AID: %s) ===", contact_aid)
    personalize_payment_app(
        card, aid=contact_aid, profile=profile,
        pan=pan, expiry_yymmdd=expiry, certs=certs,
        contactless=False,
    )

    # 4. Contactless payment app — adds PDOL, preferred name, different FCI
    log.info("=== Personalizing Contactless Payment App (AID: %s) ===", contactless_aid)
    personalize_payment_app(
        card, aid=contactless_aid, profile=profile,
        pan=pan, expiry_yymmdd=expiry, certs=certs,
        contactless=True,
    )

    log.info("=== Personalization complete ===")
    log.info("  PAN:              %s", pan)
    log.info("  Expiry:           %s", expiry)
    log.info("  Label:            %s", label)
    log.info("  Contact AID:      %s", contact_aid)
    log.info("  Contactless AID:  %s", contactless_aid)


def main():
    parser = argparse.ArgumentParser(
        description="EMV Card Personalization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python personalize.py -p profiles/default.yaml --dry-run --gen-keys
  python personalize.py -p profiles/default.yaml --reader "Identiv"
  python personalize.py -p profiles/default.yaml --pan 6690750012345678 --dry-run
""",
    )
    parser.add_argument("--profile", "-p", required=True, help="YAML profile path")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Print APDUs without sending to card")
    parser.add_argument("--reader", "-r", help="Smart card reader name (substring match)")
    parser.add_argument("--pan", help="Override PAN (16 digits, must pass Luhn)")
    parser.add_argument("--bin", help="BIN prefix to generate PAN")
    parser.add_argument("--expiry", help="Card expiry YYMMDD (default: from profile)")
    parser.add_argument("--label", help="Override application label")
    parser.add_argument("--keys-dir", help="Path to keys/ directory")
    parser.add_argument("--gen-keys", action="store_true",
                        help="Generate new certificate hierarchy")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--store-data", action="store_true",
                        help="Use CPS v2.0 STORE DATA (INS E2) instead of custom dev commands")
    parser.add_argument("--gp-jar-format", action="store_true",
                        help="In dry-run, output as gp.jar -a arguments")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    profile = load_profile(args.profile)

    # Resolve PAN
    bin_prefix = args.bin or profile.get("bin", "66907500")
    if args.pan:
        if not luhn_validate(args.pan):
            log.error("PAN %s fails Luhn check", args.pan)
            sys.exit(1)
        pan = args.pan
    else:
        pan = profile.get("pan") or generate_pan(bin_prefix)
        log.info("Using PAN: %s", pan)

    expiry = args.expiry or profile.get("expiry", "271231")
    if args.label:
        profile["application_label"] = args.label

    keys_dir = args.keys_dir or profile.get("keys", {}).get("keys_dir")

    if args.dry_run:
        transport = DryRunTransport(verbose=True)
        log.info("=== DRY RUN MODE ===")
    else:
        reader = args.reader or profile.get("reader")
        transport = PcscTransport(reader_name=reader)

    transport.connect()
    try:
        run_personalization(
            profile, transport, pan=pan, expiry=expiry,
            keys_dir=keys_dir, gen_keys=args.gen_keys,
            use_store_data=args.store_data,
        )
    finally:
        if args.dry_run and args.gp_jar_format:
            assert isinstance(transport, DryRunTransport)
            print("\n=== gp.jar command ===")
            print(f"java -jar gp.jar -d {transport.to_gp_args()}")
        transport.disconnect()


if __name__ == "__main__":
    main()
