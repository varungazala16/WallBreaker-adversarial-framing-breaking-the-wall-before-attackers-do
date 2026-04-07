#!/usr/bin/env python3
"""
ContextGuard — Permission Boundary Stress Tester for Financial RAG Systems

Usage
-----
  python demo.py                   # test the vulnerable store (default)
  python demo.py --secure          # test the secure reference implementation
  python demo.py --compare         # side-by-side: secure vs vulnerable
  python demo.py --output out.json # also export machine-readable JSON report
"""

import argparse
import sys

from src.attacks import ATTACK_VECTORS
from src.store import SecurePermissionStore, VulnerablePermissionStore
from src.tester import LeakageTester
from src.reporter import Reporter


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ContextGuard — Permission boundary stress tester for financial RAG systems.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Test the secure reference implementation (all attacks should be blocked).",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run attacks against both stores and show a side-by-side comparison.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Export the report as JSON to FILE (for CI/CD integration).",
    )
    args = parser.parse_args()

    reporter = Reporter()

    if args.compare:
        # ── Compare mode: run both stores ────────────────────────────────────────
        secure_store = SecurePermissionStore()
        vuln_store   = VulnerablePermissionStore()

        secure_tester = LeakageTester(secure_store, store_name="SecurePermissionStore")
        vuln_tester   = LeakageTester(vuln_store,   store_name="VulnerablePermissionStore")

        secure_report = secure_tester.run(ATTACK_VECTORS)
        vuln_report   = vuln_tester.run(ATTACK_VECTORS)

        reporter.print_compare(secure_report, vuln_report)

        if args.output:
            # Export the vulnerable store report (the one with findings)
            reporter.export_json(vuln_report, args.output)

        return 0 if vuln_report.leaked_count == 0 else 1

    elif args.secure:
        # ── Secure mode ──────────────────────────────────────────────────────────
        store  = SecurePermissionStore()
        tester = LeakageTester(store, store_name="SecurePermissionStore")
        report = tester.run(ATTACK_VECTORS)
        reporter.print_report(report)

    else:
        # ── Default: vulnerable store ─────────────────────────────────────────────
        store  = VulnerablePermissionStore()
        tester = LeakageTester(store, store_name="VulnerablePermissionStore")
        report = tester.run(ATTACK_VECTORS)
        reporter.print_report(report)

    if args.output:
        reporter.export_json(report, args.output)

    return 0 if report.leaked_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
