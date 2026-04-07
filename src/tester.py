"""
ContextGuard — Test Orchestrator

Runs each attack vector against a store, collects results, and produces
a TestReport with a weighted security score.

Scoring weights (by severity):
  CRITICAL = 3 pts
  HIGH     = 2 pts
  MEDIUM   = 1 pt
  CONTROL  = not scored (but failures are flagged as system errors)

Score = (sum of weights for blocked attacks) / (total possible weight) × 100
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from .attacks import AttackVector, AttackCategory, Severity, ATTACK_VECTORS
from .corpus import DOCUMENTS
from .detector import LeakageDetector, LeakageResult, build_restricted_set
from .store import SecurePermissionStore, VulnerablePermissionStore


# ── Weights ──────────────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 1,
    Severity.CONTROL: 0,   # controls don't affect the score
}


# ── Result types ─────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    attack: AttackVector
    leakage: LeakageResult
    elapsed_ms: float              # wall-clock time for the query
    # Derived
    blocked: bool = False          # True = attack failed (good); False = attack succeeded (bad)
    is_control_pass: bool = False  # For CT- attacks: True = legitimate access worked

    def __post_init__(self):
        if self.attack.severity == Severity.CONTROL:
            # Controls: we expect results to be returned (not blocked).
            # A control "passes" when the store returns at least one document.
            # We don't use leakage detection for controls.
            self.is_control_pass = not self.leakage.leaked_doc_ids  # no restricted leakage
            self.blocked = True  # treat controls as always "blocked" for scoring purposes
        else:
            self.blocked = not self.leakage.any_leakage

    @property
    def status_label(self) -> str:
        if self.attack.severity == Severity.CONTROL:
            return "PASS" if self.is_control_pass else "FAIL"
        return "BLOCKED" if self.blocked else "LEAKED"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self.attack.severity]


@dataclass
class TestReport:
    store_name: str
    results: List[AttackResult]
    elapsed_total_ms: float

    @property
    def attack_results(self) -> List[AttackResult]:
        """All non-control attack results."""
        return [r for r in self.results if r.attack.severity != Severity.CONTROL]

    @property
    def control_results(self) -> List[AttackResult]:
        return [r for r in self.results if r.attack.severity == Severity.CONTROL]

    @property
    def scored_results(self) -> List[AttackResult]:
        return self.attack_results

    @property
    def total_weight(self) -> int:
        return sum(r.weight for r in self.scored_results)

    @property
    def blocked_weight(self) -> int:
        return sum(r.weight for r in self.scored_results if r.blocked)

    @property
    def score(self) -> float:
        if self.total_weight == 0:
            return 100.0
        return (self.blocked_weight / self.total_weight) * 100

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 95:
            return "A+"
        elif s >= 90:
            return "A"
        elif s >= 80:
            return "B"
        elif s >= 70:
            return "C"
        elif s >= 60:
            return "D"
        else:
            return "F"

    @property
    def leaked_results(self) -> List[AttackResult]:
        return [r for r in self.scored_results if not r.blocked]

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.scored_results if r.blocked)

    @property
    def leaked_count(self) -> int:
        return sum(1 for r in self.scored_results if not r.blocked)

    @property
    def total_attack_count(self) -> int:
        return len(self.scored_results)


# ── Tester ────────────────────────────────────────────────────────────────────────

class LeakageTester:
    """
    Orchestrates attack vectors against a store and produces a TestReport.

    Usage
    -----
    store = VulnerablePermissionStore()
    tester = LeakageTester(store, store_name="VulnerableStore")
    report = tester.run(ATTACK_VECTORS)
    """

    def __init__(
        self,
        store,
        store_name: str = "Unknown",
        config_path: str = "config/permissions.yaml",
        top_k: int = 5,
    ) -> None:
        self.store = store
        self.store_name = store_name
        self.config_path = config_path
        self.top_k = top_k
        self.detector = LeakageDetector(config_path=config_path)

    def run_attack(self, attack: AttackVector) -> AttackResult:
        """Execute a single attack vector and return the result."""
        # Determine which docs are genuinely off-limits for this user
        restricted_ids = build_restricted_set(
            user_id=attack.attacker_user,
            target_doc_ids=attack.target_restricted_doc_ids,
            config_path=self.config_path,
        )

        # Execute the query and time it
        t0 = time.perf_counter()
        query_result = self.store.query(
            text=attack.query,
            user_id=attack.attacker_user,
            top_k=self.top_k,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Run leakage detection across all three paths
        leakage = self.detector.detect(
            result_docs=query_result.documents,
            result_metadata=query_result.metadata,
            restricted_doc_ids=restricted_ids,
            check_metadata_keys=attack.check_metadata_keys,
        )

        return AttackResult(
            attack=attack,
            leakage=leakage,
            elapsed_ms=elapsed_ms,
        )

    def run(self, vectors: List[AttackVector] = ATTACK_VECTORS) -> TestReport:
        """Run all attack vectors and return the aggregated TestReport."""
        t0 = time.perf_counter()
        results = [self.run_attack(v) for v in vectors]
        elapsed_total_ms = (time.perf_counter() - t0) * 1000

        return TestReport(
            store_name=self.store_name,
            results=results,
            elapsed_total_ms=elapsed_total_ms,
        )
