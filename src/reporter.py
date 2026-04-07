"""
ContextGuard — Rich Terminal Reporter + JSON Export

Produces a structured security assessment report from a TestReport (or a pair
of reports for --compare mode).
"""

from __future__ import annotations

import json
import datetime
from typing import List, Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from .attacks import AttackCategory, Severity
from .tester import AttackResult, TestReport

console = Console()

# ── Colour palette ───────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim yellow",
    "CONTROL":  "dim",
}

GRADE_STYLE = {
    "A+": "bold green",
    "A":  "green",
    "B":  "bold yellow",
    "C":  "yellow",
    "D":  "bold red",
    "F":  "bold red",
}

STATUS_STYLE = {
    "BLOCKED": "bold green",
    "LEAKED":  "bold red",
    "PASS":    "bold green",
    "FAIL":    "bold red",
}

CATEGORY_ABBREV = {
    AttackCategory.DIRECT_ACCESS:       "Direct",
    AttackCategory.PROMPT_INJECTION:    "Injection",
    AttackCategory.ROLE_ESCALATION:     "Escalation",
    AttackCategory.MEMBERSHIP_INFERENCE:"Membership",
    AttackCategory.BROAD_EXTRACTION:    "Extraction",
    AttackCategory.CONTROL:             "Control",
}


# ── Helper renderers ─────────────────────────────────────────────────────────────

def _status_text(label: str) -> Text:
    t = Text(f"  {label}  ", style=STATUS_STYLE.get(label, ""))
    return t


def _results_table(report: TestReport, title: str) -> Table:
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("ID",          width=8,   no_wrap=True)
    table.add_column("Attack",      width=32,  no_wrap=False)
    table.add_column("Category",    width=12,  no_wrap=True)
    table.add_column("Attacker",    width=15,  no_wrap=True)
    table.add_column("Severity",    width=10,  no_wrap=True)
    table.add_column("Result",      width=10,  justify="center", no_wrap=True)
    table.add_column("ms",          width=7,   justify="right",  no_wrap=True)

    for result in report.results:
        atk = result.attack
        table.add_row(
            atk.id,
            atk.name,
            CATEGORY_ABBREV.get(atk.category, atk.category.value),
            atk.attacker_user,
            Text(atk.severity.value, style=SEVERITY_STYLE.get(atk.severity.value, "")),
            _status_text(result.status_label),
            f"{result.elapsed_ms:.1f}",
        )

    return table


def _score_panel(report: TestReport) -> Panel:
    score = report.score
    grade = report.grade
    grade_style = GRADE_STYLE.get(grade, "white")

    lines = [
        f"[bold]Store:[/bold]          {report.store_name}",
        f"[bold]Attacks run:[/bold]    {report.total_attack_count}",
        f"[bold]Blocked:[/bold]        [green]{report.blocked_count}[/green]",
        f"[bold]Leaked:[/bold]         [red]{report.leaked_count}[/red]",
        f"[bold]Weighted score:[/bold] {score:.1f} / 100",
        f"[bold]Grade:[/bold]          [{grade_style}]{grade}[/{grade_style}]",
        f"[bold]Total time:[/bold]     {report.elapsed_total_ms:.1f} ms",
    ]
    return Panel(
        "\n".join(lines),
        title="[bold]Security Summary[/bold]",
        border_style="cyan",
        expand=False,
    )


def _vulnerability_panel(report: TestReport) -> Optional[Panel]:
    leaked = report.leaked_results
    if not leaked:
        return None

    lines = []
    for result in leaked:
        atk = result.attack
        lines.append(f"[bold red]▶ {atk.id} — {atk.name}[/bold red]")
        lines.append(f"  [dim]Category:[/dim]  {atk.category.value}")
        lines.append(f"  [dim]Attacker:[/dim]  {atk.attacker_user}")
        lines.append(f"  [dim]Severity:[/dim]  [{SEVERITY_STYLE.get(atk.severity.value, '')}]{atk.severity.value}[/]")

        lk = result.leakage
        if lk.leaked_doc_ids:
            doc_list = ", ".join(lk.leaked_doc_ids)
            lines.append(f"  [dim]Leaked docs:[/dim] {doc_list}")

        if lk.phrase_hits:
            phrases = "; ".join(f'"{h.phrase}"' for h in lk.phrase_hits[:3])
            lines.append(f"  [dim]Leaked phrases:[/dim] {phrases}")

        if lk.metadata_hits:
            for mh in lk.metadata_hits:
                lines.append(f"  [dim]Metadata leak [{mh.metadata_key}]:[/dim] {mh.leaked_value[:120]}")

        lines.append(f"  [dim]Impact:[/dim]    {atk.impact}")
        lines.append("")

    return Panel(
        "\n".join(lines).rstrip(),
        title="[bold red]⚠  Detected Vulnerabilities[/bold red]",
        border_style="red",
    )


def _recommendations(report: TestReport) -> Optional[Panel]:
    leaked = report.leaked_results
    if not leaked:
        return Panel(
            "[green]✓ All attack vectors blocked. No recommendations required.[/green]",
            title="[bold]Recommendations[/bold]",
            border_style="green",
        )

    cats = {r.attack.category for r in leaked}
    recs = []

    ordered = []
    if AttackCategory.PROMPT_INJECTION in cats:
        ordered.append(
            "[bold]Strip instruction-like text from queries before retrieval.[/bold] "
            "Parse the query as opaque text, not as commands. If an LLM reformulates "
            "the query, sandbox it with a strict system prompt."
        )
    if AttackCategory.ROLE_ESCALATION in cats or AttackCategory.DIRECT_ACCESS in cats:
        ordered.append(
            "[bold]Enforce permissions at ingestion time, not query time.[/bold] "
            "Apply role filters as mandatory vector index pre-filters so restricted "
            "documents are invisible to the retrieval engine, not just filtered post-hoc."
        )
    if AttackCategory.MEMBERSHIP_INFERENCE in cats:
        ordered.append(
            "[bold]Return uniform error responses regardless of match count.[/bold] "
            "Never echo query terms, document titles, or match counts in error messages. "
            "Return an identical generic response whether 0 or 10 docs matched."
        )
    if AttackCategory.BROAD_EXTRACTION in cats:
        ordered.append(
            "[bold]Apply query rate limits and result diversity caps.[/bold] "
            "Restrict how many distinct document IDs a single user can retrieve "
            "in a session to limit corpus enumeration attacks."
        )

    ordered.append(
        "[bold]Run ContextGuard in CI before each deployment.[/bold] "
        "Permission logic is frequently broken by schema changes, new document types, "
        "or retrieval pipeline upgrades. Automated boundary testing catches regressions early."
    )
    recs = [f"{i+1}. {r}" for i, r in enumerate(ordered)]

    return Panel(
        "\n\n".join(recs),
        title="[bold]Recommendations[/bold]",
        border_style="yellow",
    )


# ── Public API ───────────────────────────────────────────────────────────────────

class Reporter:

    def print_report(self, report: TestReport) -> None:
        """Print a full single-store security assessment to the terminal."""
        console.rule("[bold cyan]ContextGuard — Permission Boundary Stress Tester[/bold cyan]")
        console.print(
            f"[dim]Financial context security assessment · "
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n"
        )

        console.print(_results_table(report, title=f"Attack Results — {report.store_name}"))
        console.print()
        console.print(_score_panel(report))
        console.print()

        vuln_panel = _vulnerability_panel(report)
        if vuln_panel:
            console.print(vuln_panel)
            console.print()

        rec_panel = _recommendations(report)
        if rec_panel:
            console.print(rec_panel)

        console.rule()

    def print_compare(self, secure: TestReport, vulnerable: TestReport) -> None:
        """Print a side-by-side comparison of two store implementations."""
        console.rule("[bold cyan]ContextGuard — Secure vs Vulnerable Comparison[/bold cyan]")
        console.print(
            f"[dim]Each column shows results for the same 13 attack vectors "
            f"against two store implementations.[/dim]\n"
        )

        # Merged comparison table
        table = Table(
            title="Attack Vector Results — Secure vs Vulnerable",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("ID",         width=8,  no_wrap=True)
        table.add_column("Attack",     min_width=28)
        table.add_column("Severity",   width=10)
        table.add_column("Secure",     width=10, justify="center")
        table.add_column("Vulnerable", width=12, justify="center")

        for s_result, v_result in zip(secure.results, vulnerable.results):
            atk = s_result.attack
            # Highlight rows where the two stores differ
            row_style = ""
            if s_result.status_label != v_result.status_label:
                row_style = "on dark_red" if "LEAKED" in v_result.status_label else ""

            table.add_row(
                atk.id,
                atk.name,
                Text(atk.severity.value, style=SEVERITY_STYLE.get(atk.severity.value, "")),
                _status_text(s_result.status_label),
                _status_text(v_result.status_label),
                style=row_style,
            )

        console.print(table)
        console.print()

        # Side-by-side score panels
        console.print(Columns([_score_panel(secure), _score_panel(vulnerable)]))
        console.print()

        # Show only the vulnerabilities found in the vulnerable store
        vuln_panel = _vulnerability_panel(vulnerable)
        if vuln_panel:
            console.print(vuln_panel)
            console.print()

        rec_panel = _recommendations(vulnerable)
        if rec_panel:
            console.print(rec_panel)

        console.rule()

    def export_json(self, report: TestReport, path: str) -> None:
        """Export report to a machine-readable JSON file (CI/CD integration)."""
        data = {
            "store": report.store_name,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "score": round(report.score, 2),
            "grade": report.grade,
            "summary": {
                "total_attacks": report.total_attack_count,
                "blocked": report.blocked_count,
                "leaked": report.leaked_count,
                "elapsed_ms": round(report.elapsed_total_ms, 2),
            },
            "results": [
                {
                    "id": r.attack.id,
                    "name": r.attack.name,
                    "category": r.attack.category.value,
                    "severity": r.attack.severity.value,
                    "attacker": r.attack.attacker_user,
                    "status": r.status_label,
                    "elapsed_ms": round(r.elapsed_ms, 2),
                    "leaked_doc_ids": r.leakage.leaked_doc_ids,
                    "phrase_hits": [
                        {"phrase": h.phrase, "in_doc": h.found_in_doc_id}
                        for h in r.leakage.phrase_hits
                    ],
                    "metadata_hits": [
                        {"key": h.metadata_key, "value": h.leaked_value}
                        for h in r.leakage.metadata_hits
                    ],
                }
                for r in report.results
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[dim]Report exported → {path}[/dim]")
