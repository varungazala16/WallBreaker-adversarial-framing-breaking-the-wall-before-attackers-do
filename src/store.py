"""
ContextGuard — Permission-Aware Document Stores

This module intentionally provides TWO implementations:

  SecurePermissionStore   — correct implementation (pre-filter, then rank)
  VulnerablePermissionStore — intentionally broken implementation with two
                              real-world vulnerability classes:

    Bug 1 | Authentication Bypass (CWE-287)
      If the query string contains the word "admin", the permission check is
      skipped entirely. This mirrors systems that naively trust user-supplied
      metadata embedded in a query payload.

    Bug 2 | Information Disclosure via Error Messages (CWE-209)
      When a query matches a restricted document that the user cannot access,
      the error response echoes the document title — confirming the document's
      existence (membership inference).

The architectural root cause of both bugs is a TOCTOU (Time-of-Check to
Time-of-Use) pattern: the VulnerableStore ranks ALL documents first, then
applies permissions as a post-processing filter. The SecureStore applies
permissions BEFORE any content is examined.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

import yaml

from .corpus import Document, DOCUMENTS


# ── Shared types ────────────────────────────────────────────────────────────────

@dataclass
class QueryResult:
    """The response object returned by both store implementations."""
    documents: List[Document] = field(default_factory=list)
    # Metadata that may reveal information even when documents is empty
    metadata: dict = field(default_factory=dict)


def _load_permissions(config_path: str = "config/permissions.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)["users"]


def _get_user_roles(user_id: str, permissions: dict) -> Set[str]:
    if user_id not in permissions:
        return set()
    return set(permissions[user_id]["roles"])


def _tokenize(text: str) -> List[str]:
    """Lowercase, strip punctuation, split on whitespace."""
    return re.sub(r"[^\w\s]", " ", text.lower()).split()


def _rank_documents(query: str, docs: List[Document]) -> List[Document]:
    """Rank documents by keyword overlap with the query (descending)."""
    tokens = _tokenize(query)
    scored = [(doc, doc.keyword_score(tokens)) for doc in docs]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [doc for doc, score in scored if score > 0] or docs  # fallback: return all if no overlap


# ── Secure implementation ────────────────────────────────────────────────────────

class SecurePermissionStore:
    """
    Correct implementation.

    Retrieval pipeline:
      1. Resolve user roles from permissions config.
      2. Filter corpus to documents accessible to this user  ← permission check FIRST
      3. Rank filtered documents by relevance to query.
      4. Return top_k results.

    Error responses contain no information about restricted documents.
    """

    def __init__(
        self,
        documents: List[Document] = DOCUMENTS,
        config_path: str = "config/permissions.yaml",
    ) -> None:
        self.documents = documents
        self.permissions = _load_permissions(config_path)

    def query(self, text: str, user_id: str, top_k: int = 5) -> QueryResult:
        user_roles = _get_user_roles(user_id, self.permissions)

        # Step 1: Filter BEFORE ranking — user never touches restricted content
        accessible = [doc for doc in self.documents if doc.is_accessible_by(user_roles)]

        # Step 2: Rank accessible documents by relevance
        ranked = _rank_documents(text, accessible)

        return QueryResult(
            documents=ranked[:top_k],
            metadata={"result_count": len(ranked[:top_k])},
        )


# ── Vulnerable implementation ────────────────────────────────────────────────────

class VulnerablePermissionStore:
    """
    Intentionally broken implementation — DO NOT use in production.

    Contains two deliberate vulnerability classes to enable ContextGuard testing:

    Bug 1 — Authentication Bypass (triggered by "admin" in query):
      The permission filter is skipped entirely when the query contains the
      word "admin". This simulates a naive system that parses user-supplied
      strings to infer access level.

    Bug 2 — Membership Inference via Error Messages:
      When the highest-ranked document is restricted, the error response
      includes the document title. A caller learns the document exists even
      though they cannot read it.

    Root cause: ranking happens BEFORE permission filtering (post-filter pattern),
    so the system must examine restricted documents to know they match the query.
    """

    def __init__(
        self,
        documents: List[Document] = DOCUMENTS,
        config_path: str = "config/permissions.yaml",
    ) -> None:
        self.documents = documents
        self.permissions = _load_permissions(config_path)

    def query(self, text: str, user_id: str, top_k: int = 5) -> QueryResult:
        user_roles = _get_user_roles(user_id, self.permissions)

        # ── BUG 1: Authentication Bypass ────────────────────────────────────────
        # If the query contains "admin", skip the permission check entirely.
        query_lower = text.lower()
        if "admin" in query_lower.split() or "admin:" in query_lower:
            # Return ALL documents, ranked by relevance — permission boundary destroyed
            ranked_all = _rank_documents(text, self.documents)
            return QueryResult(
                documents=ranked_all[:top_k],
                metadata={
                    "result_count": len(ranked_all[:top_k]),
                    "permission_check_skipped": True,   # bug indicator for detector
                },
            )

        # Step 1: Rank ALL documents (restricted included) — TOCTOU starts here
        ranked_all = _rank_documents(text, self.documents)

        # Step 2: Split into accessible vs restricted
        accessible = [doc for doc in ranked_all if doc.is_accessible_by(user_roles)]
        restricted_matches = [doc for doc in ranked_all if not doc.is_accessible_by(user_roles)]

        # ── BUG 2: Membership Inference via Error Message ────────────────────────
        # If the top match is a restricted document, leak its title in metadata.
        leaked_titles: List[str] = []
        if restricted_matches and (
            not accessible or ranked_all[0] not in accessible
        ):
            top_restricted = restricted_matches[0]
            leaked_titles.append(top_restricted.title)

        return QueryResult(
            documents=accessible[:top_k],
            metadata={
                "result_count": len(accessible[:top_k]),
                # BUG: This message leaks existence of restricted documents
                "info": (
                    f"Note: {len(restricted_matches)} document(s) matched your query "
                    f"but are outside your permission scope: "
                    + (f'"{leaked_titles[0]}"' if leaked_titles else "")
                ) if leaked_titles else None,
            },
        )
