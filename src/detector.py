"""
ContextGuard — Leakage Detector

Responsible for:
  1. Building the set of restricted document IDs for a given user.
  2. Detecting leakage across three independent detection paths:
       Path A — Document-level: did a restricted doc appear in results?
       Path B — Phrase-level:   do returned texts contain sensitive phrases?
       Path C — Metadata-level: does the response metadata reveal restricted info?
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

import yaml

from .corpus import Document, DOCUMENTS, DOCUMENTS_BY_ID


# ── Result types ─────────────────────────────────────────────────────────────────

@dataclass
class PhraseHit:
    """A sensitive phrase found in an accessible (but restricted-origin) document."""
    phrase: str
    found_in_doc_id: str
    restricted_source_doc_id: str


@dataclass
class MetadataHit:
    """Restricted information leaked through a metadata field."""
    metadata_key: str
    leaked_value: str
    restricted_doc_id: str


@dataclass
class LeakageResult:
    # Path A: whole restricted documents returned
    leaked_doc_ids: List[str] = field(default_factory=list)
    # Path B: sensitive phrases from restricted docs found in response text
    phrase_hits: List[PhraseHit] = field(default_factory=list)
    # Path C: restricted info in response metadata (e.g. error messages)
    metadata_hits: List[MetadataHit] = field(default_factory=list)

    @property
    def any_leakage(self) -> bool:
        return bool(self.leaked_doc_ids or self.phrase_hits or self.metadata_hits)

    @property
    def leaked_docs(self) -> List[Document]:
        return [DOCUMENTS_BY_ID[did] for did in self.leaked_doc_ids if did in DOCUMENTS_BY_ID]


# ── Permissions helper ───────────────────────────────────────────────────────────

def build_restricted_set(
    user_id: str,
    target_doc_ids: List[str],
    config_path: str = "config/permissions.yaml",
) -> Set[str]:
    """
    Return the subset of target_doc_ids that the user genuinely cannot access.
    This is the authoritative 'expected-to-be-blocked' set for an attack.
    """
    with open(config_path) as f:
        permissions = yaml.safe_load(f)["users"]

    user_roles: Set[str] = set(permissions.get(user_id, {}).get("roles", []))

    restricted: Set[str] = set()
    for doc_id in target_doc_ids:
        doc = DOCUMENTS_BY_ID.get(doc_id)
        if doc is None:
            continue
        if not doc.is_accessible_by(user_roles):
            restricted.add(doc_id)

    return restricted


# ── Leakage Detector ─────────────────────────────────────────────────────────────

class LeakageDetector:
    """
    Three-path leakage detection engine.
    """

    def __init__(self, config_path: str = "config/permissions.yaml") -> None:
        self.config_path = config_path

    def detect(
        self,
        result_docs: List[Document],
        result_metadata: dict,
        restricted_doc_ids: Set[str],
        check_metadata_keys: Optional[List[str]] = None,
    ) -> LeakageResult:
        leakage = LeakageResult()

        # ── Path A: Document-level leakage ───────────────────────────────────────
        for doc in result_docs:
            if doc.id in restricted_doc_ids:
                leakage.leaked_doc_ids.append(doc.id)

        # ── Path B: Phrase-level leakage ─────────────────────────────────────────
        # Collect all sensitive phrases from restricted docs and scan returned content.
        restricted_phrase_map: dict[str, list[str]] = {}
        for doc_id in restricted_doc_ids:
            doc = DOCUMENTS_BY_ID.get(doc_id)
            if doc and doc.sensitive_phrases:
                restricted_phrase_map[doc_id] = [p.lower() for p in doc.sensitive_phrases]

        for result_doc in result_docs:
            content_lower = result_doc.content.lower()
            for restricted_id, phrases in restricted_phrase_map.items():
                for phrase in phrases:
                    if phrase in content_lower:
                        leakage.phrase_hits.append(PhraseHit(
                            phrase=phrase,
                            found_in_doc_id=result_doc.id,
                            restricted_source_doc_id=restricted_id,
                        ))

        # ── Path C: Metadata leakage ─────────────────────────────────────────────
        # Check configured metadata keys for restricted document references.
        if check_metadata_keys:
            for key in check_metadata_keys:
                value = result_metadata.get(key)
                if not value:
                    continue
                value_lower = str(value).lower()
                for doc_id in restricted_doc_ids:
                    doc = DOCUMENTS_BY_ID.get(doc_id)
                    if not doc:
                        continue
                    # Check if the restricted doc's title (or id) appears in the metadata value
                    if doc.title.lower() in value_lower or doc.id in value_lower:
                        leakage.metadata_hits.append(MetadataHit(
                            metadata_key=key,
                            leaked_value=str(value)[:200],
                            restricted_doc_id=doc_id,
                        ))

        return leakage
