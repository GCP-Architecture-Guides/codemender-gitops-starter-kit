# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Maps a stored finding onto the findings of a fresh local re-scan.

Dashboard / comment-triggered verify and fix flows re-scan the workspace, and the
CodeMender CLI may assign new finding IDs. ``select_finding`` picks the local finding
that corresponds to the stored one, or returns None when the match is not certain.
It never falls back to the first local finding (GEMINI.md "Finding Mapping Guard").

Stdlib only so it can be unit tested without Google Cloud dependencies.
"""

import re
from typing import Optional

LINE_WINDOW = 15

_PATH_KEYS = ("filepath", "file_path", "file", "path", "target_file")
_LINE_KEYS = ("line_number", "line", "start_line", "lineno")
_CLASS_KEYS = ("vuln_type", "type", "category", "vulnerability_type")
_CWE_KEYS = ("cwe", "cwe_id")

_CWE_RE = re.compile(r"\bcwe[\s_-]*(\d+)\b", re.IGNORECASE)
_PATH_LINE_SUFFIX_RE = re.compile(r":(\d+)(?::\d+)?$")
_SESSION_PREFIX_RE = re.compile(r"^/?tmp/session-[^/]+/")

# Well-known vulnerability names mapped to their CWE so "SQL Injection" == "CWE-89".
# Matched on word boundaries against lowercased text with '-', '_' and '/' turned into spaces.
_CLASS_SYNONYMS = tuple((re.compile(pattern), cwe) for pattern, cwe in (
    (r"\bnosql injection\b", "cwe-943"),
    (r"\bsql injection\b|\bsqli\b", "cwe-89"),
    (r"\bcommand injection\b|\bshell injection\b", "cwe-78"),
    (r"\bcode injection\b", "cwe-94"),
    (r"\bcross ?site scripting\b|\bxss\b", "cwe-79"),
    (r"\bserver ?side request forgery\b|\bssrf\b", "cwe-918"),
    (r"\b(?:path|directory) traversal\b", "cwe-22"),
    (r"\binsecure direct object references?\b|\bidor\b", "cwe-639"),
    (r"\bhard ?coded (?:secrets?|credentials?|passwords?|api keys?|keys?)\b", "cwe-798"),
    (r"\bmass assignment\b", "cwe-915"),
    (r"\bopen redirect\b", "cwe-601"),
    (r"\bxml external entit(?:y|ies)\b|\bxxe\b", "cwe-611"),
    (r"\b(?:insecure|unsafe|untrusted) deserialization\b", "cwe-502"),
    (r"\bauthentication bypass\b", "cwe-287"),
    (r"\bcross ?site request forgery\b|\bcsrf\b", "cwe-352"),
    (r"\bldap injection\b", "cwe-90"),
    (r"\bxpath injection\b", "cwe-643"),
    (r"\btemplate injection\b|\bssti\b", "cwe-1336"),
))


def _clean(value) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _normalize_text(value) -> str:
    text = re.sub(r"[-_/]+", " ", str(value).lower())
    return re.sub(r"\s+", " ", text).strip()


def normalize_path(path) -> str:
    """Normalizes a finding path: strips ':line[:col]', './', leading '/', and /tmp/session-*/ prefixes."""
    if not path:
        return ""
    normalized = str(path).strip().replace("\\", "/")
    normalized = _PATH_LINE_SUFFIX_RE.sub("", normalized)
    normalized = _SESSION_PREFIX_RE.sub("", normalized)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = re.sub(r"/+", "/", normalized).lstrip("/")
    return normalized.lower()


def finding_path(finding: dict) -> str:
    for key in _PATH_KEYS:
        normalized = normalize_path(finding.get(key))
        if normalized:
            return normalized
    return ""


def finding_line(finding: dict) -> Optional[int]:
    for key in _LINE_KEYS:
        value = finding.get(key)
        if value is None or isinstance(value, bool):
            continue
        try:
            line = int(value)
        except (TypeError, ValueError):
            continue
        if line > 0:
            return line
    for key in _PATH_KEYS:
        value = finding.get(key)
        if isinstance(value, str):
            match = _PATH_LINE_SUFFIX_RE.search(value.strip())
            if match:
                return int(match.group(1))
    return None


def vuln_class(finding: dict) -> str:
    """Returns a normalized vulnerability class: 'cwe-<n>' when a CWE is known or implied, else the lowercased label."""
    labels = [_clean(finding.get(key)) for key in _CWE_KEYS + _CLASS_KEYS]
    for label in labels:
        match = _CWE_RE.search(label)
        if match:
            return f"cwe-{int(match.group(1))}"
    class_labels = [_normalize_text(finding.get(key)) for key in _CLASS_KEYS if _clean(finding.get(key))]
    for label in class_labels:
        for pattern, cwe in _CLASS_SYNONYMS:
            if pattern.search(label):
                return cwe
    return class_labels[0] if class_labels else ""


_TEXT_KEYS = ("title", "description", "vuln_type", "type", "category", "vulnerability_type")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "into", "that", "this", "allows", "allow",
    "vulnerability", "insecure", "improper", "neutralization", "special", "elements",
    "used", "command", "injection", "direct", "object", "reference", "idor", "cwe",
    "high", "critical", "medium", "low", "user", "input", "data", "file", "path",
    "function", "method", "endpoint", "request", "response", "handler",
})


def _camel_parts(word: str) -> list[str]:
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", word).lower().split()
    return [p for p in parts if len(p) >= 3 and p not in _STOPWORDS]


def _finding_tokens(finding: dict) -> tuple[frozenset[str], frozenset[str]]:
    """Returns (identifiers, tokens) extracted from title/description/type fields."""
    raw_chunks = [_clean(finding.get(k)) for k in _TEXT_KEYS if _clean(finding.get(k))]
    joined = " ".join(raw_chunks)
    identifiers = set()
    tokens = set()
    for ident in _IDENTIFIER_RE.findall(joined):
        low = ident.lower()
        if low in _STOPWORDS or _CWE_RE.fullmatch(low):
            continue
        # CamelCase or snake_case symbols (e.g. viewInvoiceHandler, update_profile)
        if "_" in ident or any(c.isupper() for c in ident[1:]):
            identifiers.add(low)
            tokens.update(_camel_parts(ident))
        if len(low) >= 3:
            tokens.add(low)
    return frozenset(identifiers), frozenset(tokens)


def _unique_text_match(target: dict, findings: list) -> Optional[dict]:
    """Resolves multiple same-file same-CWE candidates by unique handler/identifier or token overlap."""
    target_idents, target_tokens = _finding_tokens(target)
    if not target_idents and not target_tokens:
        return None
    scored = []
    for finding in findings:
        cand_idents, cand_tokens = _finding_tokens(finding)
        ident_overlap = len(target_idents & cand_idents)
        token_overlap = len(target_tokens & cand_tokens)
        score = ident_overlap * 10 + token_overlap
        scored.append((score, ident_overlap, token_overlap, finding))
    if not scored:
        return None
    best_score = max(s[0] for s in scored)
    if best_score <= 0:
        return None
    winners = [s[3] for s in scored if s[0] == best_score]
    return winners[0] if len(winners) == 1 else None


def _unique_nearest(target: dict, findings: list) -> Optional[dict]:
    """Returns the single finding closest to the target line, or None if lines are unknown or tied."""
    target_line = finding_line(target)
    if target_line is not None:
        ranked = []
        for finding in findings:
            line = finding_line(finding)
            if line is not None:
                ranked.append((abs(line - target_line), finding))
        if ranked:
            best = min(distance for distance, _ in ranked)
            nearest = [finding for distance, finding in ranked if distance == best]
            if len(nearest) == 1:
                return nearest[0]
            return _unique_text_match(target, nearest)
    return _unique_text_match(target, findings)


def select_finding(target: dict, local_findings: list) -> Optional[dict]:
    """Selects the local finding that corresponds to ``target``, or None if not certain.

    Order: exact ``id`` (ignored when both sides name different files); exact
    ``fingerprint``; otherwise local findings in the same normalized file with the same
    normalized vulnerability class (CWE-aware) and, when both have line numbers, at most
    LINE_WINDOW lines apart. One candidate is returned as-is; several are resolved by a
    unique nearest line or unique handler/title token overlap, else None. Never falls back
    to ``local_findings[0]``.
    """
    if not isinstance(target, dict) or not local_findings:
        return None
    candidates = [finding for finding in local_findings if isinstance(finding, dict)]
    if not candidates:
        return None

    target_path = finding_path(target)

    # 1. Exact ID.
    target_id = _clean(target.get("id"))
    if target_id:
        for finding in candidates:
            if _clean(finding.get("id")) != target_id:
                continue
            local_path = finding_path(finding)
            if target_path and local_path and target_path != local_path:
                continue
            return finding

    # 2. Exact fingerprint.
    target_fingerprint = _clean(target.get("fingerprint"))
    if target_fingerprint:
        fingerprint_matches = [f for f in candidates if _clean(f.get("fingerprint")) == target_fingerprint]
        if len(fingerprint_matches) == 1:
            return fingerprint_matches[0]
        if fingerprint_matches:
            return _unique_nearest(target, fingerprint_matches)

    # 3. Same file + same vulnerability class (+ nearby line when both are known).
    target_class = vuln_class(target)
    if not target_path or not target_class:
        return None
    target_line = finding_line(target)
    matches = []
    for finding in candidates:
        if finding_path(finding) != target_path or vuln_class(finding) != target_class:
            continue
        line = finding_line(finding)
        if target_line is not None and line is not None and abs(line - target_line) > LINE_WINDOW:
            continue
        matches.append(finding)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return _unique_nearest(target, matches)
    return None

