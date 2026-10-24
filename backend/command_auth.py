# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

"""Pure authorization rules for GitHub comment commands and repository enrollment.

No I/O here: callers fetch author_association / collaborator roles from the webhook payload or
the GitHub API and pass the values in.
"""

# GitHub computes author_association server-side, so commenters cannot forge it in a webhook
# GitHub signs. Relayed (WIF) events are unsigned, so the webhook takes it from GitHub's copy of
# the comment (event_validation). It is only a cheap pre-filter: MEMBER means org membership,
# not access to this repository.
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

# Base permissions (collaborator permission API, "permission" field) that can push to the
# repository. Slash commands push branches and approve patches, so they need one of these.
# The API reports the maintain role as "write" and triage as "read".
WRITE_PERMISSIONS = frozenset({"admin", "write"})

# Repository roles allowed to suppress findings or override the merge gate.
MAINTAINER_ROLES = frozenset({"admin", "maintain"})

# Words the webhook router accepts without a leading slash ('fix all', 'approve', ...).
BARE_WORD_COMMANDS = frozenset({
    "approve", "verify", "verify-all", "fix", "fix-all", "remediate", "remediate-all",
})

# The router sends any comment starting with '/dismiss' or '/override' to the dismissal handler
# (including '/override-gate' and typos such as '/dismissed'), so authorize on the same prefixes.
MAINTAINER_COMMAND_PREFIXES = ("dismiss", "override")

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def command_name(comment_body) -> str | None:
    """Returns the lower-cased command word ('/fix all' -> 'fix'), or None for ordinary comments."""
    words = str(comment_body or "").strip().split(maxsplit=1)
    if not words:
        return None
    first = words[0].lower()
    if first.startswith("/"):
        return first[1:] or None
    return first if first in BARE_WORD_COMMANDS else None


def is_trusted_association(association) -> bool:
    return str(association or "").strip().upper() in TRUSTED_ASSOCIATIONS


def requires_maintainer(command) -> bool:
    return bool(command) and str(command).lower().startswith(MAINTAINER_COMMAND_PREFIXES)


def has_maintainer_role(role) -> bool:
    return str(role or "").strip().lower() in MAINTAINER_ROLES


def has_write_permission(permission) -> bool:
    return str(permission or "").strip().lower() in WRITE_PERMISSIONS


def is_independent_approver(commenter, pr_author) -> bool:
    """True when both logins are known and differ (GitHub logins are case-insensitive)."""
    approver = str(commenter or "").strip().lower()
    author = str(pr_author or "").strip().lower()
    return bool(approver) and bool(author) and approver != author


def env_flag(value, default: bool = False) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in _TRUE_VALUES


def parse_allowed_repos(raw) -> frozenset:
    """Parses ALLOWED_REPOS ('owner/repo,owner/other'). Empty means no allowlist (local dev only)."""
    return frozenset(r.strip().lower() for r in str(raw or "").split(",") if r.strip())


def is_repo_allowed(repo_name, allowed_repos) -> bool:
    if not allowed_repos:
        return True
    return str(repo_name or "").strip().lower() in allowed_repos
