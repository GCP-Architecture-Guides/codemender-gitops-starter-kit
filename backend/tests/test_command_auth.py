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

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from command_auth import (  # noqa: E402
    command_name,
    env_flag,
    has_maintainer_role,
    has_write_permission,
    is_independent_approver,
    is_repo_allowed,
    is_trusted_association,
    parse_allowed_repos,
    requires_maintainer,
)


class CommandNameTest(unittest.TestCase):

    def test_slash_commands(self):
        self.assertEqual(command_name("/fix all"), "fix")
        self.assertEqual(command_name("  /verify a1b2c3  "), "verify")
        self.assertEqual(command_name("/Override-Gate [BUSINESS_ACCEPTED_RISK] reason"), "override-gate")
        self.assertEqual(command_name("/unknown"), "unknown")

    def test_bare_words_the_router_accepts(self):
        self.assertEqual(command_name("approve"), "approve")
        self.assertEqual(command_name("fix the sqli please"), "fix")
        self.assertEqual(command_name("VERIFY all"), "verify")
        self.assertEqual(command_name("remediate-all"), "remediate-all")

    def test_ordinary_comments_are_not_commands(self):
        for body in ("", None, "   ", "/", "looks good to me", "dismiss this", "LGTM, approved!"):
            with self.subTest(body=body):
                self.assertIsNone(command_name(body))


class AssociationAndRoleTest(unittest.TestCase):

    def test_trusted_associations(self):
        for assoc in ("OWNER", "MEMBER", "COLLABORATOR", "member"):
            with self.subTest(assoc=assoc):
                self.assertTrue(is_trusted_association(assoc))

    def test_untrusted_associations(self):
        for assoc in ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", "", None):
            with self.subTest(assoc=assoc):
                self.assertFalse(is_trusted_association(assoc))

    def test_maintainer_commands_follow_router_prefixes(self):
        for cmd in ("dismiss", "override", "override-gate", "dismissed", "OVERRIDE"):
            with self.subTest(cmd=cmd):
                self.assertTrue(requires_maintainer(cmd))
        for cmd in ("fix", "verify", "approve", "cancel", "", None):
            with self.subTest(cmd=cmd):
                self.assertFalse(requires_maintainer(cmd))

    def test_maintainer_roles(self):
        for role in ("admin", "maintain", "ADMIN", " maintain "):
            with self.subTest(role=role):
                self.assertTrue(has_maintainer_role(role))
        for role in ("write", "triage", "read", "none", "custom-security-role", "", None):
            with self.subTest(role=role):
                self.assertFalse(has_maintainer_role(role))

    def test_write_permissions(self):
        # Base permission levels from the collaborator API ("maintain" reports "write").
        for permission in ("admin", "write", "WRITE", " admin "):
            with self.subTest(permission=permission):
                self.assertTrue(has_write_permission(permission))
        for permission in ("read", "none", "triage", "maintain", "", None):
            with self.subTest(permission=permission):
                self.assertFalse(has_write_permission(permission))


class IndependentApproverTest(unittest.TestCase):

    def test_author_cannot_approve_own_pr(self):
        self.assertFalse(is_independent_approver("alice", "alice"))
        self.assertFalse(is_independent_approver("Alice", "alice"))

    def test_different_user_can_approve(self):
        self.assertTrue(is_independent_approver("bob", "alice"))

    def test_unknown_logins_fail_closed(self):
        self.assertFalse(is_independent_approver("bob", ""))
        self.assertFalse(is_independent_approver(None, "alice"))


class RepoAllowlistTest(unittest.TestCase):

    def test_empty_allowlist_allows_everything(self):
        allowed = parse_allowed_repos("")
        self.assertEqual(allowed, frozenset())
        self.assertTrue(is_repo_allowed("any/repo", allowed))

    def test_allowlist_is_trimmed_and_case_insensitive(self):
        allowed = parse_allowed_repos(" your-org/your-repo , Org/Other ,, ")
        self.assertTrue(is_repo_allowed("Cloud-GTM/CodeMender-GitOps", allowed))
        self.assertTrue(is_repo_allowed("org/other", allowed))
        self.assertFalse(is_repo_allowed("evil/repo", allowed))
        self.assertFalse(is_repo_allowed(None, allowed))


class EnvFlagTest(unittest.TestCase):

    def test_values(self):
        for value in ("true", "TRUE", "1", "yes", " on "):
            with self.subTest(value=value):
                self.assertTrue(env_flag(value))
        for value in ("false", "0", "no", "off", "maybe"):
            with self.subTest(value=value):
                self.assertFalse(env_flag(value))

    def test_default_applies_to_unset(self):
        self.assertFalse(env_flag(None))
        self.assertTrue(env_flag("", default=True))


if __name__ == "__main__":
    unittest.main()
