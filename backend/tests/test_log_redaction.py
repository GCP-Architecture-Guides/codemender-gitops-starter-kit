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

"""Stdlib-only tests for log_redaction (token masking and the logging filter)."""

import io
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import log_redaction  # noqa: E402
from log_redaction import install_log_redaction, redact  # noqa: E402

# Obviously fake credentials, built at runtime so no token-shaped literal sits in the source.
FAKE_GHS = "ghs_" + "A1b2C3d4E5" * 3
FAKE_GHP = "ghp_" + "Z9y8X7w6V5" * 3
FAKE_PAT = "github_pat_" + "11AAAA0000_" * 3


class RedactTest(unittest.TestCase):
    def test_masks_token_in_git_remote_url(self):
        url = f"https://x-access-token:{FAKE_GHS}@github.com/your-org/your-repo.git"
        self.assertEqual(redact(url), "https://x-access-token:***@github.com/your-org/your-repo.git")

    def test_masks_github_token_families(self):
        for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
            token = prefix + "Q" * 36
            self.assertEqual(redact(f"token={token} end"), "token=*** end", prefix)

    def test_masks_fine_grained_pat(self):
        self.assertEqual(redact(f"using {FAKE_PAT}"), "using ***")

    def test_masks_authorization_header_keeping_scheme(self):
        cases = {
            "Authorization: Bearer abc.def-ghi": "Authorization: Bearer ***",
            "AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Zm9v": "AUTHORIZATION: basic ***",
            "Authorization: Basic dXNlcjpwYXNz": "Authorization: Basic ***",
            "Authorization: token sometoken123": "Authorization: token ***",
            "{'Authorization': 'Bearer abc123', 'X': 1}": "{'Authorization': 'Bearer ***', 'X': 1}",
            '{"Authorization": "Bearer abc123"}': '{"Authorization": "Bearer ***"}',
        }
        for raw, expected in cases.items():
            self.assertEqual(redact(raw), expected, raw)

    def test_git_extraheader_value_is_masked(self):
        line = "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX3h4eA=="
        self.assertEqual(redact(line), "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic ***")

    def test_leaves_ordinary_text_alone(self):
        for text in ("git push origin main", "ghp_short", "Authorization required", "", "a@b.c"):
            self.assertEqual(redact(text), text)

    def test_non_string_input_is_returned_unchanged(self):
        self.assertIsNone(redact(None))
        self.assertEqual(redact(42), 42)


class InstallLogRedactionTest(unittest.TestCase):
    def setUp(self):
        self._orig_factory = logging.getLogRecordFactory()
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        self.root = logging.getLogger()
        self._orig_level = self.root.level
        self.root.setLevel(logging.INFO)
        self.root.addHandler(self.handler)  # attached before install: gets the filter

    def tearDown(self):
        self.root.removeHandler(self.handler)
        self.root.setLevel(self._orig_level)
        logging.setLogRecordFactory(self._orig_factory)
        for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
            target = logging.getLogger(name) if name else logging.getLogger()
            for filterer in [target, *target.handlers]:
                for f in list(filterer.filters):
                    if isinstance(f, log_redaction.RedactingFilter):
                        filterer.removeFilter(f)

    @staticmethod
    def _count_filters(filterer):
        return sum(isinstance(f, log_redaction.RedactingFilter) for f in filterer.filters)

    def test_install_is_idempotent(self):
        install_log_redaction()
        install_log_redaction()
        for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
            target = logging.getLogger(name) if name else logging.getLogger()
            self.assertEqual(self._count_filters(target), 1, name or "root")
        self.assertEqual(self._count_filters(self.handler), 1)

    def test_child_logger_messages_and_args_are_redacted(self):
        install_log_redaction()
        log = logging.getLogger("tests.redaction.child")
        log.info("cloning https://x-access-token:%s@github.com/o/r.git", FAKE_GHS)
        log.info(f"token in msg {FAKE_GHP}")
        log.info("header %(h)s", {"h": "Authorization: Bearer abc123"})
        log.info("Authorization: Bearer %s", "def456")  # placeholder inside a secret-shaped template
        log.info(f"leaked {FAKE_PAT} for %s", "repo")  # template itself leaks
        output = self.stream.getvalue()
        self.assertNotIn(FAKE_GHS, output)
        self.assertNotIn(FAKE_GHP, output)
        self.assertNotIn(FAKE_PAT, output)
        self.assertNotIn("abc123", output)
        self.assertNotIn("def456", output)
        self.assertIn("x-access-token:***@github.com/o/r.git", output)
        self.assertIn("header Authorization: Bearer ***", output)
        self.assertIn("leaked *** for repo", output)
        self.assertEqual(output.count("Authorization: Bearer ***"), 2)

    def test_non_string_args_keep_their_shape(self):
        install_log_redaction()

        class Url:
            def __str__(self):
                return f"https://x-access-token:{FAKE_GHS}@github.com/x.git"

        logging.getLogger("tests.redaction.shape").info("%s %d %s", Url(), 200, "GET")
        self.assertIn("https://x-access-token:***@github.com/x.git 200 GET", self.stream.getvalue())

    def test_exception_text_is_redacted(self):
        install_log_redaction()
        try:
            raise RuntimeError(f"push failed for https://x-access-token:{FAKE_GHS}@github.com/o/r.git")
        except RuntimeError:
            logging.getLogger("tests.redaction.exc").exception("git failed")
        output = self.stream.getvalue()
        self.assertIn("git failed", output)
        self.assertNotIn(FAKE_GHS, output)
        self.assertIn("x-access-token:***@", output)

    def test_handler_added_after_install_is_still_redacted(self):
        install_log_redaction()
        late_stream = io.StringIO()
        late_handler = logging.StreamHandler(late_stream)
        self.root.addHandler(late_handler)
        try:
            logging.getLogger("tests.redaction.late").warning("pat %s", FAKE_PAT)
        finally:
            self.root.removeHandler(late_handler)
        self.assertNotIn(FAKE_PAT, late_stream.getvalue())
        self.assertIn("pat ***", late_stream.getvalue())


if __name__ == "__main__":
    unittest.main()
