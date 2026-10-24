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

"""Stdlib-only tests for CodeMender CLI retry behaviour.

Covers the transient/permanent classifier, backoff schedule, model fallback selection, the
late-timeout output collection, and the local (no-network) session token parser.
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _ensure_database_stub():
    """cm_tools imports Firestore/BigQuery helpers from `database`; stub them (no Google Cloud)."""
    module = sys.modules.get("database")
    if module is None:
        module = types.ModuleType("database")
        sys.modules["database"] = module
    for name in ("update_scan_status", "log_token_usage", "get_scan_repo_name", "append_scan_step"):
        if not hasattr(module, name):
            setattr(module, name, lambda *args, **kwargs: None)


_ensure_database_stub()
import cm_tools  # noqa: E402
from cm_tools import classify_cm_error, parse_session_token_usage  # noqa: E402


class ClassifyCmErrorTest(unittest.TestCase):
    TRANSIENT = [
        "Error 429: Too Many Requests",
        "rpc error: code = ResourceExhausted desc = RESOURCE_EXHAUSTED: Quota exceeded for aiplatform",
        "googleapi: Error 503: The service is currently unavailable.",
        "rpc error: code = Unavailable desc = connection error",
        "HTTP/1.1 502 Bad Gateway",
        "500 Internal error encountered.",
        "status code 504 from upstream",
        "read tcp 10.0.0.1:443: read: connection reset by peer",
        "context deadline exceeded",
        "net/http: TLS handshake timeout",
        "400 Precondition check failed.",
        "FAILED_PRECONDITION: session expired",
    ]
    PERMANENT = [
        "Error: Unsupported model 'gemini-9'",
        "finding d60761e6 not found in project",
        "PERMISSION_DENIED: 403 caller does not have permission",
        "INVALID_ARGUMENT: request contains an invalid argument",
        "Found 503 lines in vulnerable_app.py",
        "",
    ]

    def test_transient_errors(self):
        for stderr in self.TRANSIENT:
            self.assertEqual(classify_cm_error(stderr, timed_out=False), "transient", stderr)

    def test_permanent_errors(self):
        for stderr in self.PERMANENT:
            self.assertEqual(classify_cm_error(stderr, timed_out=False), "permanent", stderr)

    def test_timeout_is_never_retried(self):
        # P2 C1: one long run per command; a retry would spend another full timeout window.
        self.assertEqual(classify_cm_error("", timed_out=True), "permanent")
        self.assertEqual(classify_cm_error("503 Service Unavailable", timed_out=True), "permanent")
        self.assertEqual(classify_cm_error(None, timed_out=False), "permanent")


class RetryScheduleTest(unittest.TestCase):
    def test_backoff_is_5_15_45_seconds_plus_jitter(self):
        for retry_index, base in enumerate((5.0, 15.0, 45.0)):
            for _ in range(20):
                delay = cm_tools._retry_delay(retry_index)
                self.assertGreaterEqual(delay, base)
                self.assertLessEqual(delay, base + 2.0)

    def test_model_fallback_chain_never_repeats_a_model(self):
        tried = {"gemini-3.8-flash"}
        self.assertEqual(cm_tools._next_fallback_model("gemini-3.8-flash", tried), "gemini-3.7-flash")
        tried.add("gemini-3.7-flash")
        self.assertEqual(cm_tools._next_fallback_model("gemini-3.7-flash", tried), "gemini-3.5-flash")
        tried.add("gemini-3.5-flash")
        self.assertIsNone(cm_tools._next_fallback_model("gemini-3.5-flash", tried))

    def test_model_rejection_detection(self):
        rejected = [
            "Error: Unsupported model gemini-3.8-flash",
            "400 Requests ending with a model turn are not supported.",
            "404 Publisher Model `projects/p/locations/global/publishers/google/models/gemini-3.8-flash` was not found",
        ]
        for message in rejected:
            self.assertIsNotNone(cm_tools._MODEL_REJECTION_RE.search(message), message)
        self.assertIsNone(cm_tools._MODEL_REJECTION_RE.search("finding d60761e6 was not found"))


async def _run_script(script: str, timeout: float, grace: float = 0.3):
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", script,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    started = time.monotonic()
    out, err, timed_out = await cm_tools._collect_process_output(proc, b"y\n", timeout, grace=grace)
    elapsed = time.monotonic() - started
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        pass
    return proc, out, err, timed_out, elapsed


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class CollectProcessOutputTest(unittest.TestCase):
    def test_normal_run_returns_output_and_feeds_stdin(self):
        script = "import sys; print('answer=' + sys.stdin.read().strip()); sys.stderr.write('warn')"
        proc, out, err, timed_out, _ = asyncio.run(_run_script(script, timeout=30))
        self.assertFalse(timed_out)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(out.decode().strip(), "answer=y")
        self.assertEqual(err.decode(), "warn")

    def test_exited_cli_with_lingering_child_counts_as_completed(self):
        # The child inherits stdout (like a verification mock server) and outlives the CLI.
        script = (
            "import subprocess, sys\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print('child=%d' % child.pid, flush=True)\n"
            "print('done', flush=True)\n"
        )
        proc, out, _, timed_out, elapsed = asyncio.run(_run_script(script, timeout=60))
        self.assertFalse(timed_out)
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"done", out)
        self.assertLess(elapsed, 15, "must not wait for the deadline when the CLI already exited")
        child_pid = int(out.decode().split("child=")[1].split()[0])
        for _ in range(50):
            if not _pid_alive(child_pid):
                break
            time.sleep(0.1)
        self.assertFalse(_pid_alive(child_pid), "leftover child should be terminated")

    def test_running_cli_times_out_and_keeps_partial_output(self):
        script = "import time; print('started', flush=True); time.sleep(60)"
        proc, out, _, timed_out, elapsed = asyncio.run(_run_script(script, timeout=1.0))
        self.assertTrue(timed_out)
        self.assertIn(b"started", out)
        self.assertLess(elapsed, 15)
        self.assertIsNotNone(proc.returncode)
        self.assertLess(proc.returncode, 0)


_FAKE_CM_SCRIPT = '''
import json, sys
state_path = {state!r}
reject = {reject!r}
responses = {responses!r}
try:
    with open(state_path) as fh:
        state = json.load(fh)
except FileNotFoundError:
    state = {{"models": [], "served": 0}}
model = sys.argv[sys.argv.index("--model") + 1] if "--model" in sys.argv else None
state["models"].append(model)
if model in reject:
    code, out, err = 1, "partial output", "Error: Unsupported model " + str(model) + " token={token}"
else:
    code, out, err = responses[min(state["served"], len(responses) - 1)]
    state["served"] += 1
with open(state_path, "w") as fh:
    json.dump(state, fh)
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(code)
'''


class RunCmCmdRetryTest(unittest.TestCase):
    FAKE_TOKEN = "ghs_" + "R3tryR3try" * 3

    def setUp(self):
        self.session_id = f"unittest-cm-{os.getpid()}-{time.monotonic_ns()}"
        self.workspace = f"/tmp/session-{self.session_id}"
        os.makedirs(self.workspace)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = os.path.join(self._tmp.name, "state.json")
        cm_tools._CLI_SEMAPHORE = None  # bind a fresh semaphore to this test's event loop
        delay_patcher = mock.patch.object(cm_tools, "_retry_delay", return_value=0.0)
        delay_patcher.start()
        self.addCleanup(delay_patcher.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.workspace, ignore_errors=True)

    def _run(self, reject=(), responses=((0, "ok", ""),)):
        script = os.path.join(self._tmp.name, "fake_cm.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_FAKE_CM_SCRIPT.format(state=self.state_path, reject=list(reject),
                                            responses=[list(r) for r in responses], token=self.FAKE_TOKEN))
        cmd = [sys.executable, script, "verify", "abc123", "-y", "--model", "gemini-3.8-flash"]
        return asyncio.run(cm_tools._run_cm_cmd(cmd, self.session_id))

    def _models_called(self):
        with open(self.state_path, encoding="utf-8") as fh:
            return json.load(fh)["models"]

    def test_exhausted_model_fallback_raises_instead_of_returning_stdout(self):
        with self.assertRaises(RuntimeError) as err:
            self._run(reject=("gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash"))
        message = str(err.exception)
        self.assertIn("Unsupported model", message)
        self.assertNotIn(self.FAKE_TOKEN, message)
        self.assertIn("***", message)
        self.assertEqual(self._models_called(), ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash"])

    def test_permanent_error_fails_fast(self):
        with self.assertRaises(RuntimeError):
            self._run(responses=((2, "", "INVALID_ARGUMENT: bad finding id"),))
        self.assertEqual(len(self._models_called()), 1)

    def test_transient_error_is_retried_then_succeeds(self):
        out = self._run(responses=((1, "", "503 Service Unavailable"), (0, "verified-ok", "")))
        self.assertEqual(out, "verified-ok")
        self.assertEqual(len(self._models_called()), 2)

    def test_model_fallback_does_not_consume_attempts(self):
        # Two rejected models, then two transient failures, then success: 5 runs within 3 attempts.
        out = self._run(
            reject=("gemini-3.8-flash", "gemini-3.7-flash"),
            responses=((1, "", "429 RESOURCE_EXHAUSTED"), (1, "", "UNAVAILABLE"), (0, "done", "")),
        )
        self.assertEqual(out, "done")
        self.assertEqual(self._models_called(), ["gemini-3.8-flash", "gemini-3.7-flash"] + ["gemini-3.5-flash"] * 3)

    def test_transient_errors_stop_after_three_attempts(self):
        with self.assertRaises(RuntimeError) as err:
            self._run(responses=((1, "", "503 Service Unavailable"),))
        self.assertIn("503", str(err.exception))
        self.assertEqual(len(self._models_called()), 3)


class SessionTokenUsageTest(unittest.TestCase):
    SESSION_A = "ChA3YzAxMzMwMGQyOGFjZjNjEAgaAjk1KgRtYWlu"
    SESSION_B = "ChBkYjA4MzM4MDc5OGE5NmI0EAgaAjhlKgRtYWlu"  # sibling session of the same command
    SESSION_X = "ChAwZTcyMDIzZGFlZjRjMDUwEAgaATAqBG1haW4"  # unrelated, newest file

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        env_patcher = mock.patch.dict(os.environ, {"HOME": self._tmp.name})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("CM_HOME", None)
        project_dir = os.path.join(self._tmp.name, ".codemender", "logs", "sessions", "53de1cc0-proj")
        os.makedirs(project_dir)

        def write(name, records):
            with open(os.path.join(project_dir, name), "w", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec) + "\n")

        def interaction(session_id, command_id, inp, out, cached, thought):
            return {"type": "interaction", "session_id": session_id, "interaction_id": session_id,
                    "command_id": command_id, "input": inp, "output": out, "cached": cached,
                    "thought": thought, "total": inp + out + thought, "ts": "2026-10-22T02:15:04Z"}

        a = self.SESSION_A
        write(f"session-20261022T021243Z-{a[:8]}.jsonl", [
            {"type": "command_start", "session_id": a, "command_id": "cmd-1"},
            {"type": "command_finish", "session_id": a, "command_id": "cmd-1", "exit_code": 0},
        ])
        record_a = interaction(a, "cmd-1", 158541, 4118, 108691, 18593)
        write(f"session-20261022T021243Z-{a[:8]}-1.jsonl", [record_a, record_a])  # duplicate counted once
        write(f"session-20261022T021243Z-{self.SESSION_B[:8]}-2.jsonl", [
            interaction(self.SESSION_B, "cmd-1", 1000, 100, 500, 50),
        ])
        write(f"session-20261022T031500Z-{self.SESSION_X[:8]}.jsonl", [
            interaction(self.SESSION_X, "cmd-2", 999999, 99999, 9999, 999),
        ])

    def test_exact_jsonl_totals_by_session_id(self):
        usage = parse_session_token_usage(f"Scan done\n   Session: {self.SESSION_A}\n")
        self.assertEqual(usage["source"], "jsonl")
        self.assertEqual(usage["input_tokens"], 158541 + 1000)
        self.assertEqual(usage["output_tokens"], 4118 + 100)
        self.assertEqual(usage["cached_tokens"], 108691 + 500)
        self.assertEqual(usage["thoughts_tokens"], 18593 + 50)
        self.assertEqual(usage["total_tokens"], usage["input_tokens"] + usage["output_tokens"] + usage["thoughts_tokens"])

    def test_short_session_id_and_explicit_id(self):
        short = parse_session_token_usage(f"Session: {self.SESSION_A[:8]}")
        explicit = parse_session_token_usage("", cm_session_id=self.SESSION_A)
        self.assertEqual(short["input_tokens"], 159541)
        self.assertEqual(explicit["input_tokens"], 159541)

    def test_falls_back_to_cli_summary_for_the_same_run(self):
        output = ("Session: ChBzZXNzaW9uLW5vdC1sb2dnZWQ\n"
                  "   Total tokens consumed: 181.3k (in: 158.5k, cached: 108.7k, out: 4.1k, thinking: 18.6k)\n")
        usage = parse_session_token_usage(output)
        self.assertEqual(usage["source"], "cli_summary")
        self.assertEqual((usage["input_tokens"], usage["cached_tokens"], usage["output_tokens"], usage["thoughts_tokens"]),
                         (158500, 108700, 4100, 18600))

    def test_legacy_cli_summary(self):
        usage = parse_session_token_usage("Tokens: 89k in / 1k out / 93k total")
        self.assertEqual(usage["source"], "cli_summary")
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["thoughts_tokens"]), (89000, 1000, 3000))

    def test_no_data_is_unavailable_and_never_uses_newest_file(self):
        usage = parse_session_token_usage("cm crashed before printing a session id")
        self.assertEqual(usage["source"], "unavailable")
        self.assertEqual(
            {k: usage[k] for k in ("input_tokens", "output_tokens", "cached_tokens", "thoughts_tokens", "total_tokens")},
            {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "thoughts_tokens": 0, "total_tokens": 0},
        )

    def test_makes_no_network_calls(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network access attempted")):
            usage = parse_session_token_usage(f"Session: {self.SESSION_A}")
        self.assertEqual(usage["source"], "jsonl")


if __name__ == "__main__":
    unittest.main()
