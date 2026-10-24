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

"""Masks credentials (GitHub tokens, HTTP Authorization values) before they reach log output.

Usage:
    from log_redaction import install_log_redaction, redact
    install_log_redaction()      # once, at startup (safe to call repeatedly)
    safe_text = redact(text)     # for strings that are persisted outside the logging system
"""

import logging
import re

_REDACTION_RULES = (
    # Credentials embedded in git remote URLs: https://x-access-token:<token>@github.com/...
    (re.compile(r"x-access-token:[^@\s]+@"), "x-access-token:***@"),
    # GitHub personal / OAuth / user-to-server / server-to-server / refresh tokens.
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "***"),
    # GitHub fine-grained personal access tokens.
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "***"),
    # Google OAuth access tokens (defense in depth for ADC bearer tokens).
    (re.compile(r"ya29\.[0-9A-Za-z_\-.]{20,}"), "ya29.***"),
    # Authorization headers (plain, dict repr or JSON): keep the scheme, mask the credential.
    (
        re.compile(r"(Authorization)([\"']?\s*[:=]\s*[\"']?)(Bearer|Basic|token)\s+[^\s\"',;}]+", re.IGNORECASE),
        r"\1\2\3 ***",
    ),
)

# Loggers that get the filter attached directly (in addition to their handlers).
_TARGET_LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access")
_MARKER = "_cm_log_redaction"


def redact(text: str) -> str:
    """Returns ``text`` with GitHub tokens and Authorization header values masked."""
    if not isinstance(text, str) or not text:
        return text
    for pattern, replacement in _REDACTION_RULES:
        text = pattern.sub(replacement, text)
    return text


def _redact_arg(value):
    """Redacts one logging argument while keeping non-secret values (ints, etc.) untouched."""
    if isinstance(value, str):
        return redact(value)
    if value is None or isinstance(value, (bool, int, float, bytes)):
        return value
    try:
        rendered = str(value)
    except Exception:
        return value
    masked = redact(rendered)
    return masked if masked != rendered else value


def _redact_record(record: logging.LogRecord) -> None:
    """Redacts a LogRecord in place, preserving the shape of ``record.args``."""
    args = record.args
    if isinstance(args, tuple) and args:
        record.args = tuple(_redact_arg(a) for a in args)
    elif isinstance(args, dict) and args:
        record.args = {k: _redact_arg(v) for k, v in args.items()}

    redacted_args = record.args
    collapsed = False
    if redacted_args:
        # Check the rendered text, not the %-template: masking the template itself could destroy
        # its placeholders (e.g. "x-access-token:%s@"). Only when the template leaks a secret is
        # the message replaced by its redacted rendering.
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = None
        if rendered is None:
            record.msg = _redact_arg(record.msg)
        else:
            masked = redact(rendered)
            if masked != rendered:
                record.msg, record.args = masked, ()
                collapsed = True
    else:
        record.msg = _redact_arg(record.msg)
    # uvicorn formatters prefer this %-template over msg when colors are enabled. If it would leak
    # (or its args were collapsed above), drop it so formatters fall back to the redacted msg.
    color_message = record.__dict__.get("color_message")
    if isinstance(color_message, str):
        try:
            rendered_color = color_message % redacted_args if redacted_args else color_message
        except Exception:
            rendered_color = color_message
        if collapsed or redact(rendered_color) != rendered_color:
            del record.__dict__["color_message"]
    if record.exc_info and not record.exc_text:
        try:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        except Exception:
            pass
    if record.exc_text:
        record.exc_text = redact(record.exc_text)
    if record.stack_info:
        record.stack_info = redact(record.stack_info)


class RedactingFilter(logging.Filter):
    """logging.Filter that masks credentials in the message, its args and exception text."""

    _cm_log_redaction = True

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            _redact_record(record)
        except Exception:
            pass  # Never drop a log line because redaction failed.
        return True


_FILTER = RedactingFilter()


def _attach(filterer) -> None:
    if not any(getattr(f, _MARKER, False) for f in filterer.filters):
        filterer.addFilter(_FILTER)


def _install_record_factory() -> None:
    """Redacts at record creation too, so handlers added after install are covered."""
    current = logging.getLogRecordFactory()
    if getattr(current, _MARKER, False):
        return

    def _redacting_record_factory(*args, **kwargs):
        record = current(*args, **kwargs)
        try:
            _redact_record(record)
        except Exception:
            pass
        return record

    setattr(_redacting_record_factory, _MARKER, True)
    logging.setLogRecordFactory(_redacting_record_factory)


def install_log_redaction() -> None:
    """Idempotently installs the redacting filter on the root and uvicorn loggers and handlers."""
    for name in _TARGET_LOGGERS:
        target = logging.getLogger(name) if name else logging.getLogger()
        _attach(target)
        for handler in list(target.handlers):
            _attach(handler)
    _install_record_factory()
