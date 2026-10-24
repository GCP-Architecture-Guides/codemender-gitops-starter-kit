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

"""Pure workspace-lease decision helpers.

Shared by ``database.py`` (lease API) and ``maintenance.py`` (stale-lock sweeper).
Deliberately free of Google Cloud imports so the logic can be unit tested with
the standard library only.

Lease document shape (collection ``locks``)::

    {"lock_id": str, "owner": str, "locked_at": float, "expires_at": float}

``locked_at`` / ``expires_at`` are epoch seconds. Legacy documents written by the
old ``acquire_lock`` only carry ``locked_at`` and are treated as expiring
``LEGACY_LOCK_TTL_SECONDS`` after that timestamp.
"""

import asyncio
import logging
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_LOCK_TTL_SECONDS = 1800
LEGACY_LOCK_TTL_SECONDS = 1800


def _to_epoch(value) -> Optional[float]:
    """Converts an epoch number or datetime (e.g. Firestore timestamp) to epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    return None


def lock_expiry(doc: Optional[dict]) -> Optional[float]:
    """Returns the lease expiry (epoch seconds), or None if the document shape is unknown."""
    if not doc:
        return None
    expires_at = _to_epoch(doc.get("expires_at"))
    if expires_at is not None:
        return expires_at
    locked_at = _to_epoch(doc.get("locked_at"))
    if locked_at is not None:
        return locked_at + LEGACY_LOCK_TTL_SECONDS
    return None


def is_lock_expired(doc: Optional[dict], now: float) -> bool:
    """True if the lease is known to be expired. Unknown document shapes are never expired."""
    expiry = lock_expiry(doc)
    return expiry is not None and expiry < now


def can_acquire(existing: Optional[dict], now: float) -> bool:
    """True if a new owner may take the lease.

    Missing documents are free, expired leases may be taken over, and documents
    whose expiry cannot be determined are treated as held (fail closed).
    """
    if not existing:
        return True
    return is_lock_expired(existing, now)


def is_owner(existing: Optional[dict], owner: Optional[str]) -> bool:
    """True if the lease document is held by the given owner token."""
    return bool(existing) and bool(owner) and existing.get("owner") == owner


def build_lock_doc(lock_id: str, owner: str, now: float, ttl_seconds: float = DEFAULT_LOCK_TTL_SECONDS) -> dict:
    """Builds a fresh lease document."""
    return {
        "lock_id": lock_id,
        "owner": owner,
        "locked_at": now,
        "expires_at": now + ttl_seconds,
    }


def renewal_fields(now: float, ttl_seconds: float = DEFAULT_LOCK_TTL_SECONDS) -> dict:
    """Fields written when the current owner extends its lease."""
    return {"expires_at": now + ttl_seconds, "renewed_at": now}


def start_renewal_task(
    renew_fn: Callable[[str, str, float], bool],
    lock_id: str,
    owner: str,
    ttl_seconds: float = DEFAULT_LOCK_TTL_SECONDS,
    interval_seconds: float = 300,
) -> "asyncio.Task":
    """Starts a background task that calls ``renew_fn(lock_id, owner, ttl_seconds)``
    in a worker thread every ``interval_seconds`` until the task is cancelled.

    Failures are logged and retried on the next tick. Must be called from a running
    event loop.
    """
    if interval_seconds <= 0 or interval_seconds >= ttl_seconds:
        clamped = max(1.0, ttl_seconds / 3.0)
        logger.warning(
            f"Lease renewal interval {interval_seconds}s is invalid for TTL {ttl_seconds}s on {lock_id}; using {clamped:.0f}s."
        )
        interval_seconds = clamped

    async def _renew_loop():
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                renewed = await asyncio.to_thread(renew_fn, lock_id, owner, ttl_seconds)
            except Exception as err:
                logger.error(f"Lease renewal for {lock_id} raised: {err}")
                continue
            if not renewed:
                logger.error(f"Lease renewal for {lock_id} failed (lease lost, released, or Firestore error).")

    return asyncio.get_running_loop().create_task(_renew_loop(), name=f"lock-renewal:{lock_id}")
