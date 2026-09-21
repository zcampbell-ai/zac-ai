"""S3-compatible `BackupObjectStore` backend (D031B Phase 1).

Implements `zacai.backup_artifacts.BackupObjectStore` against any
S3-API-compatible provider (Amazon S3, Cloudflare R2, Backblaze B2's
S3-compatible mode) via `boto3` - one implementation satisfies all
three, differing only in `endpoint_url`/`bucket`/credentials
(DECISIONS.md D031B). Backblaze B2 is D031B's recommended provider, but
nothing here is B2-specific.

**This module creates no infrastructure and touches no real provider.**
It is exercised entirely against a mocked S3 backend (`moto`) in tests.
Real use requires Zac to create a real bucket and a scoped, no-delete
application key himself (DECISIONS.md D031B S:N) - Phase 1 (this module)
never does that, never uploads anything, and is never pointed at a real
account.

**Minimum required capabilities, verified empirically against this
module's actual method bodies, not assumed by habit**: only
`readFiles` (`s3:GetObject`) and `writeFiles` (`s3:PutObject`) are
required - every method here calls only `head_object`/`get_object`/
`put_object`, all object-scoped operations. `listFiles`
(`s3:ListBucket`) is **not** required: `list_objects_v2`/`ListBucket` is
never called anywhere in this class, since the `BackupObjectStore`
protocol (D031A) has no listing method and `backup_artifacts.py`'s
Source-driven backup algorithm never scans a bucket's contents - it only
ever addresses objects by their deterministically-computed,
content-addressed key. `listAllBucketNames`
(`s3:ListAllMyBuckets`, B2's account-wide "list every bucket" capability)
is **also not required**: this class never calls `list_buckets()`; the
bucket name and its S3-compatible endpoint URL are supplied directly at
construction time via configuration, never discovered via an API call.
No delete, bucket-management, or account-admin capability is ever
exercised by any method here.

Retries for transient network/5xx errors are handled entirely by
`boto3`'s own built-in retry configuration (`Config(retries=...)`,
below) - no second, application-level retry loop is added, since one
would just duplicate what `boto3` already does correctly.
"""

from __future__ import annotations

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from zacai.backup_artifacts import BackupArtifactsError, ObjectStat

_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_CONNECT_TIMEOUT = 10.0
_DEFAULT_READ_TIMEOUT = 30.0

_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound"})


class RemoteBackupError(BackupArtifactsError):
    """Raised for any S3-compatible backend failure other than a
    not-found lookup (which `exists()` reports as `False`, not an
    error - see `_is_not_found`). The message is built only from the
    provider's own error code/text and the object key - it never
    includes, and cannot include, the credential values passed to
    `S3CompatibleBackupObjectStore.__init__`, since those are never
    read back from `boto3`/`botocore` exception objects at all."""


class S3CompatibleBackupObjectStore:
    """`BackupObjectStore` (D031A protocol, unchanged) backed by any
    S3-API-compatible provider.

    Object `PutObject`/`GetObject` are natively atomic on all three
    candidate providers (DECISIONS.md D031B SF) - an object is either
    fully absent or fully present with its complete final bytes; there
    is no application-visible partial-write state the way a local
    filesystem write has. No local temp-then-rename dance is needed
    here, unlike `LocalDirectoryBackupStore` (D031A), which needed one
    specifically because plain filesystem writes aren't atomic.
    """

    def __init__(
        self,
        *,
        bucket: str,
        access_key_id: str,
        secret_access_key: str,
        endpoint_url: str | None = None,
        region: str = "auto",
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = _DEFAULT_READ_TIMEOUT,
    ) -> None:
        self._bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            config=Config(
                retries={"max_attempts": max_attempts, "mode": "standard"},
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
            ),
        )

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            if _is_not_found(exc):
                return False
            raise RemoteBackupError(f"could not check existence of {key!r}: {_safe_error_text(exc)}") from exc
        except BotoCoreError as exc:
            raise RemoteBackupError(f"could not check existence of {key!r}: {_safe_error_text(exc)}") from exc
        return True

    def stat(self, key: str) -> ObjectStat:
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key)
        except (ClientError, BotoCoreError) as exc:
            raise RemoteBackupError(f"could not stat {key!r}: {_safe_error_text(exc)}") from exc
        return ObjectStat(size=int(response["ContentLength"]))

    def get_object(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            body: bytes = response["Body"].read()
        except (ClientError, BotoCoreError) as exc:
            raise RemoteBackupError(f"could not read {key!r}: {_safe_error_text(exc)}") from exc
        return body

    def put_object(self, key: str, data: bytes) -> None:
        try:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=data)
        except (ClientError, BotoCoreError) as exc:
            raise RemoteBackupError(f"could not write {key!r}: {_safe_error_text(exc)}") from exc


def _is_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    code = str(error.get("Code", ""))
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return code in _NOT_FOUND_CODES or status == 404


def _safe_error_text(exc: Exception) -> str:
    """A short description built only from the provider's own error
    code/message - never from request parameters, headers, or anything
    that could carry a credential value."""
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'UnknownError')}: {error.get('Message', 'no message')}"
    return type(exc).__name__
