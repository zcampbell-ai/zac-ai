"""Bounded preserved legacy recovery evidence; never historical actor authority."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zacai.connectors.connector_authority import _guard, _json, _pairs
from zacai.connectors.gmail_quarantine_record import parse_gmail_quarantine_record

LEGACY_JOURNAL = "gmail-quarantine-intent.bin"
LEGACY_SPEND = "gmail-recovery-attempt.bin"
PROFILE = "legacy_repeat_v2"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_KEYS = {
    "version",
    "profile",
    "configuration",
    "account",
    "generation",
    "journal",
    "spend",
    "legacy_files",
    "state",
    "rows",
}


def recovery_names(configuration: str, account: str, generation: str) -> tuple[str, str, str]:
    if (
        any(type(v) is not str or _DIGEST.fullmatch(v) is None for v in (configuration, account))
        or type(generation) is not str
        or _GENERATION.fullmatch(generation) is None
    ):
        raise ValueError("closed recovery namespace required")
    suffix = hashlib.sha256(
        b"zac-gmail-repeat-namespace-v2\0" + _json([configuration, account, generation])
    ).hexdigest()[:32]
    return (
        f"gmail-quarantine-intent-{suffix}.bin",
        f".gmail-quarantine-intent-{suffix}.stage",
        f"gmail-recovery-attempt-{suffix}.bin",
    )


def validate_history_descriptor(
    value: Any, *, configuration: str, account: str, generation: str
) -> dict[str, Any]:
    """Strict untrusted syntax only; MAC/current-owner checks remain mandatory."""
    if (
        type(value) is not dict
        or set(value) != _KEYS
        or type(value["version"]) is not int
        or value["version"] != 2
        or value["profile"] != PROFILE
    ):
        raise ValueError("closed history schema required")
    journal, _, spend = recovery_names(configuration, account, generation)
    if any(
        value[k] != v
        for k, v in (
            ("configuration", configuration),
            ("account", account),
            ("generation", generation),
            ("journal", journal),
            ("spend", spend),
        )
    ):
        raise ValueError("exact history correlations required")
    if type(value["state"]) is not str or _DIGEST.fullmatch(value["state"]) is None:
        raise ValueError("exact legacy state required")
    files, rows = value["legacy_files"], value["rows"]
    if type(files) is not dict or set(files) != {LEGACY_JOURNAL, LEGACY_SPEND}:
        raise ValueError("exact legacy evidence required")
    for item in files.values():
        if (
            type(item) is not dict
            or set(item) != {"sha256", "witness"}
            or type(item["sha256"]) is not str
            or _DIGEST.fullmatch(item["sha256"]) is None
            or type(item["witness"]) is not list
            or len(item["witness"]) != 8
            or any(type(x) is not int or x < 0 for x in item["witness"])
        ):
            raise ValueError("bounded legacy witness required")
    if (
        type(rows) is not dict
        or not 1 <= len(rows) <= 8
        or value["state"] not in rows
        or len(_json(value)) > 48_000
    ):
        raise ValueError("bounded complete legacy rows required")
    for state, row in rows.items():
        if (
            type(state) is not str
            or _DIGEST.fullmatch(state) is None
            or type(row) is not dict
            or set(row)
            != {
                "configuration",
                "account",
                "binding",
                "generation",
                "rotation",
                "expires",
                "state",
                "verifier",
                "execution",
                "loaded",
            }
        ):
            raise ValueError("complete historical rows required")
        # No uncertain in-flight attempt can be silently bypassed, including other accounts.
        if row["state"] not in {"held", "denied"}:
            raise ValueError("historical unresolved attempt requires separate review")
    result: dict[str, Any] = json.loads(_json(value), object_pairs_hook=_pairs)
    return result


def _file(
    directory: Any, name: str, *, expected: dict[str, Any] | None = None
) -> tuple[bytes, dict[str, Any]]:
    path = directory / name
    before = _guard(path)
    witness = [
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ]
    if expected is not None and witness != expected["witness"]:
        raise ValueError("original retained legacy inode required")
    if before.st_size > 65_565:
        raise ValueError("bounded legacy evidence required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if [
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ] != witness:
            raise ValueError("original opened legacy inode required")
        raw = os.pread(fd, 65_566, 0)
        after = os.fstat(fd)
        if [
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ] != witness or len(raw) != before.st_size:
            raise ValueError("unchanged legacy evidence required")
    finally:
        os.close(fd)
    final = _guard(path)
    if [
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_uid,
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
    ] != witness:
        raise ValueError("unchanged legacy name required")
    return raw, {"sha256": hashlib.sha256(raw).hexdigest(), "witness": witness}


def history_ciphers(
    authority: Any, configuration: Any, account: str, key: bytes
) -> tuple[AESGCM, bytes, AESGCM, bytes]:
    journal_context = (
        b"zac-gmail-quarantine-journal-v1\0"
        + authority._continuity._context
        + b"\0"
        + configuration.configuration_digest.encode("ascii")
        + b"\0"
        + account.encode("ascii")
    )
    spend_context = b"zac-gmail-one-recovery-v1\0" + authority._context

    def cipher(salt: bytes, context: bytes) -> AESGCM:
        return AESGCM(HKDF(algorithm=SHA256(), length=32, salt=salt, info=context).derive(key))

    return (
        cipher(b"zac-gmail-quarantine-journal-key-v1", journal_context),
        journal_context,
        cipher(b"zac-gmail-one-recovery-key-v1", spend_context),
        spend_context,
    )


def authenticate_history(
    descriptor: dict[str, Any], *, authority: Any, configuration: Any, key: bytes, identity: Any
) -> None:
    """Authenticate immutable legacy chain under a separately current real owner."""
    configuration, account = authority._configuration(configuration, None)
    checked = validate_history_descriptor(
        descriptor,
        configuration=configuration.configuration_digest,
        account=account,
        generation=descriptor["generation"],
    )
    raw, journal_file = _file(
        authority._directory, LEGACY_JOURNAL, expected=checked["legacy_files"][LEGACY_JOURNAL]
    )
    spent_raw, spend_file = _file(
        authority._directory, LEGACY_SPEND, expected=checked["legacy_files"][LEGACY_SPEND]
    )
    if checked["legacy_files"] != {LEGACY_JOURNAL: journal_file, LEGACY_SPEND: spend_file}:
        raise ValueError("exact retained legacy files required")
    cipher, context, spend_cipher, spend_context = history_ciphers(
        authority, configuration, descriptor["account"], key
    )
    record = parse_gmail_quarantine_record(
        cipher.decrypt(raw[:12], raw[12:], context), configuration=configuration
    )
    plain = spend_cipher.decrypt(spent_raw[:12], spent_raw[12:], spend_context)
    spent = json.loads(plain, object_pairs_hook=_pairs)
    if (
        _json(spent) != plain
        or type(spent) is not dict
        or set(spent)
        != {
            "version",
            "state",
            "configuration",
            "old_state",
            "old_row",
            "journal",
            "hr_binding",
            "original_binding",
            "generation",
        }
    ):
        raise ValueError("exact authenticated legacy spend required")
    if (
        record.version != 1
        or record.history is not None
        or record.account_digest != account
        or type(spent["version"]) is not int
        or spent["version"] != 1
        or spent["state"] != "spent"
        or spent["configuration"] != configuration.configuration_digest
        or spent["old_state"] != record.state_hash
        or checked["state"] != record.state_hash
        or _json(checked["rows"][record.state_hash]) != record.original_row_bytes
        or spent["old_row"] != hashlib.sha256(record.original_row_bytes).hexdigest()
        or spent["journal"] != hashlib.sha256(raw).hexdigest()
        or spent["generation"] != record.review_generation_claim
        or spent["hr_binding"] != record.reviewer_binding_claim
        or record.reviewer_issuer_hint != identity.issuer
        or record.reviewer_subject_hint != identity.subject
    ):
        raise ValueError("bound authenticated legacy chain required")
    if (
        any(
            type(spent[k]) is not str or _DIGEST.fullmatch(spent[k]) is None
            for k in ("hr_binding", "original_binding")
        )
        or spent["generation"] == descriptor["generation"]
    ):
        raise ValueError("independent fresh action required")


_CAPTURES: WeakKeyDictionary[GmailRecoveryHistory, tuple[Any, ...]] = WeakKeyDictionary()


@dataclass(frozen=True, init=False, repr=False, eq=False)
class GmailRecoveryHistory:
    """Private capture of immutable evidence; current action is separate authority."""

    _authority: Any
    _action: Any
    _key: bytes
    _data: bytes
    _original_data: bytes
    _pins: tuple[Any, ...]
    _directory_identity: tuple[int, ...]

    def __init__(self) -> None:
        raise TypeError("actual current-owner capture only")

    def _graph(self) -> tuple[Any, ...]:
        authority = self._authority
        continuity = authority._continuity
        return (
            authority._directory,
            authority._path,
            authority._lock_path,
            authority._context,
            authority._cipher,
            continuity,
            continuity._context,
            continuity._key,
            self._action._configuration,
            self._action._configuration.configuration_digest,
            self._action._generation,
            self._directory_identity,
        )

    def descriptor(self) -> dict[str, Any]:
        if (
            type(self) is not GmailRecoveryHistory
            or _CAPTURES.get(self) is not self._pins
            or self._data != self._original_data
            or (self._authority, self._action, self._key, self._data, *self._graph()) != self._pins
            or self._authority is not self._action._authority
            or self._action is not self._pins[1]
            or self._authority is not self._pins[0]
            or self._authority._cipher is not self._pins[8]
            or self._authority._continuity is not self._pins[9]
            or self._action._configuration is not self._pins[12]
        ):
            raise ValueError("original history changed")
        value: dict[str, Any] = json.loads(self._data, object_pairs_hook=_pairs)
        return value

    def current(self) -> None:
        value = self.descriptor()
        directory = _guard(self._authority._directory, directory=True)
        if (
            directory.st_dev,
            directory.st_ino,
            directory.st_mode,
            directory.st_uid,
        ) != self._directory_identity:
            raise ValueError("original history directory required")
        for name, expected in value["legacy_files"].items():
            if _file(self._authority._directory, name, expected=expected)[1] != expected:
                raise ValueError("historical evidence changed")

    def check_rows(self, ledger: dict[str, Any], *, fresh_state: str | None = None) -> None:
        rows = self.descriptor()["rows"]
        if set(ledger["rows"]) != set(rows) | (
            {fresh_state} if fresh_state is not None else set()
        ) or any(_json(ledger["rows"].get(state)) != _json(row) for state, row in rows.items()):
            raise ValueError("complete historical ledger changed")

    @classmethod
    def capture(cls, *, action: Any, key: bytes) -> GmailRecoveryHistory:
        from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction

        if type(action) is not GmailRecoveryAction or type(key) is not bytes or len(key) != 32:
            raise ValueError("actual current-owner recovery action required")
        action.current()
        authority, configuration = action._authority, action._configuration
        configuration, account = authority._configuration(configuration, None)
        directory = _guard(authority._directory, directory=True)
        directory_identity = (
            directory.st_dev,
            directory.st_ino,
            directory.st_mode,
            directory.st_uid,
        )
        names = {p.name for p in authority._directory.iterdir()}
        if names != {authority._path.name, authority._lock_path.name, LEGACY_JOURNAL, LEGACY_SPEND}:
            raise ValueError("one exact legacy failed recovery required")
        with authority._locked() as lock_current:
            action.current()
            lock_current()
            rows = authority._read()["rows"]
            journal_raw, journal_file = _file(authority._directory, LEGACY_JOURNAL)
            _, spend_file = _file(authority._directory, LEGACY_SPEND)
            cipher, context, _, _ = history_ciphers(authority, configuration, account, key)
            record = parse_gmail_quarantine_record(
                cipher.decrypt(journal_raw[:12], journal_raw[12:], context),
                configuration=configuration,
            )
            journal, _, spend = recovery_names(
                configuration.configuration_digest, account, action._generation
            )
            descriptor = validate_history_descriptor(
                {
                    "version": 2,
                    "profile": PROFILE,
                    "configuration": configuration.configuration_digest,
                    "account": account,
                    "generation": action._generation,
                    "journal": journal,
                    "spend": spend,
                    "legacy_files": {LEGACY_JOURNAL: journal_file, LEGACY_SPEND: spend_file},
                    "state": record.state_hash,
                    "rows": rows,
                },
                configuration=configuration.configuration_digest,
                account=account,
                generation=action._generation,
            )
            identity = action._hr_principal.identity
            authenticate_history(
                descriptor,
                authority=authority,
                configuration=configuration,
                key=key,
                identity=identity,
            )
            action.current()
            lock_current()
            if {p.name for p in authority._directory.iterdir()} != names or _json(
                authority._read()["rows"]
            ) != _json(rows):
                raise ValueError("historical ledger changed during capture")
        receipt = object.__new__(cls)
        for name, value in (
            ("_authority", authority),
            ("_action", action),
            ("_key", key),
            ("_data", _json(descriptor)),
            ("_original_data", _json(descriptor)),
            ("_directory_identity", directory_identity),
            (
                "_pins",
                (
                    authority,
                    action,
                    key,
                    _json(descriptor),
                    authority._directory,
                    authority._path,
                    authority._lock_path,
                    authority._context,
                    authority._cipher,
                    authority._continuity,
                    authority._continuity._context,
                    authority._continuity._key,
                    action._configuration,
                    action._configuration.configuration_digest,
                    action._generation,
                    directory_identity,
                ),
            ),
        ):
            object.__setattr__(receipt, name, value)
        _CAPTURES[receipt] = receipt._pins
        receipt.current()
        action.current()
        if {p.name for p in authority._directory.iterdir()} != names:
            raise ValueError("exact capture namespace required")
        return receipt
