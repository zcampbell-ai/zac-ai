"""Closed bounded terminal history: preserved evidence, never remote-grant proof."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, cast

from zacai.connectors.connector_authority import _guard, _json, _pairs
from zacai.connectors.gmail_quarantine_record import parse_gmail_quarantine_record
from zacai.connectors.gmail_recovery_history import (
    _CAPTURES,
    LEGACY_JOURNAL,
    LEGACY_SPEND,
    GmailRecoveryHistory,
    _file,
    authenticate_history,
    history_ciphers,
    recovery_names,
)

PROFILE = "terminal_chain_v3"
ABSENCE_PROFILE = "terminal_native_absence_v4"
MAX_EPOCHS = 3  # retained suffixed epochs; one new current epoch is additional
MAX_ROWS = 8
MAX_DESCRIPTOR = 60000
NAME = re.compile(r" gmail".strip() + r"-quarantine-intent-([0-9a-f]{32})\.bin")


def namespace_pairs(names: set[str], *, maximum: int = MAX_EPOCHS) -> bool:
    """Syntax only. No reads, authentication or authority granted."""
    journals = [name for name in names if NAME.fullmatch(name)]
    expected: set[str] = set()
    for name in journals:
        matched = NAME.fullmatch(name)
        assert matched is not None
        suffix = matched[1]
        expected.update((name, "gmail-recovery-attempt-" + suffix + ".bin"))
    return 1 <= len(journals) <= maximum and names == expected


def validate(value: Any, *, configuration: str, account: str, generation: str) -> dict[str, Any]:
    from zacai.connectors.gmail_recovery_history import validate_history_descriptor

    if type(value) is not dict or set(value) != (
        {
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
            "epochs",
        }
        | ({"native_absence_observations"} if value.get("profile") == ABSENCE_PROFILE else set())
    ):
        raise ValueError("closed terminal history required")
    if (
        type(value["version"]) is not int
        or value["profile"] not in {PROFILE, ABSENCE_PROFILE}
        or value["version"] != (4 if value["profile"] == ABSENCE_PROFILE else 3)
    ):
        raise ValueError("closed terminal version required")
    files, epochs = value["legacy_files"], value["epochs"]
    if type(files) is not dict or type(epochs) is not list or not 1 <= len(epochs) <= MAX_EPOCHS:
        raise ValueError("bounded terminal epochs required")
    if not namespace_pairs(set(files) - {LEGACY_JOURNAL, LEGACY_SPEND}):
        raise ValueError("complete terminal pairs required")
    expected = {LEGACY_JOURNAL, LEGACY_SPEND}
    generations = set()
    for epoch in epochs:
        if type(epoch) is not dict or set(epoch) != {
            "generation",
            "journal",
            "spend",
            "history_sha256",
        }:
            raise ValueError("closed terminal epoch required")
        prior = epoch["generation"]
        if type(prior) is not str or prior == generation or prior in generations:
            raise ValueError("distinct terminal generation required")
        journal, _, spend = recovery_names(configuration, account, prior)
        if (
            epoch["journal"] != journal
            or epoch["spend"] != spend
            or type(epoch["history_sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", epoch["history_sha256"]) is None
        ):
            raise ValueError("exact terminal correlations required")
        generations.add(prior)
        expected.update((journal, spend))
    if set(files) != expected or len(_json(value)) > MAX_DESCRIPTOR:
        raise ValueError("exact bounded terminal file map required")
    # Reuse v2 closed correlation/row/witness grammar for the legacy subset,
    # while validating every extra file with the identical witness grammar.
    base = {k: v for k, v in value.items() if k not in {"epochs", "native_absence_observations"}}
    base.update(
        version=2,
        profile="legacy_repeat_v2",
        legacy_files={k: files[k] for k in (LEGACY_JOURNAL, LEGACY_SPEND)},
    )
    validate_history_descriptor(
        base, configuration=configuration, account=account, generation=generation
    )
    for entry in files.values():
        if (
            type(entry) is not dict
            or set(entry) != {"sha256", "witness"}
            or type(entry["sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", entry["sha256"]) is None
            or type(entry["witness"]) is not list
            or len(entry["witness"]) != 8
            or any(type(v) is not int or v < 0 for v in entry["witness"])
        ):
            raise ValueError("exact terminal witness required")
    if value["profile"] == ABSENCE_PROFILE:
        from zacai.connectors.gmail_recovery_native_absence import validate_observations

        validate_observations(value["native_absence_observations"])
        if len(_json(value)) > 48_000:
            raise ValueError("bounded native history required")
    result: dict[str, Any] = json.loads(_json(value), object_pairs_hook=_pairs)
    return result


def authenticate(
    value: dict[str, Any],
    *,
    authority: Any,
    configuration: Any,
    key: bytes,
    identity: Any,
    reconciliation_only: bool = False,
) -> list[tuple[str, str]]:
    configuration, account = authority._configuration(configuration, None)
    targets: list[tuple[str, str]] = []
    checked = validate(
        value,
        configuration=configuration.configuration_digest,
        account=account,
        generation=value["generation"],
    )
    jc, ctx, sc, sctx = history_ciphers(authority, configuration, account, key)
    previous_files = {k: checked["legacy_files"][k] for k in (LEGACY_JOURNAL, LEGACY_SPEND)}
    previous_rows = None
    published_observations: list[dict[str, Any]] = []
    for epoch in checked["epochs"]:
        raw, witness = _file(
            authority._directory,
            epoch["journal"],
            expected=checked["legacy_files"][epoch["journal"]],
        )
        spent_raw, sw = _file(
            authority._directory, epoch["spend"], expected=checked["legacy_files"][epoch["spend"]]
        )
        record = parse_gmail_quarantine_record(
            jc.decrypt(raw[:12], raw[12:], ctx), configuration=configuration
        )
        history: Any = record.history
        plain = sc.decrypt(spent_raw[:12], spent_raw[12:], sctx)
        spent = json.loads(plain, object_pairs_hook=_pairs)
        if (
            type(spent) is not dict
            or set(spent)
            != {
                "version",
                "history_sha256",
                "state",
                "configuration",
                "old_state",
                "old_row",
                "journal",
                "hr_binding",
                "original_binding",
                "generation",
            }
            or type(spent["version"]) is not int
            or spent["version"] != 2
            or _json(spent) != plain
        ):
            raise ValueError("closed terminal spend required")
        if (
            history is None
            or record.version != 2
            or history["legacy_files"] != previous_files
            or history["generation"] != epoch["generation"]
            or hashlib.sha256(_json(history)).hexdigest() != epoch["history_sha256"]
        ):
            raise ValueError("exact terminal predecessor commitment required")
        if previous_rows is None:
            if history["profile"] != "legacy_repeat_v2":
                raise ValueError("original legacy predecessor required")
            authenticate_history(
                history,
                authority=authority,
                configuration=configuration,
                key=key,
                identity=identity,
            )
        elif (
            history["rows"] != previous_rows
            or history.get("epochs") != checked["epochs"][: checked["epochs"].index(epoch)]
        ):
            raise ValueError("exact predecessor row snapshot required")
        if (
            spent["history_sha256"] != epoch["history_sha256"]
            or spent["state"] != "spent"
            or spent["configuration"] != configuration.configuration_digest
            or spent["old_state"] != record.state_hash
            or spent["old_row"] != hashlib.sha256(record.original_row_bytes).hexdigest()
            or spent["journal"] != hashlib.sha256(raw).hexdigest()
            or spent["generation"] != epoch["generation"]
            or record.review_generation_claim != epoch["generation"]
            or spent["hr_binding"] != record.reviewer_binding_claim
            or record.reviewer_issuer_hint != identity.issuer
            or record.reviewer_subject_hint != identity.subject
            or any(
                type(spent[k]) is not str or re.fullmatch("[0-9a-f]{64}", spent[k]) is None
                for k in ("hr_binding", "original_binding")
            )
        ):
            raise ValueError("authenticated terminal owner chain required")
        if history.get("profile") == ABSENCE_PROFILE:
            from zacai.connectors.gmail_recovery_native_absence import recorded_observations

            recorded_observations(history, record, spent, published_observations)
            published_observations = history["native_absence_observations"]
        # Exactly one row belongs to this spent epoch. It must have no native
        # stage acknowledgement. A loaded fresh row needs separate reconciliation.
        snapshot: Any = checked["rows"] if epoch is checked["epochs"][-1] else None
        if snapshot is None:
            next_epoch = checked["epochs"][checked["epochs"].index(epoch) + 1]
            next_raw, _ = _file(
                authority._directory,
                next_epoch["journal"],
                expected=checked["legacy_files"][next_epoch["journal"]],
            )
            next_record = parse_gmail_quarantine_record(
                jc.decrypt(next_raw[:12], next_raw[12:], ctx), configuration=configuration
            )
            if next_record.history is None:
                raise ValueError("exact next predecessor required")
            snapshot = next_record.history["rows"]
        inherited = history.get("native_absence_observations", [])
        for observation in inherited:
            if (
                observation not in checked.get("native_absence_observations", [])
                and not reconciliation_only
            ):
                raise ValueError("immutable historical native observation required")
        old = history["rows"]
        added = set(snapshot) - set(old)
        if len(added) != 1 or any(snapshot.get(s) != row for s, row in old.items()):
            raise ValueError("one exact terminal row per epoch required")
        state_hash = next(iter(added))
        row = snapshot[state_hash]
        if (
            row["binding"] != spent["hr_binding"]
            or row["configuration"] != configuration.configuration_digest
            or row["account"] != account
            or row["state"] not in {"held", "denied"}
            or row["verifier"] is not None
            or (
                row["loaded"] is not False
                and (
                    row["state"] != "held"
                    or type(row["execution"]) is not str
                    or re.fullmatch("[0-9a-f]{64}", row["execution"]) is None
                )
            )
            or row["rotation"] is not None
        ):
            raise ValueError("unresolved native or transaction outcome requires review")
        if row["loaded"]:
            targets.append((epoch["generation"], state_hash))
            if not reconciliation_only:
                if checked["profile"] != ABSENCE_PROFILE:
                    raise ValueError("unresolved native outcome requires review")
                observations = [
                    o for o in checked["native_absence_observations"] if o["state"] == state_hash
                ]
                if len(observations) != 1:
                    raise ValueError("exact historical native observation required")
                observation = observations[0]
                if (
                    observation["epoch_generation"] != epoch["generation"]
                    or observation["row_sha256"] != hashlib.sha256(_json(row)).hexdigest()
                    or observation["configuration"] != configuration.configuration_digest
                    or observation["account"] != account
                    or observation["issuer"] != identity.issuer
                    or observation["subject"] != identity.subject
                ):
                    raise ValueError("exact native observation epoch required")
        previous_rows = snapshot
        previous_files = previous_files | {epoch["journal"]: witness, epoch["spend"]: sw}
    if previous_files != checked["legacy_files"] or previous_rows != checked["rows"]:
        raise ValueError("complete authenticated terminal chain required")
    if (
        not reconciliation_only
        and checked["profile"] == ABSENCE_PROFILE
        and {o["state"] for o in checked["native_absence_observations"]} != {s for _, s in targets}
    ):
        raise ValueError("exact eligible suffixed native observations required")
    return targets


def capture(*, action: Any, key: bytes) -> GmailRecoveryHistory:
    from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAction

    if type(action) is not GmailRecoveryAction or type(key) is not bytes or len(key) != 32:
        raise ValueError("actual fresh terminal-chain action required")
    action.current()
    authority, configuration = action._authority, action._configuration
    configuration, account = authority._configuration(configuration, None)
    directory = _guard(authority._directory, directory=True)
    directory_identity = (directory.st_dev, directory.st_ino, directory.st_mode, directory.st_uid)
    names = {p.name for p in authority._directory.iterdir()}
    extra = names - {authority._path.name, authority._lock_path.name, LEGACY_JOURNAL, LEGACY_SPEND}
    if not namespace_pairs(extra) or not {LEGACY_JOURNAL, LEGACY_SPEND} <= names:
        raise ValueError("complete bounded terminal namespace required")
    with authority._locked() as lock_current:
        action.current()
        lock_current()
        rows = authority._read()["rows"]
        if len(rows) >= MAX_ROWS:
            raise ValueError("terminal capacity must reserve one fresh row")
        files = {
            name: _file(authority._directory, name)[1]
            for name in sorted(names - {authority._path.name, authority._lock_path.name})
        }
        jc, ctx, _, _ = history_ciphers(authority, configuration, account, key)
        epochs = []
        state = None
        for name in sorted(extra):
            if NAME.fullmatch(name) is None:
                continue
            raw, _ = _file(authority._directory, name, expected=files[name])
            record = parse_gmail_quarantine_record(
                jc.decrypt(raw[:12], raw[12:], ctx), configuration=configuration
            )
            if record.history is None:
                raise ValueError("authenticated predecessor required")
            generation = record.review_generation_claim
            journal, _, spend = recovery_names(
                configuration.configuration_digest, account, generation
            )
            if journal != name:
                raise ValueError("exact terminal filename required")
            epochs.append(
                (
                    len(cast(dict[str, Any], record.history)["legacy_files"]),
                    {
                        "generation": generation,
                        "journal": journal,
                        "spend": spend,
                        "history_sha256": hashlib.sha256(_json(record.history)).hexdigest(),
                    },
                )
            )
            state = record.state_hash if state is None else state
            if state != record.state_hash:
                raise ValueError("same original preserved row required")
        epochs.sort(key=lambda item: item[0])
        journal, _, spend = recovery_names(
            configuration.configuration_digest, account, action._generation
        )
        native_profile = action._join._host._recovery_profile == ABSENCE_PROFILE
        descriptor = validate(
            {
                "version": 4 if native_profile else 3,
                "profile": ABSENCE_PROFILE if native_profile else PROFILE,
                "configuration": configuration.configuration_digest,
                "account": account,
                "generation": action._generation,
                "journal": journal,
                "spend": spend,
                "legacy_files": files,
                "state": state,
                "rows": rows,
                "epochs": [item[1] for item in epochs],
                **({"native_absence_observations": []} if native_profile else {}),
            },
            configuration=configuration.configuration_digest,
            account=account,
            generation=action._generation,
        )
        authenticate(
            descriptor,
            authority=authority,
            configuration=configuration,
            key=key,
            identity=action._hr_principal.identity,
            reconciliation_only=native_profile,
        )
        action.current()
        lock_current()
        if {p.name for p in authority._directory.iterdir()} != names or authority._read()[
            "rows"
        ] != rows:
            raise ValueError("terminal capture changed")
    capabilities = []
    if native_profile:
        from zacai.connectors.gmail_recovery_native_absence import inspect_epoch

        targets = authenticate(
            descriptor,
            authority=authority,
            configuration=configuration,
            key=key,
            identity=action._hr_principal.identity,
            reconciliation_only=True,
        )
        inherited_observations = []
        # Historical observations remain immutable; current capabilities independently inspect ALL eligible rows.
        for epoch in descriptor["epochs"]:
            raw, _ = _file(authority._directory, epoch["journal"], expected=files[epoch["journal"]])
            record = parse_gmail_quarantine_record(
                jc.decrypt(raw[:12], raw[12:], ctx), configuration=configuration
            )
            if record.history is not None:
                for observation in cast(dict[str, Any], record.history).get(
                    "native_absence_observations", []
                ):
                    if observation not in inherited_observations:
                        inherited_observations.append(observation)
        for epoch, selected_state in targets:
            capability = inspect_epoch(
                action=action, descriptor=descriptor, key=key, epoch=epoch, state=selected_state
            )
            capabilities.append(capability)
            if not any(o["state"] == selected_state for o in inherited_observations):
                inherited_observations.append(json.loads(capability._record_bytes))
        descriptor["native_absence_observations"] = inherited_observations
        authenticate(
            descriptor,
            authority=authority,
            configuration=configuration,
            key=key,
            identity=action._hr_principal.identity,
        )
    receipt = object.__new__(GmailRecoveryHistory)
    for name, value in (
        ("_authority", authority),
        ("_action", action),
        ("_key", key),
        ("_data", _json(descriptor)),
        ("_original_data", _json(descriptor)),
        ("_directory_identity", directory_identity),
    ):
        object.__setattr__(receipt, name, value)
    pins = (authority, action, key, receipt._data, *receipt._graph())
    object.__setattr__(receipt, "_pins", pins)
    _CAPTURES[receipt] = pins
    if native_profile:
        from zacai.connectors.gmail_recovery_native_absence import attach_capabilities

        attach_capabilities(receipt, capabilities)
    receipt.current()
    action.current()
    if {p.name for p in authority._directory.iterdir()} != names:
        raise ValueError("original terminal names required")
    return receipt
