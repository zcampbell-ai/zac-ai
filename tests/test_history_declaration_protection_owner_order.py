"""Actual constructor/config + signed invented owner; no native/SQL recovery."""

import pytest

from tests.test_personal_history_factory import case as case  # noqa: PLC0414
from tests.test_personal_history_factory import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory import factory_case as factory_case  # noqa: PLC0414
from tests.test_personal_history_factory import host as host  # noqa: PLC0414
from tests.test_personal_history_factory import installed as installed  # noqa: PLC0414
from tests.test_personal_history_factory import invoke
from tests.test_personal_history_factory import post_case as post_case  # noqa: PLC0414
from tests.test_personal_history_factory import setup as setup  # noqa: PLC0414
from zacai.contextual_protection import PersonalHistoryFragmentProtector
from zacai.intelligence import history_declaration_protection as p
from zacai.intelligence.history_generation_review_declaration import decode_history_consent


@pytest.fixture
def actual_graph(factory_case):
    f = factory_case
    out = invoke(f)
    f.c.identity_path.write_bytes(b"INVENTED-NOT-AGE-IDENTITY")
    f.c.identity_path.chmod(0o600)
    actual = PersonalHistoryFragmentProtector(
        factory=f.c.factory,
        engine=f.c.engine,
        artifacts=f.c.artifacts,
        cold_artifacts=f.c.cold_artifacts,
        objects=f.c.objects,
        verification_objects=f.c.verification_objects,
        recipient="age1" + "a" * 58,
        identity_path=f.c.identity_path,
        manifest_cache=f.c.manifest_cache,
        operation=f.operation,
        clock=f.s.inputs.clock,
        restoration=f.c.restoration,
    )
    generation = decode_history_consent(out.retained.declaration.generation_consent_json.encode())
    return f, actual, generation


def test_current_actual_configuration_and_owner_are_admissible(actual_graph):
    f, actual, generation = actual_graph
    before = f.operation.establish()
    assert p._access(actual, generation, before) == before


def test_last_configuration_revocation_is_seen_by_actual_owner_check(actual_graph, monkeypatch):
    f, actual, generation = actual_graph
    before = f.operation.establish()
    configuration = PersonalHistoryFragmentProtector._configuration
    calls = []

    def callback(protector):
        configuration(protector)
        calls.append(True)
        # Exact existing legacy _access invokes2 configurations; wrapper's
        # final third check is the independently demonstrated ordering seam.
        if len(calls) == 3:
            f.s.inputs.owners.revoke()

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_configuration", callback)
    with pytest.raises(ValueError):
        p._access(actual, generation, before)
    assert len(calls) == 3
