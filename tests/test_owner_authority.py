"""Neutral contract compatibility only; existing suites cover persistent sessions."""

import ast
from pathlib import Path

import pytest

from zacai import owner_authority as core
from zacai.interfaces import oidc_identity, private_web, session_store
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def test_legacy_and_neutral_contracts_have_exact_identity():
    assert session_store.Identity is core.Identity
    assert private_web.Identity is core.Identity
    assert private_web.BoundaryScope is core.BoundaryScope
    assert private_web.OwnerGrant is core.OwnerGrant
    assert private_web.InterfacePrincipal is core.InterfacePrincipal
    assert oidc_identity.GOOGLE_ISSUER == core.GOOGLE_ISSUER
    assert private_web.GOOGLE_ISSUER == core.GOOGLE_ISSUER


def test_neutral_module_has_no_interface_or_transport_dependency():
    tree = ast.parse(Path(core.__file__).read_text())
    imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert set(imports) == {"__future__", "dataclasses", "zacai.policy"}
    assert not any(isinstance(n, ast.Import) for n in ast.walk(tree))


@pytest.mark.parametrize("issuer", ["accounts.google.com", "https://other.example.test"])
def test_owner_grant_keeps_exact_canonical_issuer_policy(issuer):
    identity = core.Identity(issuer, "invented-owner")
    scope = core.BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL}))
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        core.OwnerGrant(identity, (scope,))


def test_legacy_and_neutral_values_share_frozen_contract_and_scope_checks():
    identity = session_store.Identity(core.GOOGLE_ISSUER, "invented-owner")
    scope = private_web.BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL}))
    assert core.OwnerGrant(identity, (scope,)) == private_web.OwnerGrant(identity, (scope,))
    with pytest.raises(AttributeError):
        identity.subject = "replacement"
    with pytest.raises(ValueError):
        core.OwnerGrant(identity, (scope, scope))
    with pytest.raises(ValueError):
        core.OwnerGrant(identity, (core.BoundaryScope(B.PERSONAL, {C.CONFIDENTIAL}),))
