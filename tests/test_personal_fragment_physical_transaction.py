"""Actual issuer condition code; physical driver/SQL are explicitly simulated.

No psycopg connection or query is made. Root's genuine RC/AUTOCOMMIT controls
are required to establish actual driver and advisory-lock behavior.
"""
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.pq import TransactionStatus

from zacai import contextual_authorization as m


@pytest.mark.parametrize('autocommit,status,closed,broken,logical,expected', [
    (False,TransactionStatus.INTRANS,False,False,True,True),
    (True,TransactionStatus.INTRANS,False,False,True,False),
    (True,TransactionStatus.IDLE,False,False,True,False),
    (False,TransactionStatus.IDLE,False,False,True,False),
    (False,TransactionStatus.INERROR,False,False,True,False),
    (False,TransactionStatus.INTRANS,True,False,True,False),
    (False,TransactionStatus.INTRANS,False,True,True,False),
    (False,TransactionStatus.INTRANS,False,False,False,False),
])
def test_exact_physical_transaction_condition(autocommit,status,closed,broken,logical,expected,monkeypatch):
    class InventedDriver:
        pass
    driver=InventedDriver()
    driver.autocommit=autocommit
    driver.info=SimpleNamespace(transaction_status=status)
    driver.closed,driver.broken=closed,broken
    connection=SimpleNamespace(connection=SimpleNamespace(driver_connection=driver),
        in_transaction=lambda:logical)
    session=SimpleNamespace(connection=lambda:connection)
    outer=object()
    monkeypatch.setattr(m,'_fragment_transaction',lambda s:(outer,None))
    monkeypatch.setattr(psycopg,'Connection',InventedDriver)
    # The method does not use self. Invoke its exact frozen code directly.
    method=m.CanonicalPersonalFragmentAuthorization._physical_transaction
    if expected:
        assert method(None,session)==(outer,None,connection,driver)
    else:
        with pytest.raises(ValueError,match='physical psycopg transaction'):
            method(None,session)


def test_unrecognized_driver_cannot_supply_success_properties(monkeypatch):
    driver=SimpleNamespace(autocommit=False,closed=False,broken=False,
        info=SimpleNamespace(transaction_status=TransactionStatus.INTRANS))
    connection=SimpleNamespace(connection=SimpleNamespace(driver_connection=driver),
        in_transaction=lambda:True)
    monkeypatch.setattr(m,'_fragment_transaction',lambda s:(object(),None))
    with pytest.raises(ValueError,match='physical psycopg transaction'):
        m.CanonicalPersonalFragmentAuthorization._physical_transaction(None,
            SimpleNamespace(connection=lambda:connection))
