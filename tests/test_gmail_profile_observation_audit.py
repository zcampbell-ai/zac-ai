"""Original profile issuance pins survive late clock callbacks, with invented data."""

import pytest

from tests.test_oauth_exchange import Fixture, safe
from zacai.connectors.oauth_exchange import OAuthExchangeError


@pytest.mark.parametrize(
    "replacement", ["authority", "configuration", "named_operation", "backend"]
)
def test_final_observation_clock_cannot_rebaseline_original_graph(
    tmp_path, monkeypatch, replacement
):
    f = Fixture(tmp_path)
    observed_at = f.operation.observed_at
    replaced = False

    def late_observation():
        nonlocal replaced
        result = observed_at()
        # Only the final explicit observation follows the existing profile call.
        if len(f.calls) == 3 and not replaced:
            replaced = True
            if replacement == "authority":
                f.operation._authority = f.transactions.reopen()
            elif replacement == "configuration":
                f.operation._configuration = f.operation._configuration.model_copy()
            elif replacement == "named_operation":
                f.operation._operation = f.transactions.sessions.continuity.for_cookie(
                    f.transactions.sessions.cookie
                )
            else:
                original = f.operation._authority._backend
                duplicate = type(original)()
                duplicate.current = original.current
                f.operation._authority._backend = duplicate
        return result

    monkeypatch.setattr(f.operation, "observed_at", late_observation)
    with pytest.raises(OAuthExchangeError) as raised:
        f.execute()
    safe(raised.value)
    assert replaced
    assert len(f.calls) == 3
    assert all(connection.closed for connection in f.connections)
    assert f.row()["state"] == "held"
