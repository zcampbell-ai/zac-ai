"""Opt-in isolation for tests that commit on the shared disposable PG engine.

The session-scoped D027 engine already holds its test-process advisory lock.
Only requesting this fixture resets schema; offline tests acquire no database
fixture through this module. It is not an application schema lifecycle helper.
"""

import pytest
from sqlalchemy import text

from tests.conftest import (
    _reset_test_schema,
    assert_connected_to_safe_test_database,
    assert_safe_test_database_url,
)


@pytest.fixture
def isolated_committed_factory(test_session_factory):
    engine = test_session_factory.kw["bind"]
    url = engine.url.render_as_string(hide_password=False)
    assert_safe_test_database_url(url)

    def reset():
        # Recheck the actual dedicated target before BOTH schema operations.
        with engine.connect() as connection:
            assert_connected_to_safe_test_database(
                connection.scalar(text("SELECT current_database()"))
            )
        _reset_test_schema(url, already_stamped=True)

    reset()
    try:
        yield test_session_factory
    finally:
        reset()
