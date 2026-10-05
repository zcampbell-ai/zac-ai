"""Invented connections: schema drift denies before source rows/COPY access."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.engine import make_url

from zacai import review_protection as module


@pytest.mark.parametrize("which", ["live", "restored"])
@pytest.mark.parametrize("drift", ["extra", "missing", "duplicate", "nonpublic"])
def test_actual_selected_source_schema_drift_denied_before_row_access(which, drift):
    calls = []

    class Connection:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, query):
            statement = str(query)
            calls.append((self.name, statement))
            if statement.startswith("SET "):
                return None
            assert "information_schema.columns" in statement
            assert "table_schema = current_schema()" in statement
            assert "table_schema = 'public'" in statement
            values = list(module._SELECTED_SOURCE_COLUMNS)
            if self.name == which:
                if drift == "extra":
                    values.append("invented_unknown_column")
                elif drift == "missing":
                    values.remove("excerpt")
                elif drift == "duplicate":
                    values.append("excerpt")
                else:
                    values = []
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: values))

        def scalar(self, statement):
            if str(statement) == "SELECT current_database()":
                return "zacai_test" if self.name == "live" else "zacai_restore_test"
            pytest.fail("schema drift must deny before row query")

    current = SimpleNamespace(
        url=make_url("postgresql+psycopg://127.0.0.1:5432/zacai_test"),
        connect=lambda: Connection("live"),
    )
    restored = SimpleNamespace(
        url=make_url("postgresql+psycopg://127.0.0.1:5432/zacai_restore_test"),
        connect=lambda: Connection("restored"),
    )
    with pytest.raises(ValueError, match="actual selected provenance schema"):
        module._verify_selected_source_rows(restored, current, {uuid4(): "a" * 64})
    # Normalized formatting and schema discovery share each owned read-only
    # transaction. Failure cannot silently omit a field or read private rows.
    for name in {name for name, _ in calls}:
        seen = [sql for found, sql in calls if found == name]
        assert seen[:3] == [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "SET LOCAL TIME ZONE 'UTC'",
            "SET LOCAL DateStyle = 'ISO, YMD'",
        ]
