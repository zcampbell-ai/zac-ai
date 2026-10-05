"""Throwaway encrypted session files only; no canonical DB, keys or network."""

import hashlib
import multiprocessing
import os
import secrets
import sqlite3
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore

NOW = datetime(2026, 10, 5, tzinfo=UTC)
IDENTITY = Identity("https://accounts.google.com", "invented-private-owner")


def transaction():
    return {
        "zac_nonce": "N" * 43,
        "_state_google_" + "S" * 30: {
            "exp": 1_800_000_000.0,
            "data": {
                "nonce": "N" * 43,
                "code_verifier": "V" * 48,
                "redirect_uri": "https://zac.example.test/auth/callback",
                "url": "https://accounts.google.com/invented",
            },
        },
    }


def rows(directory):
    with sqlite3.connect(directory / "sessions.sqlite") as connection:
        return connection.execute(
            "SELECT digest,kind,issued,seen,expires,sealed FROM sessions"
        ).fetchall()


def consume_in_process(directory, key, token):
    # Spawned child receives only throwaway test credentials over multiprocessing
    # IPC; no shell argv/environment/key file or live service is involved.
    return SqliteSessionStore(directory, key=key).consume_login(token, NOW)


@pytest.fixture
def setup(tmp_path):
    directory, key = tmp_path / "operational-auth", secrets.token_bytes(32)
    return directory, key, SqliteSessionStore(directory, key=key)


def test_restart_retains_user_session_without_plaintext_secrets(setup):
    directory, key, store = setup
    token = store.start_user(IDENTITY, NOW)
    first = store.user(token, NOW + timedelta(seconds=1))
    assert first.identity == IDENTITY
    reopened = SqliteSessionStore(directory, key=key)
    second = reopened.user(token, NOW + timedelta(seconds=2))
    assert second.identity == IDENTITY and second.csrf == first.csrf
    row = rows(directory)[0]
    assert row[0] == hashlib.sha256(token.encode()).hexdigest()
    raw = (directory / "sessions.sqlite").read_bytes()
    for private in (token.encode(), key, first.csrf.encode(), IDENTITY.subject.encode()):
        assert private not in raw
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "sessions.sqlite").stat().st_mode & 0o777 == 0o600
    assert not list(directory.glob("*-wal")) and not list(directory.glob("*-journal"))


def test_fresh_nonce_for_each_write_and_metadata_binding(setup):
    directory, _, store = setup
    token = store.start_user(IDENTITY, NOW)
    before = rows(directory)[0]
    store.user(token, NOW + timedelta(seconds=1))
    after = rows(directory)[0]
    assert before[5][:12] != after[5][:12]
    assert before[3] != after[3] and before[4] == after[4]


@pytest.mark.parametrize("column", ["issued", "seen", "expires"])
def test_tampered_metadata_rejects_with_closed_errors(setup, column):
    directory, _, store = setup
    token = store.start_user(IDENTITY, NOW)
    with sqlite3.connect(directory / "sessions.sqlite") as connection:
        # Constant parametrized column allowlist, never supplied by clients.
        connection.execute(f"UPDATE sessions SET {column}={column}+1")
    with pytest.raises(ValueError, match="^session store unavailable$") as error:
        store.user(token, NOW)
    assert error.value.__context__ is None


def test_wrong_key_and_swapped_row_payload_never_release_identity(setup):
    directory, _, store = setup
    one = store.start_user(IDENTITY, NOW)
    two = store.start_user(Identity(IDENTITY.issuer, "different-invented-owner"), NOW)
    with pytest.raises(ValueError, match="^session store unavailable$"):
        SqliteSessionStore(directory, key=secrets.token_bytes(32)).user(one, NOW)
    records = rows(directory)
    first = next(row for row in records if row[0] == hashlib.sha256(one.encode()).hexdigest())
    second = next(row for row in records if row[0] == hashlib.sha256(two.encode()).hexdigest())
    with sqlite3.connect(directory / "sessions.sqlite") as connection:
        connection.execute("UPDATE sessions SET sealed=? WHERE digest=?", (first[5], second[0]))
    with pytest.raises(ValueError, match="^session store unavailable$"):
        store.user(two, NOW)


def test_transaction_is_sealed_bounded_and_consumed_once_across_processes(setup):
    directory, key, store = setup
    data = transaction()
    token = store.start_login(data, NOW)
    raw = (directory / "sessions.sqlite").read_bytes()
    assert ("N" * 43).encode() not in raw and ("V" * 48).encode() not in raw
    with ProcessPoolExecutor(
        max_workers=2, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        a = pool.submit(consume_in_process, directory, key, token)
        b = pool.submit(consume_in_process, directory, key, token)
        results = [a.result(timeout=15), b.result(timeout=15)]
    assert results.count(None) == 1
    consumed = next(value for value in results if value is not None)
    assert consumed["zac_nonce"] == data["zac_nonce"]
    state = next(value for name, value in consumed.items() if name != "zac_nonce")
    assert "url" not in state["data"]
    assert not rows(directory)


@pytest.mark.parametrize("bad", ["access_token", "id_token", "grants", "source_context"])
def test_provider_tokens_and_context_cannot_enter_login_storage(setup, bad):
    directory, _, store = setup
    data = transaction()
    data[bad] = "invented secret or context"
    with pytest.raises(ValueError, match="^session store unavailable$") as error:
        store.start_login(data, NOW)
    assert not rows(directory) and error.value.__context__ is None


def test_expiry_revocation_and_regressed_clock_survive_reopen(setup):
    directory, key, store = setup
    token = store.start_login(transaction(), NOW)
    assert (
        SqliteSessionStore(directory, key=key).consume_login(token, NOW + timedelta(minutes=5))
        is None
    )
    token = store.start_user(IDENTITY, NOW)
    assert store.user(token, NOW - timedelta(seconds=1)) is None
    assert SqliteSessionStore(directory, key=key).user(token, NOW) is None
    one = store.start_user(IDENTITY, NOW)
    other = store.start_user(Identity(IDENTITY.issuer, "other"), NOW)
    SqliteSessionStore(directory, key=key).revoke_identity(IDENTITY)
    assert store.user(one, NOW) is None and store.user(other, NOW) is not None
    store.revoke(other)
    assert SqliteSessionStore(directory, key=key).user(other, NOW) is None


def test_idle_and_absolute_expiry_are_server_enforced(setup):
    directory, key, _ = setup
    store = SqliteSessionStore(
        directory, key=key, idle=timedelta(minutes=30), lifetime=timedelta(hours=1)
    )
    token = store.start_user(IDENTITY, NOW)
    for minute in (20, 40, 59):
        assert store.user(token, NOW + timedelta(minutes=minute)) is not None
    assert store.user(token, NOW + timedelta(hours=1)) is None
    token = store.start_user(IDENTITY, NOW)
    assert store.user(token, NOW + timedelta(minutes=30)) is None


def test_atomic_capacity_across_separate_instances(setup):
    directory, key, _ = setup
    stores = [SqliteSessionStore(directory, key=key, capacity=1) for _ in range(2)]

    def create(store):
        try:
            return store.start_user(IDENTITY, NOW)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, stores))
    assert results.count(None) == 1 and len(rows(directory)) == 1
    store = stores[0]
    assert store.start_user(IDENTITY, NOW + timedelta(hours=8))
    assert len(rows(directory)) == 1


@pytest.mark.parametrize(
    "unsafe",
    ["directory_mode", "file_mode", "directory_symlink", "file_symlink", "hardlink", "schema"],
)
def test_unsafe_existing_store_path_and_schema_reject(setup, tmp_path, unsafe):
    directory, key, _ = setup
    path = directory / "sessions.sqlite"
    if unsafe == "directory_mode":
        directory.chmod(0o755)
    elif unsafe == "file_mode":
        path.chmod(0o644)
    elif unsafe == "directory_symlink":
        link = tmp_path / "directory-link"
        link.symlink_to(directory, target_is_directory=True)
        directory = link
    elif unsafe == "file_symlink":
        actual = directory / "real.sqlite"
        path.rename(actual)
        path.symlink_to(actual)
    elif unsafe == "hardlink":
        os.link(path, directory / "extra-link.sqlite")
    else:
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="^session store unavailable$") as error:
        SqliteSessionStore(directory, key=key)
    assert error.value.__context__ is None


def test_corruption_and_naive_time_never_return_a_session(setup):
    directory, _, store = setup
    token = store.start_user(IDENTITY, NOW)
    with sqlite3.connect(directory / "sessions.sqlite") as connection:
        connection.execute("UPDATE sessions SET sealed=?", (b"corrupt",))
    with pytest.raises(ValueError, match="^session store unavailable$"):
        store.user(token, NOW)
    with pytest.raises(ValueError, match="invalid session time"):
        store.user(token, NOW.replace(tzinfo=None))


@pytest.mark.asyncio
async def test_actual_authlib_transaction_survives_encrypted_reopen(setup, monkeypatch):
    import time
    from urllib.parse import parse_qs, urlencode, urlsplit

    import httpx
    from joserfc import jwt
    from joserfc.jwk import RSAKey
    from starlette.requests import Request

    from zacai.interfaces.oidc_identity import AuthlibGoogleIdentity

    async def denied(*args, **kwargs):
        raise AssertionError("synthetic auth must not make network requests")

    monkeypatch.setattr(httpx.AsyncClient, "request", denied)
    directory, key, store = setup
    provider = AuthlibGoogleIdentity(client_id="invented-client", client_secret="invented-secret")

    def request(data, query=b""):
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/auth/callback",
                "query_string": query,
                "headers": [],
                "scheme": "https",
                "session": data,
            }
        )

    begin = request({})
    response = await provider.begin(begin, "https://zac.example.test/auth/callback")
    args = parse_qs(urlsplit(response.headers["location"]).query)
    token = store.start_login(begin.session, NOW)
    recovered = SqliteSessionStore(directory, key=key).consume_login(token, NOW)
    assert recovered is not None
    assert SqliteSessionStore(directory, key=key).consume_login(token, NOW) is None
    signing_key = RSAKey.generate_key(2048)
    provider._client.server_metadata["jwks"] = {"keys": [signing_key.as_dict(private=False)]}
    signed = jwt.encode(
        {"alg": "RS256"},
        {
            "iss": IDENTITY.issuer,
            "sub": IDENTITY.subject,
            "aud": "invented-client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 120,
            "nonce": args["nonce"][0],
        },
        signing_key,
    )

    async def exchange(**kwargs):
        assert len(kwargs["code_verifier"]) >= 43
        assert kwargs["redirect_uri"] == "https://zac.example.test/auth/callback"
        return {"access_token": "invented-token", "token_type": "Bearer", "id_token": signed}

    monkeypatch.setattr(provider._client, "fetch_access_token", exchange)
    callback = request(
        recovered, urlencode({"code": "invented-code", "state": args["state"][0]}).encode()
    )
    assert await provider.finish(callback) == IDENTITY


def test_pending_flood_evicts_only_oldest_and_reserves_authenticated_capacity(setup):
    directory, key, _ = setup
    store = SqliteSessionStore(directory, key=key, capacity=2)
    first = store.start_login(transaction(), NOW)
    second = store.start_login(transaction(), NOW + timedelta(seconds=1))
    owner = store.start_user(IDENTITY, NOW + timedelta(seconds=1))
    reopened = SqliteSessionStore(directory, key=key, capacity=2)
    third = reopened.start_login(transaction(), NOW + timedelta(seconds=2))
    assert len(rows(directory)) == 3
    assert reopened.consume_login(first, NOW + timedelta(seconds=2)) is None
    assert reopened.consume_login(second, NOW + timedelta(seconds=2)) is not None
    assert reopened.consume_login(third, NOW + timedelta(seconds=2)) is not None
    assert reopened.user(owner, NOW + timedelta(seconds=2)).identity == IDENTITY


def test_corrupt_row_cannot_roll_back_other_identity_revocation(setup):
    directory, key, store = setup
    corrupt = store.start_user(Identity(IDENTITY.issuer, "corrupt-other"), NOW)
    owner = store.start_user(IDENTITY, NOW)
    unaffected = store.start_user(Identity(IDENTITY.issuer, "valid-other"), NOW)
    with sqlite3.connect(directory / "sessions.sqlite") as connection:
        connection.execute(
            "UPDATE sessions SET sealed=? WHERE digest=?",
            (b"corrupt", hashlib.sha256(corrupt.encode()).hexdigest()),
        )
    SqliteSessionStore(directory, key=key).revoke_identity(IDENTITY)
    assert store.user(owner, NOW) is None
    assert store.user(corrupt, NOW) is None
    assert store.user(unaffected, NOW).identity.subject == "valid-other"


def test_wrong_key_revocation_fails_closed_by_deleting_undecryptable_users(setup):
    directory, _, store = setup
    owner = store.start_user(IDENTITY, NOW)
    other = store.start_user(Identity(IDENTITY.issuer, "other"), NOW)
    wrong_key_store = SqliteSessionStore(directory, key=secrets.token_bytes(32))
    wrong_key_store.revoke_identity(IDENTITY)
    assert store.user(owner, NOW) is None and store.user(other, NOW) is None
    assert not rows(directory)
