from datetime import datetime

from fastapi.testclient import TestClient

from zacai.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert isinstance(body["version"], str) and body["version"]
    # Raises if the timestamp isn't a valid ISO-8601 datetime.
    datetime.fromisoformat(body["timestamp"])
