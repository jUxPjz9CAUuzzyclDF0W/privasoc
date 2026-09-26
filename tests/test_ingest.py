import json

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from privasoc.api import create_app
from privasoc.config import Settings
from privasoc.store import Record, Store


@pytest.fixture
def client(tmp_path):
    s = Settings(
        api_token=SecretStr("t0k"),
        hmac_key=SecretStr("h"),
        vault_key=SecretStr("v"),
        data_dir=tmp_path,
    )
    store = Store(s.db_path)
    return TestClient(create_app(s, store)), store


def test_store_routes_unparsed_to_quarantine(tmp_path):
    st = Store(tmp_path / "x.db")
    c = st.ingest(
        [
            Record("pihole", "raw line"),
            Record("pihole", "raw 2", ecs={"event": {"kind": "event"}}, parser_id="p1"),
        ],
        auto_approve=True,
    )
    assert c == {"events": 1, "unparsed": 1, "held": 0, "dropped": 0}
    assert st.quarantine_stats()[0][:2] == ("pihole", 1)


def test_ingest_requires_token(client):
    c, _ = client
    assert c.post("/ingest", content=b"{}").status_code == 401
    assert (
        c.post("/ingest", content=b"{}", headers={"Authorization": "Bearer nope"}).status_code
        == 401
    )


def test_ingest_ndjson_from_vector(client):
    c, store = client
    body = "\n".join(
        json.dumps({"message": f"line {i}", "privasoc_source": "syslog:10.0.0.1"}) for i in range(3)
    )
    r = c.post("/ingest", content=body, headers={"Authorization": "Bearer t0k"})
    # D45: a new sender is pending and its lines are held, invisible to the quarantine
    assert r.status_code == 200 and r.json()["held"] == 3
    assert store.hosts()[0]["status"] == "pending"
    assert store.quarantine_sample("syslog:10.0.0.1", 5) == []
    store.set_host("syslog:10.0.0.1", "approved")
    assert store.quarantine_sample("syslog:10.0.0.1", 5)[0] == "line 2"


def test_ingest_rejects_garbage(client):
    c, _ = client
    r = c.post("/ingest", content=b"not json", headers={"Authorization": "Bearer t0k"})
    assert r.status_code == 400
