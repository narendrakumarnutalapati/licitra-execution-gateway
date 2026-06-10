def test_healthz_returns_200(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_healthz_has_mmr_root(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "mmr_root" in r.json()


def test_metrics_endpoint_returns_200(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "total_verifications" in r.json()
