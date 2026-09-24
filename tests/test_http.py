"""HTTP-level tests for the FastAPI application."""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def payload(**over):
    p = {
        "nodes": ["R", "A", "B", "C", "T1", "T2"],
        "root": "R",
        "terminals": ["T1", "T2"],
        "edges": [
            ["R", "A"], ["R", "B"],
            ["A", "C"], ["B", "C"], ["C", "T1"],
        ],
    }
    p.update(over)
    return p


def test_health_reports_available(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "available"


def test_audit_diamond(client):
    resp = client.post("/api/audit", json=payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["unreachable_terminals"] == ["T2"]
    critical = {c["node"]: c["dominated_terminals"] for c in body["critical_relays"]}
    assert critical == {"C": 1}
    idom = {d["node"]: d["immediate_dominator"] for d in body["dominators"]}
    assert idom["C"] == "R"  # diamond bypass protects the merge point


def test_audit_serial(client):
    resp = client.post("/api/audit", json=payload(
        edges=[["R", "A"], ["A", "B"], ["B", "T1"]]
    ))
    assert resp.status_code == 200
    critical = {c["node"]: c["dominated_terminals"]
                for c in resp.json()["critical_relays"]}
    assert critical == {"A": 1, "B": 1}


def test_audit_parallel_edges(client):
    resp = client.post("/api/audit", json=payload(
        edges=[["R", "A"], ["R", "A"], ["A", "T1"]]
    ))
    assert resp.status_code == 200
    critical = {c["node"]: c["dominated_terminals"]
                for c in resp.json()["critical_relays"]}
    assert critical == {"A": 1}


def test_audit_wide_merge_bypass(client):
    # Same emergency beam-stop topology as the audit acceptance test,
    # submitted over HTTP: R->A->M plus 96 independent R->S<i>->M bypass
    # paths, then 97 protected terminals behind M.
    bypass_count = 96
    bypasses = [f"S{i:02d}" for i in range(bypass_count)]
    terminals = [f"T{j:02d}" for j in range(bypass_count + 1)]
    nodes = ["R", "A", "M", *bypasses, *terminals]
    edges = [["R", "A"], ["A", "M"]]
    for s in bypasses:
        edges += [["R", s], [s, "M"]]
    edges += [["M", t] for t in terminals]

    resp = client.post("/api/audit", json={
        "nodes": nodes, "root": "R", "terminals": terminals, "edges": edges,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()

    idom = {d["node"]: d["immediate_dominator"] for d in body["dominators"]}
    assert idom["M"] == "R"
    assert idom["A"] == "R"
    for s in bypasses:
        assert idom[s] == "R"
    for t in terminals:
        assert idom[t] == "M"

    critical = {c["node"]: c["dominated_terminals"]
                for c in body["critical_relays"]}
    assert critical == {"M": 97}

    assert body["reachable_node_count"] == len(nodes)
    assert body["unreachable_terminals"] == []
    reached = sorted(name for name in idom if name in set(terminals))
    assert reached == terminals


def test_validation_error_is_locatable_and_has_no_partial_body(client):
    resp = client.post("/api/audit", json=payload(
        edges=[["R", "A"], ["GHOST", "T1"]]
    ))
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"] == "validation_failed"
    dangling = [d for d in body["details"] if d["type"] == "dangling_reference"]
    assert dangling and dangling[0]["loc"] == ["edges", 1, 0]
    assert "critical_relays" not in body and "dominators" not in body


def test_malformed_json_body(client):
    resp = client.post(
        "/api/audit",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_json"


def test_json_object_required(client):
    resp = client.post("/api/audit", json=[1, 2, 3])
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
