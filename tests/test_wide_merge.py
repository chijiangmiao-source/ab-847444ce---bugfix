"""Acceptance tests for the wide-confluence emergency beam-stop network.

The root controller ``R`` feeds merge point ``M`` through relay ``A`` and
through 96 fully independent bypass relays.  A naive analysis that samples
only some predecessors of a wide merge point (e.g. one per DFS "region")
loses the bypasses and wrongly reports ``A`` as the immediate dominator of
``M``.  Every assertion here is cross-checked against an independently
recomputed oracle (plain node-deletion reachability / DFS), never only
against the production response shape.
"""

from __future__ import annotations

from app.audit import audit_graph
from app.dominators import compute_dominators, count_dominated_terminals

from .topologies import BYPASS_COUNT, wide_merge_payload


# ---------------------------------------------------------------------------
# Independent reference oracle (test code only; deliberately simple)
# ---------------------------------------------------------------------------

def _reach(adj, root, banned=None):
    if banned is not None and root == banned:
        return set()
    seen = {root}
    stack = [root]
    while stack:
        u = stack.pop()
        for v in adj[u]:
            if v != banned and v not in seen:
                seen.add(v)
                stack.append(v)
    return seen


def _oracle_idom(adj, n, root):
    """Immediate dominators via per-node deletion, O(V*(V+E))."""
    reach = _reach(adj, root)

    def dominates(u, v):
        return u == v or v not in _reach(adj, root, banned=u)

    idom = [-1] * n
    for v in reach:
        if v == root:
            continue
        strict = [u for u in reach if u != v and dominates(u, v)]
        for u in strict:
            if all(w == u or dominates(w, u) for w in strict):
                idom[v] = u
                break
    return reach, idom


def _integer_graph():
    n_bypasses = BYPASS_COUNT
    # Layout: 0=R, 1=A, 2=M, 3..98=bypasses, 99..195=terminals
    n = 3 + n_bypasses + (n_bypasses + 1)
    adj = [[] for _ in range(n)]
    pre = [[] for _ in range(n)]

    def add(u, v):
        adj[u].append(v)
        pre[v].append(u)

    add(0, 1)
    add(1, 2)
    for i in range(n_bypasses):
        b = 3 + i
        add(0, b)
        add(b, 2)
    for j in range(n_bypasses + 1):
        add(2, 3 + n_bypasses + j)
    return n, adj, pre


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------

def test_wide_merge_core_matches_deletion_oracle():
    n, adj, pre = _integer_graph()
    terminals = [False] * n
    for j in range(BYPASS_COUNT + 1):
        terminals[3 + BYPASS_COUNT + j] = True

    result = compute_dominators(
        n, adj, pre, root=0, is_terminal=terminals,
        labels=[f"n{i}" for i in range(n)],
    )
    reach, expected_idom = _oracle_idom(adj, n, root=0)

    assert set(result.vertex) == reach
    assert len(reach) == n  # every node reachable
    assert result.idom == expected_idom

    # The 96 bypasses route around A: M is dominated directly by R.
    assert result.idom[2] == 0
    assert result.idom[1] == 0
    for i in range(BYPASS_COUNT):
        assert result.idom[3 + i] == 0
    for j in range(BYPASS_COUNT + 1):
        assert result.idom[3 + BYPASS_COUNT + j] == 2


def test_wide_merge_core_terminal_counts():
    n, adj, pre = _integer_graph()
    terminals = [False] * n
    term_ids = [3 + BYPASS_COUNT + j for j in range(BYPASS_COUNT + 1)]
    for t in term_ids:
        terminals[t] = True

    result = compute_dominators(
        n, adj, pre, root=0, is_terminal=terminals,
        labels=[f"n{i}" for i in range(n)],
    )
    counts = count_dominated_terminals(result)

    # Independent oracle: u dominates terminal t iff deleting u loses t.
    for u in range(n):
        expected = sum(t not in _reach(adj, 0, banned=u) for t in term_ids)
        assert counts[u] == expected, u

    assert counts[1] == 0  # A is bypassed
    for i in range(BYPASS_COUNT):
        assert counts[3 + i] == 0  # each bypass relay is bypassed by the others
    assert counts[2] == BYPASS_COUNT + 1  # M is the unique single point
    assert counts[0] == BYPASS_COUNT + 1  # root naturally dominates all


# ---------------------------------------------------------------------------
# Full audit (validation + assembly) on the ASCII business topology
# ---------------------------------------------------------------------------

def test_wide_merge_audit_response():
    payload = wide_merge_payload()
    out = audit_graph(payload)

    name_to_id = {name: i for i, name in enumerate(payload["nodes"])}
    adj: dict[str, list[str]] = {name: [] for name in payload["nodes"]}
    for src, dst in payload["edges"]:
        adj[src].append(dst)

    # -- Reachability recomputed independently from the raw edges ----------
    seen = {"R"}
    stack = ["R"]
    while stack:
        u = stack.pop()
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                stack.append(v)
    reachable_terminals = sorted(t for t in payload["terminals"] if t in seen)

    assert out["unreachable_terminals"] == []
    assert reachable_terminals == sorted(payload["terminals"])
    assert len(reachable_terminals) == BYPASS_COUNT + 1
    assert out["reachable_node_count"] == len(seen) == len(payload["nodes"])

    idom = {d["node"]: d["immediate_dominator"] for d in out["dominators"]}

    # Every terminal reachable, and its immediate dominator is M.
    assert {t: idom[t] for t in payload["terminals"]} == {
        t: "M" for t in payload["terminals"]
    }
    # The bypasses genuinely route around A.
    assert idom["M"] == "R"
    assert idom["A"] == "R"
    for i in range(BYPASS_COUNT):
        assert idom[f"B{i}"] == "R"
    assert idom["R"] is None

    # Cross-recompute M's terminal count from the idom listing itself:
    # exactly the 97 terminals name M as their immediate dominator.
    terminals_directly_under_m = sorted(
        name for name, dom in idom.items()
        if dom == "M" and name in set(payload["terminals"])
    )
    assert terminals_directly_under_m == reachable_terminals

    critical = {c["node"]: c["dominated_terminals"] for c in out["critical_relays"]}
    assert critical == {"M": BYPASS_COUNT + 1}
    # A and every bypass relay are explicitly not critical.
    assert "A" not in critical
    assert all(f"B{i}" not in critical for i in range(BYPASS_COUNT))


def test_wide_merge_node_identifiers_all_unique_ascii():
    payload = wide_merge_payload()
    names = payload["nodes"]
    assert len(names) == len(set(names))
    assert all(isinstance(name, str) and name and name.isascii() for name in names)
