"""Shared acceptance topologies for the test suite."""

from __future__ import annotations

BYPASS_COUNT = 96


def wide_merge_payload(bypass_count: int = BYPASS_COUNT) -> dict[str, object]:
    """Emergency beam-stop wide-confluence network.

    ``R`` reaches the merge point ``M`` through relay ``A`` *and* through
    ``bypass_count`` independent bypasses, each with its own unique relay
    ``B0 .. B{n-1}``.  ``M`` then feeds ``bypass_count + 1`` sink-only
    protected terminals ``T0 .. T{n}``.

    Every identifier is a unique ASCII string.
    """
    bypasses = [f"B{i}" for i in range(bypass_count)]
    terminals = [f"T{i}" for i in range(bypass_count + 1)]
    nodes = ["R", "A", "M", *bypasses, *terminals]
    edges: list[list[str]] = [["R", "A"], ["A", "M"]]
    edges += [["R", b] for b in bypasses]
    edges += [[b, "M"] for b in bypasses]
    edges += [["M", t] for t in terminals]
    return {
        "nodes": nodes,
        "root": "R",
        "terminals": terminals,
        "edges": edges,
    }
