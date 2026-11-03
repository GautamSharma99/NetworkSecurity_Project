import random
from collections import Counter

import numpy as np
import pytest
from fastapi.testclient import TestClient

from ppm_traceback import (
    EDGE, NODE, VICTIM, Packet, TraceConfig, build_topology, edge_sampling,
    mark_probability, node_sampling, reconstruct_edge_sampling,
    reconstruct_node_sampling, run_trace,
)
from ppm_traceback.experiments import packets_needed
from server.app import app


# ------------------------------------------------------------------ topology

def test_topology_paths_have_requested_length():
    topo = build_topology(path_length=12, num_attackers=1, seed=3)
    path = topo.path_to_victim("A1")
    assert len(path) == 12
    depths = [topo.nodes[r].depth for r in path]
    assert depths == list(range(12, 0, -1))  # farthest first, ends next to victim


def test_topology_addresses_are_unique():
    topo = build_topology(path_length=20, num_attackers=6, seed=11)
    ips = [n.ip for n in topo.nodes.values()]
    assert len(ips) == len(set(ips))


def test_hosts_are_not_on_attack_paths():
    topo = build_topology(path_length=10, num_attackers=3, seed=5)
    attack_routers = {r for a in topo.attackers for r in topo.path_to_victim(a)}
    for host in topo.hosts:
        parent = topo.nodes[host].parent
        assert parent not in topo.attackers


# ------------------------------------------------------------------ marking

def _final_depths(marker, scheme, p, d, n, seed=1):
    """Run packets hop by hop along a d-router path; return the depth of the
    router whose mark arrives (None when unmarked)."""
    rng = random.Random(seed)
    path = [f"R{k}" for k in range(d, 0, -1)]  # R{k} sits k hops from victim
    out = Counter()
    for _ in range(n):
        pkt = Packet(src="x", dst="v", origin="A")
        for r in path:
            marker(pkt, r, p, rng)
        mark = pkt.node if scheme == NODE else pkt.start
        out[None if mark is None else int(mark[1:])] += 1
    return out


@pytest.mark.parametrize("marker,scheme", [(node_sampling, NODE), (edge_sampling, EDGE)])
def test_mark_frequencies_match_p_one_minus_p_power(marker, scheme):
    p, d, n = 0.1, 8, 60_000
    counts = _final_depths(marker, scheme, p, d, n)
    for k in range(1, d + 1):
        expected = n * mark_probability(k, p)
        assert abs(counts[k] - expected) < 5 * expected ** 0.5 + 5, (k, counts[k], expected)
    # Closer routers are seen more often.
    assert counts[1] > counts[d]


def test_edge_distance_counts_hops_from_end_to_victim():
    rng = random.Random(0)
    path = ["R3", "R2", "R1"]
    # Force R3 to mark and the rest to pass.
    pkt = Packet(src="x", dst="v", origin="A")
    edge_sampling(pkt, "R3", 1.0, rng)
    for r in path[1:]:
        edge_sampling(pkt, r, 0.0, rng)
    assert (pkt.start, pkt.end, pkt.distance) == ("R3", "R2", 2)


def test_later_router_overwrites_node_mark():
    rng = random.Random(0)
    pkt = Packet(src="x", dst="v", origin="A")
    assert node_sampling(pkt, "R2", 1.0, rng) == "mark"
    assert node_sampling(pkt, "R1", 1.0, rng) == "overwrite"
    assert pkt.node == "R1"


# ------------------------------------------------------------------ reconstruction

def test_node_reconstruction_orders_by_count():
    result = reconstruct_node_sampling(Counter({"R1": 50, "R3": 10, "R2": 30}))
    assert [r for r, _ in result.ranking] == ["R1", "R2", "R3"]
    assert result.links == [("R1", VICTIM), ("R2", "R1"), ("R3", "R2")]


def test_edge_reconstruction_drops_inconsistent_marks():
    marks = Counter({
        ("R1", None, 0): 5,
        ("R2", "R1", 1): 4,
        ("R3", "R2", 2): 3,
        ("X", "R2", 7): 2,      # wrong distance
        ("Y", "Nowhere", 1): 1,  # end not in graph
    })
    result = reconstruct_edge_sampling(marks)
    assert result.paths == [["R3", "R2", "R1"]]
    assert result.dropped_marks == 3


# ------------------------------------------------------------------ full simulation

def test_edge_sampling_recovers_multiple_attackers():
    out = run_trace(TraceConfig(scheme=EDGE, attackers=3, packets=20_000, seed=7))
    assert out["score"]["recovered"] == 1.0
    assert out["score"]["false_links"] == 0


def test_node_sampling_recovers_single_path_with_enough_packets():
    out = run_trace(TraceConfig(scheme=NODE, p=0.04, path_length=8, packets=150_000, seed=2))
    assert out["score"]["recovered"] == 1.0


def test_forged_marks_break_node_sampling_but_not_edge_sampling():
    node = run_trace(TraceConfig(scheme=NODE, forge=True, packets=50_000, seed=4))
    edge = run_trace(TraceConfig(scheme=EDGE, forge=True, packets=50_000, seed=4))
    # Forged addresses outrank every real router, so the path is wrong.
    top3 = [r["router"] for r in node["reconstruction"]["ranking"][:3]]
    assert all(r.startswith("F") for r in top3)
    assert node["score"]["recovered"] < 1.0 and node["score"]["false_links"] >= 3
    assert edge["score"]["recovered"] == 1.0
    # Every surviving forged edge sits beyond the attacker's first router.
    first_hop = edge["topology"]["attack_paths"]["A1"][0]
    for e in edge["reconstruction"]["edges"]:
        if e["from"].startswith("F"):
            assert e["to"] == first_hop


def test_spoofed_and_forged_addresses_never_match_real_nodes():
    out = run_trace(TraceConfig(scheme=EDGE, forge=True, packets=2_000, seed=7))
    real = {n["ip"] for n in out["topology"]["nodes"]}
    assert not real & set(out["forged_ips"].values())
    assert not real & {t["src"] for t in out["traces"]}


# ------------------------------------------------------------------ experiments

def test_geometric_shortcut_matches_hop_by_hop_simulation():
    """experiments.py draws each packet's final mark from Geometric(p);
    compare that with the faithful router-by-router simulation."""
    p, d, n = 0.15, 6, 50_000
    hop_by_hop = _final_depths(node_sampling, NODE, p, d, n, seed=9)
    ks = np.random.default_rng(9).geometric(p, size=n)
    shortcut = Counter(int(k) if k <= d else None for k in ks)
    for k in list(range(1, d + 1)) + [None]:
        # Difference of two binomial counts: allow 4 standard deviations.
        assert abs(hop_by_hop[k] - shortcut[k]) < 4 * (2 * max(hop_by_hop[k], 1)) ** 0.5


def test_edge_sampling_needs_far_fewer_packets_than_node_sampling():
    rng = np.random.default_rng(1)
    edge = packets_needed(EDGE, 0.04, 15, rng)
    node = packets_needed(NODE, 0.04, 15, rng)
    assert edge is not None and node is not None
    assert node > 50 * edge


# ------------------------------------------------------------------ API

def test_api_trace_and_experiments():
    client = TestClient(app)
    r = client.post("/api/trace", json={"scheme": "edge", "packets": 1000, "attackers": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["scheme"] == "edge"
    assert body["timeline"][-1]["packets"] == 1000

    assert client.post("/api/trace", json={"p": 1.5}).status_code == 422

    r = client.get("/api/experiments", params={"variable": "d", "fixed": 0.1, "trials": 5})
    assert r.status_code == 200
    assert len(r.json()["rows"]) > 3

    assert client.get("/").status_code == 200
