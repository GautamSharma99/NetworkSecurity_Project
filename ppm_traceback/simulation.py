"""End-to-end attack simulation: attackers flood the victim with spoofed
packets, routers mark them, and the victim reconstructs the attack paths."""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass

from .marking import EDGE, MARKERS, NODE, Packet, mark_probability
from .reconstruction import reconstruct_edge_sampling, reconstruct_node_sampling
from .topology import VICTIM, Topology, build_topology, random_public_ip


@dataclass
class TraceConfig:
    scheme: str = NODE
    p: float = 0.04
    path_length: int = 15
    attackers: int = 1
    packets: int = 20_000
    forge: bool = False
    seed: int | None = 7
    checkpoints: int = 60
    sample_traces: int = 40

    def validate(self) -> None:
        if self.scheme not in MARKERS:
            raise ValueError(f"unknown scheme {self.scheme!r}")
        if not 0 < self.p < 1:
            raise ValueError("p must be between 0 and 1")
        if self.packets < 1:
            raise ValueError("packets must be positive")


def checkpoint_schedule(total: int, count: int) -> list[int]:
    """Roughly log-spaced packet counts ending at ``total``."""
    if total <= count:
        return list(range(1, total + 1))
    first = min(10, total)
    points = {
        round(first * (total / first) ** (i / (count - 1))) for i in range(count)
    }
    points.add(total)
    return sorted(p for p in points if 1 <= p <= total)


def score_links(found: list[tuple[str, str]], truth: set[tuple[str, str]]) -> dict:
    found_set = set(found)
    correct = found_set & truth
    false = found_set - truth
    return {
        "recovered": len(correct) / len(truth) if truth else 1.0,
        "correct_links": len(correct),
        "false_links": len(false),
        "total_links": len(truth),
    }


def _reconstruct(scheme: str, node_counts: Counter, edge_counts: Counter):
    if scheme == NODE:
        return reconstruct_node_sampling(node_counts)
    return reconstruct_edge_sampling(edge_counts)


def run_trace(config: TraceConfig, topology: Topology | None = None) -> dict:
    config.validate()
    # Separate stream from the topology builder, so spoofed and forged
    # addresses never repeat the routers' own addresses.
    rng = random.Random(None if config.seed is None else f"traffic:{config.seed}")
    if topology is None:
        topology = build_topology(
            path_length=config.path_length,
            num_attackers=config.attackers,
            seed=config.seed,
        )

    mark = MARKERS[config.scheme]
    paths = {a: topology.path_to_victim(a) for a in topology.attackers}
    victim_ip = topology.nodes[VICTIM].ip
    truth = topology.attack_links()

    # Fake router addresses an attacker writes into the mark field.
    forged_ips: dict[str, str] = {}
    if config.forge:
        forged_ips = {f"F{i}": random_public_ip(rng) for i in range(1, 4)}
    forged_ids = list(forged_ips)

    node_counts: Counter = Counter()
    edge_counts: Counter = Counter()
    sent_by: Counter = Counter()

    schedule = checkpoint_schedule(config.packets, config.checkpoints)
    next_checkpoint = 0
    timeline: list[dict] = []
    traces: list[dict] = []
    first_complete: int | None = None  # every true link found, nothing false
    first_recovered: int | None = None  # every true link found
    unmarked = 0
    forged_received = 0
    sources: set[str] = set()  # every source address the victim has seen

    for n in range(1, config.packets + 1):
        attacker = rng.choice(topology.attackers)
        sent_by[attacker] += 1
        packet = Packet(src=random_public_ip(rng), dst=victim_ip, origin=attacker)
        sources.add(packet.src)
        if forged_ids:
            fake = rng.choice(forged_ids)
            if config.scheme == NODE:
                packet.node = fake
            else:
                packet.start, packet.distance = fake, 0

        record = len(traces) < config.sample_traces
        hops = []
        if record:
            hops.append({"at": attacker, "action": "send", "mark": packet.mark_fields(config.scheme)})

        for router in paths[attacker]:
            action = mark(packet, router, config.p, rng)
            if record:
                hops.append({"at": router, "action": action, "mark": packet.mark_fields(config.scheme)})

        # The victim records whatever mark arrived.
        if config.scheme == NODE:
            if packet.node is None:
                unmarked += 1
            else:
                node_counts[packet.node] += 1
                forged_received += packet.node in forged_ips
        else:
            if packet.start is None:
                unmarked += 1
            else:
                edge_counts[(packet.start, packet.end, packet.distance)] += 1
                forged_received += packet.start in forged_ips

        if record:
            traces.append({"origin": attacker, "src": packet.src, "dst": packet.dst, "hops": hops})

        if next_checkpoint < len(schedule) and n == schedule[next_checkpoint]:
            next_checkpoint += 1
            result = _reconstruct(config.scheme, node_counts, edge_counts)
            score = score_links(result.links, truth)
            if score["recovered"] == 1.0:
                if first_recovered is None:
                    first_recovered = n
                if score["false_links"] == 0 and first_complete is None:
                    first_complete = n
            timeline.append({
                "packets": n,
                **score,
                "sources": len(sources),
                "unmarked": unmarked,
                "forged": forged_received,
                "tally": _router_tally(config.scheme, node_counts, edge_counts),
            })

    final = _reconstruct(config.scheme, node_counts, edge_counts)
    final_score = score_links(final.links, truth)

    return {
        "config": {
            "scheme": config.scheme,
            "p": config.p,
            "path_length": config.path_length,
            "attackers": config.attackers,
            "packets": config.packets,
            "forge": config.forge,
            "seed": config.seed,
        },
        "topology": topology.to_dict(),
        "forged_ips": forged_ips,
        "reconstruction": _serialise_reconstruction(config.scheme, final, truth),
        "score": final_score,
        "first_complete": first_complete,
        "first_recovered": first_recovered,
        "unmarked": unmarked,
        "forged_received": forged_received,
        "tally": _tally_table(topology, config, node_counts, edge_counts, sent_by, forged_ips),
        "timeline": timeline,
        "traces": traces,
        "theory": {
            "farthest_mark_probability": mark_probability(config.path_length, config.p),
            "unmarked_probability": (1 - config.p) ** config.path_length,
            "edge_expected_packets": expected_packets_edge(config.path_length, config.p),
        },
    }


def expected_packets_edge(d: int, p: float) -> float:
    """Savage et al.'s bound on packets needed for edge sampling:
    E[X] < ln(d) / (p (1 - p)^(d - 1))."""
    return math.log(max(d, 2)) / mark_probability(d, p)


def _router_tally(scheme: str, node_counts: Counter, edge_counts: Counter) -> dict[str, int]:
    if scheme == NODE:
        return dict(node_counts)
    tally: Counter = Counter()
    for (start, _end, _dist), count in edge_counts.items():
        tally[start] += count
    return dict(tally)


def _tally_table(topology, config, node_counts, edge_counts, sent_by, forged_ips) -> list[dict]:
    """Observed vs expected mark counts for every router on an attack path."""
    observed = _router_tally(config.scheme, node_counts, edge_counts)
    through: Counter = Counter()
    for attacker, sent in sent_by.items():
        for router in topology.path_to_victim(attacker):
            through[router] += sent

    rows = []
    for router, packets_through in through.items():
        depth = topology.nodes[router].depth
        rows.append({
            "router": router,
            "ip": topology.nodes[router].ip,
            "depth": depth,
            "observed": observed.get(router, 0),
            "expected": packets_through * mark_probability(depth, config.p),
            "forged": False,
        })
    for fake, ip in forged_ips.items():
        rows.append({
            "router": fake, "ip": ip, "depth": None,
            "observed": observed.get(fake, 0), "expected": None, "forged": True,
        })
    rows.sort(key=lambda r: (r["depth"] is None, r["depth"] or 0, r["router"]))
    return rows


def _serialise_reconstruction(scheme: str, result, truth: set) -> dict:
    links = [
        {"from": a, "to": b, "correct": (a, b) in truth} for a, b in result.links
    ]
    if scheme == NODE:
        return {
            "ranking": [{"router": r, "count": c} for r, c in result.ranking],
            "links": links,
        }
    return {
        "edges": result.edges,
        "paths": result.paths,
        "dropped_marks": result.dropped_marks,
        "links": links,
    }
