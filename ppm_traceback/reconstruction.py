"""Victim-side path reconstruction.

The victim only sees the mark fields of the packets it receives. It never sees
the true topology. Both procedures here follow Savage et al.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .topology import VICTIM


@dataclass
class NodeReconstruction:
    """Node sampling result: routers ranked by how often their mark arrived.

    Rank 1 is believed to be the router next to the victim, rank 2 the one
    after it, and so on. The implied path links each router to the one ranked
    just above it.
    """

    ranking: list[tuple[str, int]]

    @property
    def links(self) -> list[tuple[str, str]]:
        order = [router for router, _ in self.ranking]
        return list(zip(order, [VICTIM] + order[:-1]))


def reconstruct_node_sampling(counts: Counter) -> NodeReconstruction:
    ranking = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return NodeReconstruction(ranking=ranking)


@dataclass
class EdgeReconstruction:
    """Edge sampling result: a graph of consistent edges rooted at the victim."""

    edges: list[dict] = field(default_factory=list)  # kept edges
    dropped_marks: int = 0  # marks whose distance did not fit the graph
    paths: list[list[str]] = field(default_factory=list)  # far end -> victim

    @property
    def links(self) -> list[tuple[str, str]]:
        return [(e["from"], e["to"]) for e in self.edges]


def reconstruct_edge_sampling(edge_counts: Counter) -> EdgeReconstruction:
    """Rebuild the attack graph from (start, end, distance) marks.

    Paper procedure:
      * a mark with distance 0 is the edge (start -> victim)
      * otherwise it is the edge (start -> end) at the given distance
      * drop edges whose distance does not match the end router's distance
        from the victim, then read off the paths.

    The graph is grown outward one distance level at a time, so an edge is
    kept only when its ``end`` router was already placed at exactly
    ``distance`` hops from the victim.
    """
    by_distance: dict[int, list[tuple[str, str, int]]] = {}
    for (start, end, distance), count in edge_counts.items():
        if start is None:
            continue  # never marked by any router
        to = VICTIM if distance == 0 else end
        by_distance.setdefault(distance, []).append((start, to, count))

    level_of: dict[str, int] = {VICTIM: 0}
    kept: list[dict] = []
    dropped = 0
    parent_of: dict[str, str] = {}

    for distance in sorted(by_distance):
        for start, to, count in sorted(by_distance[distance]):
            fits = level_of.get(to) == distance
            already_placed = start in level_of and level_of[start] != distance + 1
            if fits and not already_placed and start != to:
                level_of[start] = distance + 1
                parent_of.setdefault(start, to)
                kept.append({"from": start, "to": to, "distance": distance, "count": count})
            else:
                dropped += count

    children = {e["to"] for e in kept}
    leaves = [e["from"] for e in kept if e["from"] not in children]
    paths: list[list[str]] = []
    for leaf in sorted(set(leaves), key=lambda r: (-level_of[r], r)):
        path = [leaf]
        while path[-1] != VICTIM:
            path.append(parent_of[path[-1]])
        paths.append(path[:-1])

    return EdgeReconstruction(edges=kept, dropped_marks=dropped, paths=paths)
