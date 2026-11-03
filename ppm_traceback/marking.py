"""Router marking procedures from Savage et al., "Practical Network Support
for IP Traceback" (SIGCOMM 2000).

Two schemes are implemented, both exactly as written in the paper:

Node sampling
    for each packet w:
        with probability p: write R into w.node

Edge sampling
    for each packet w:
        let x be a random number in [0, 1)
        if x < p:
            write R into w.start and 0 into w.distance
        else:
            if w.distance == 0: write R into w.end
            increment w.distance

In both schemes a later router can overwrite an earlier router's mark, which is
why routers close to the victim show up more often.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

NODE = "node"
EDGE = "edge"
SCHEMES = (NODE, EDGE)


@dataclass
class Packet:
    src: str  # source address written by the attacker (spoofed)
    dst: str
    origin: str  # ground truth for scoring only; the victim never reads it

    # Node sampling mark field
    node: str | None = None

    # Edge sampling mark fields
    start: str | None = None
    end: str | None = None
    distance: int = 0

    def mark_fields(self, scheme: str) -> dict:
        if scheme == NODE:
            return {"node": self.node}
        return {"start": self.start, "end": self.end, "distance": self.distance}


def node_sampling(packet: Packet, router: str, p: float, rng: random.Random) -> str:
    """Apply node sampling at ``router``. Returns what happened to the mark."""
    if rng.random() < p:
        overwrote = packet.node is not None
        packet.node = router
        return "overwrite" if overwrote else "mark"
    return "pass"


def edge_sampling(packet: Packet, router: str, p: float, rng: random.Random) -> str:
    """Apply edge sampling at ``router``. Returns what happened to the mark."""
    if rng.random() < p:
        overwrote = packet.start is not None
        packet.start = router
        packet.end = None
        packet.distance = 0
        return "overwrite" if overwrote else "mark"
    action = "pass"
    if packet.distance == 0:
        packet.end = router
        # Completing an edge only means something if a start was written.
        action = "complete" if packet.start is not None else "pass"
    packet.distance += 1
    return action


MARKERS = {NODE: node_sampling, EDGE: edge_sampling}


def mark_probability(depth: int, p: float) -> float:
    """Probability that the victim receives the mark of the router at ``depth``.

    The router must mark (p) and every one of the ``depth - 1`` routers between
    it and the victim must leave the mark alone ((1 - p) each).
    """
    return p * (1 - p) ** (depth - 1)


def unmarked_probability(path_length: int, p: float) -> float:
    """Probability that no router on a path of ``path_length`` marks a packet.

    This is also the chance that a mark forged by the attacker survives.
    """
    return (1 - p) ** path_length
