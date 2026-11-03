"""Network topology used by the simulation.

The network is modelled the way Savage et al. model it: a tree rooted at the
victim. Every router knows its next hop toward the victim (its parent), so the
path a packet takes from any host is the chain of parents up to the victim.

Depth convention used everywhere in this package:
    depth 0  -> the victim
    depth 1  -> the router directly attached to the victim
    depth d  -> a router d hops away from the victim
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass

VICTIM = "V"

# First octets that are never handed out to routers, so the generated
# addresses look like public internet routers (no private / loopback /
# multicast ranges).
_RESERVED_FIRST_OCTETS = {0, 10, 100, 127, 169, 172, 192, 198, 203}


@dataclass
class Node:
    id: str
    kind: str  # "victim" | "router" | "attacker" | "host"
    ip: str
    parent: str | None  # next hop toward the victim (None for the victim)
    depth: int


@dataclass
class Topology:
    nodes: dict[str, Node]
    attackers: list[str]
    hosts: list[str]

    def path_to_victim(self, host_id: str) -> list[str]:
        """Routers a packet from ``host_id`` crosses, in travel order.

        The first element is the router farthest from the victim (the
        attacker's first hop) and the last is the router next to the victim.
        """
        path: list[str] = []
        current = self.nodes[host_id].parent
        while current is not None and current != VICTIM:
            path.append(current)
            current = self.nodes[current].parent
        return path

    def router_ids(self) -> list[str]:
        return [n.id for n in self.nodes.values() if n.kind == "router"]

    def links(self) -> list[tuple[str, str]]:
        """Every (child, parent) link in the tree."""
        return [(n.id, n.parent) for n in self.nodes.values() if n.parent is not None]

    def attack_links(self) -> set[tuple[str, str]]:
        """Router-to-router links that attack traffic actually crosses.

        Traceback can only identify routers, so the final hop from the
        attacker's machine to its first router is not part of this set.
        """
        links: set[tuple[str, str]] = set()
        for attacker in self.attackers:
            path = self.path_to_victim(attacker)
            for child, parent in zip(path, path[1:] + [VICTIM]):
                links.add((child, parent))
        return links

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self.nodes.values()],
            "attackers": list(self.attackers),
            "hosts": list(self.hosts),
            "attack_paths": {a: self.path_to_victim(a) for a in self.attackers},
        }


def random_public_ip(rng: random.Random) -> str:
    while True:
        first = rng.randint(1, 223)
        if first not in _RESERVED_FIRST_OCTETS:
            break
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class _Builder:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.nodes: dict[str, Node] = {}
        self.used_ips: set[str] = set()
        self.router_count = 0

    def _ip(self) -> str:
        while True:
            ip = random_public_ip(self.rng)
            if ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip

    def add(self, node_id: str, kind: str, parent: str | None, depth: int) -> str:
        self.nodes[node_id] = Node(node_id, kind, self._ip(), parent, depth)
        return node_id

    def add_router(self, parent: str, depth: int) -> str:
        self.router_count += 1
        return self.add(f"R{self.router_count}", "router", parent, depth)

    def grow_chain(self, start: str, start_depth: int, end_depth: int) -> str:
        """Add routers below ``start`` until ``end_depth``; return the last one."""
        current = start
        for depth in range(start_depth + 1, end_depth + 1):
            current = self.add_router(current, depth)
        return current

    def ancestor_at_depth(self, node_id: str, depth: int) -> str:
        current = node_id
        while self.nodes[current].depth > depth:
            current = self.nodes[current].parent  # type: ignore[assignment]
        return current


def build_topology(
    path_length: int = 15,
    num_attackers: int = 1,
    num_hosts: int | None = None,
    seed: int | None = None,
) -> Topology:
    """Generate a tree-shaped network.

    * ``path_length``: router hops between the first attacker and the victim.
      Extra attackers get paths within two hops of this length.
    * ``num_attackers``: attack paths that share routers near the victim and
      split apart further out, like real internet routes.
    * ``num_hosts``: idle branches ending in ordinary hosts. They send no
      attack traffic, so a correct traceback must never implicate them.
    """
    if path_length < 2:
        raise ValueError("path_length must be at least 2")
    if num_attackers < 1:
        raise ValueError("num_attackers must be at least 1")

    rng = random.Random(seed)
    b = _Builder(rng)
    b.add(VICTIM, "victim", None, 0)

    attackers: list[str] = []
    attack_tips: list[str] = []  # the router each attacker hangs off

    # First attacker: a straight chain of routers from the victim.
    tip = b.grow_chain(VICTIM, 0, path_length)
    attack_tips.append(tip)

    # Further attackers branch off an existing attack path part-way out.
    for _ in range(num_attackers - 1):
        base_tip = rng.choice(attack_tips)
        length = max(3, path_length + rng.randint(-2, 2))
        max_branch = min(length - 1, b.nodes[base_tip].depth - 1)
        branch_depth = rng.randint(1, max(1, max_branch)) if max_branch >= 1 else 1
        branch_from = b.ancestor_at_depth(base_tip, branch_depth)
        attack_tips.append(b.grow_chain(branch_from, branch_depth, length))

    for i, tip in enumerate(attack_tips, start=1):
        attackers.append(b.add(f"A{i}", "attacker", tip, b.nodes[tip].depth + 1))

    # Idle branches with ordinary hosts at the end.
    if num_hosts is None:
        num_hosts = 3 + num_attackers
    hosts: list[str] = []
    routers = [n for n in b.nodes.values() if n.kind == "router"]
    for i in range(1, num_hosts + 1):
        anchor = rng.choice(routers)
        branch_len = rng.randint(1, 4)
        tip = b.grow_chain(anchor.id, anchor.depth, anchor.depth + branch_len)
        hosts.append(b.add(f"H{i}", "host", tip, b.nodes[tip].depth + 1))

    return Topology(nodes=b.nodes, attackers=attackers, hosts=hosts)
