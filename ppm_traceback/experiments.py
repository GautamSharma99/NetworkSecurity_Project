"""Monte Carlo experiments: how many packets does the victim need?

Running the hop-by-hop simulation thousands of times is slow, so this module
uses an exact shortcut. On a single path of d routers, the mark that reaches
the victim always belongs to the *closest* router that chose to mark, because
everything further out was overwritten. The router at depth k (1 = next to the
victim) is that router with probability p(1-p)^(k-1), which is a geometric
distribution. So each packet's final mark can be drawn directly:

    k ~ Geometric(p);  k > d means the packet arrived unmarked.

For node sampling the mark is router k. For edge sampling it is the edge
(router k -> router k-1) with distance k-1. ``tests/test_experiments.py``
checks that this matches the hop-by-hop simulation.
"""

from __future__ import annotations

import math
from functools import lru_cache

import numpy as np

from .marking import EDGE, NODE, mark_probability

P_VALUES = (0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.15, 0.2, 0.3, 0.5)
D_VALUES = (3, 5, 8, 10, 12, 15, 18, 20, 25)
MAX_PACKETS = 300_000


def _final_marks(rng: np.random.Generator, p: float, n: int) -> np.ndarray:
    return rng.geometric(p, size=n)


def packets_needed(scheme: str, p: float, d: int, rng: np.random.Generator,
                   max_packets: int = MAX_PACKETS) -> int | None:
    """Packets until the victim reconstructs a d-hop path correctly.

    Edge sampling: every one of the d edges has arrived at least once.
    Node sampling: every router has arrived and sorting by count gives the
    true order (strictly more marks for each router closer to the victim).
    Returns None if this does not happen within ``max_packets``.
    """
    counts = np.zeros(d, dtype=np.int64)
    seen = 0
    chunk = 2048
    while seen < max_packets:
        size = min(chunk, max_packets - seen)
        ks = _final_marks(rng, p, size)
        onehot = np.zeros((size, d), dtype=np.int32)
        marked = ks <= d
        onehot[np.nonzero(marked)[0], ks[marked] - 1] = 1
        cumulative = np.cumsum(onehot, axis=0) + counts

        if scheme == EDGE:
            ok = np.all(cumulative > 0, axis=1)
        else:
            ok = (cumulative[:, -1] > 0) & np.all(np.diff(cumulative, axis=1) < 0, axis=1)

        hits = np.flatnonzero(ok)
        if hits.size:
            return seen + int(hits[0]) + 1
        counts = cumulative[-1]
        seen += size
        chunk *= 2
    return None


def theory_node_minimum(d: int, p: float) -> float:
    """Expected packets before the farthest router's mark arrives even once.
    Node sampling cannot finish before this."""
    return 1 / mark_probability(d, p)


def theory_edge_bound(d: int, p: float) -> float:
    """Savage et al.: E[X] < ln(d) / (p (1-p)^(d-1))."""
    return math.log(max(d, 2)) / mark_probability(d, p)


def _summarise(samples: list[int | None]) -> dict:
    done = [s for s in samples if s is not None]
    return {
        "median": float(np.median(done)) if done else None,
        "mean": float(np.mean(done)) if done else None,
        "converged": len(done),
        "trials": len(samples),
    }


@lru_cache(maxsize=32)
def sweep(variable: str, fixed: float, trials: int = 20, seed: int = 2000) -> dict:
    """Vary p (with d fixed) or d (with p fixed) and measure both schemes."""
    rng = np.random.default_rng(seed)
    if variable == "p":
        d = int(fixed)
        cases = [(p, d) for p in P_VALUES]
    elif variable == "d":
        p = float(fixed)
        cases = [(p, d) for d in D_VALUES]
    else:
        raise ValueError("variable must be 'p' or 'd'")

    rows = []
    for p, d in cases:
        row = {"p": p, "d": d}
        for scheme in (NODE, EDGE):
            row[scheme] = _summarise([packets_needed(scheme, p, d, rng) for _ in range(trials)])
        row["theory_node_minimum"] = theory_node_minimum(d, p)
        row["theory_edge_bound"] = theory_edge_bound(d, p)
        rows.append(row)
    return {"variable": variable, "fixed": fixed, "trials": trials,
            "max_packets": MAX_PACKETS, "rows": rows}
