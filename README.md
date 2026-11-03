# TraceBack: IP Traceback with Probabilistic Packet Marking

In a DDoS attack the attacker spoofs the source address of every packet, so the victim can't tell where the flood comes from. **Probabilistic Packet Marking (PPM)**, from Savage et al., *Practical Network Support for IP Traceback* (ACM SIGCOMM 2000), solves this: each router writes its own address into a forwarded packet with a small probability `p`, and the victim rebuilds the attack path from the marks it collects.

This project simulates the attack and both marking schemes from the paper, and shows the results on an interactive dashboard.

## Run it

Needs Python 3.10 to 3.13.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py                      # opens http://127.0.0.1:8000
```

Everything the page needs (fonts, D3, Chart.js) is in `web/`, so it works with no internet connection.

Run the tests with `pytest`.

## What's on the dashboard

| Section | What it shows |
|---|---|
| **Live trace** | A generated network with attackers, routers, ordinary hosts and the victim. Packets flow toward the victim and routers fill up as their marks arrive. At the end the victim's rebuilt path is drawn over the map: correct links in purple, wrong links as red dashed arcs, forged addresses in amber. |
| **Marks received per router** | Counted marks against the expected `n·p(1−p)^(d−1)`. Closer routers are seen more often. |
| **Attack path recovered** | Share of the real path rebuilt as packets arrive. |
| **Follow one packet** | An IPv4 header diagram. Step hop by hop and watch the spoofed source stay fake while the mark field is written and overwritten. |
| **Experiments** | Packets needed against `p` and against path length, node vs. edge sampling, with the paper's theoretical bounds. |
| **How it works** | The algorithm, the formula, a comparison table and limitations. |

## Suggested demo order for the presentation

The *Scenarios* buttons at the top left run each case in one click:

1. **One attacker, node sampling.** The algorithm as described in the topic. The path is recovered, and the bar chart shows nearer routers getting more marks.
2. **Too few packets.** Same setup with only 5,000 packets. The far routers are still out of order, so the method needs volume.
3. **Three attackers.** Node sampling mixes the paths together: red links everywhere.
4. **Attacker forges marks.** The attacker pre-fills the mark field. Fake addresses survive with probability `(1−p)^d` (54% for p = 0.04, d = 15) and rank first.
5. **Edge sampling.** Three attackers and forged marks, and every real path is still rebuilt from about 400 packets. Forged edges can only appear *beyond* the attacker, never closer.
6. Scroll to **Follow one packet** to explain marking hop by hop, then to **Experiments** for the numbers.

## The algorithm

**Node sampling** (the scheme in the project topic). At each router, with probability `p` write the router's address into the packet, overwriting any earlier mark. The router `d` hops from the victim gets its mark through with probability `p(1−p)^(d−1)`, so the victim sorts routers by mark count to get the path order.

**Edge sampling** (the paper's improvement):

```
for each packet w at router R:
    if random() < p:
        w.start = R; w.distance = 0
    else:
        if w.distance == 0: w.end = R
        w.distance += 1
```

Each mark is an edge `(start → end)` plus its distance from the victim, so the victim joins edges into paths directly. That makes it much faster and lets it handle several attackers. Expected packets needed: `E[X] < ln(d) / (p(1−p)^(d−1))`.

Measured here for a 15-hop path at p = 0.04 (median of 20 runs): node sampling needs **about 72,000 packets**, edge sampling **about 100**.

## Project layout

```
ppm_traceback/
  topology.py        tree network rooted at the victim, random public IPs
  marking.py         node sampling and edge sampling, written as in the paper
  reconstruction.py  victim-side path rebuilding for both schemes
  simulation.py      full attack run: spoofing, forged marks, scoring, timeline
  experiments.py     fast Monte Carlo sweeps (exact geometric shortcut, tested)
server/app.py        FastAPI: POST /api/trace, GET /api/experiments, serves web/
web/                 dashboard (HTML, CSS, JS modules, local fonts and libraries)
tests/               marking statistics, reconstruction, simulation, API
run.py               starts the server and opens the browser
```

## Limits of the method (and of this simulation)

- Traceback finds the attacker's **first router**, not the attacker's machine.
- Every router on the path must support marking.
- The real deployment fits marks into the 16-bit IP Identification field by splitting each edge into 8 fragments. This simulation keeps the whole mark in one field so it can be followed hop by hop. Fragmenting would multiply the packets needed by about 8 and add a hash check.
- The network is a tree with fixed routes; real routes can change during an attack.

## Reference

S. Savage, D. Wetherall, A. Karlin, T. Anderson. *Practical Network Support for IP Traceback.* ACM SIGCOMM 2000.
