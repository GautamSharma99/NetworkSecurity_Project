import { NetworkMap } from "./map.js";
import { TraceCharts, experimentChart } from "./charts.js";
import { Inspector } from "./inspector.js";
import { el, fmt, nodeName, pct, prefersReducedMotion } from "./format.js";

const P_VALUES = [0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5];
const PACKETS = [1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000];
const PLAYBACK_MS = 7000;

const SCENARIOS = [
  { name: "One attacker, node sampling", note: "The algorithm as described: count the marks, sort by count.",
    s: { scheme: "node", p: 0.04, hops: 15, attackers: 1, packets: 100000, forge: false } },
  { name: "Too few packets", note: "Stop early and the far routers are still out of order.",
    s: { scheme: "node", p: 0.04, hops: 15, attackers: 1, packets: 5000, forge: false } },
  { name: "Three attackers", note: "Counts from different paths mix into one list.",
    s: { scheme: "node", p: 0.04, hops: 15, attackers: 3, packets: 100000, forge: false } },
  { name: "Attacker forges marks", note: "Fake addresses arrive more often than real ones.",
    s: { scheme: "node", p: 0.04, hops: 15, attackers: 1, packets: 100000, forge: true } },
  { name: "Edge sampling", note: "Three attackers and forged marks, traced with 20,000 packets.",
    s: { scheme: "edge", p: 0.04, hops: 15, attackers: 3, packets: 20000, forge: true } },
];

const $ = (id) => document.getElementById(id);
const form = $("controls");
const map = new NetworkMap($("map"), $("tooltip"));
const charts = new TraceCharts($("tally-chart"), $("recovery-chart"));
const inspector = new Inspector($("inspector"));

/* ---------------------------------------------------------------- controls */

function settings() {
  return {
    scheme: form.querySelector('input[name="scheme"]:checked').value,
    p: P_VALUES[+$("p").value],
    hops: +$("hops").value,
    attackers: +$("attackers").value,
    packets: PACKETS[+$("packets").value],
    forge: $("forge").checked,
    seed: Math.max(0, Math.min(1_000_000, parseInt($("seed").value, 10) || 0)),
  };
}

function applySettings(s) {
  form.querySelector(`input[name="scheme"][value="${s.scheme}"]`).checked = true;
  $("p").value = String(P_VALUES.indexOf(s.p));
  $("hops").value = String(s.hops);
  $("attackers").value = String(s.attackers);
  $("packets").value = String(PACKETS.indexOf(s.packets));
  $("forge").checked = s.forge;
  syncLabels();
}

function syncLabels() {
  const s = settings();
  $("p-out").textContent = s.p.toFixed(2);
  $("p-hint").textContent = `Each router marks about ${Math.round(s.p * 100)} in every 100 packets it forwards.`;
  $("hops-out").textContent = `${s.hops} hops`;
  $("attackers-out").textContent = String(s.attackers);
  $("packets-out").textContent = fmt(s.packets);
  $("scheme-hint").textContent = s.scheme === "node"
    ? "A mark holds one router address. The victim orders routers by how often each appears."
    : "A mark holds two neighbouring routers and their distance from the victim, so order is known directly.";
}

function renderScenarios() {
  const list = $("scenarios");
  list.replaceChildren(...SCENARIOS.map((sc, i) => {
    const b = el("button", { type: "button", class: "scenario", "aria-pressed": "false", "data-i": String(i) },
      sc.name, el("small", { text: sc.note }));
    b.addEventListener("click", () => {
      applySettings(sc.s);
      markScenario(i);
      run();
    });
    return b;
  }));
}

function markScenario(index) {
  $("scenarios").querySelectorAll(".scenario").forEach((b, i) => b.setAttribute("aria-pressed", String(i === index)));
}

form.addEventListener("input", (e) => {
  syncLabels();
  if (e.target.id !== "seed") markScenario(-1);
});
form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
$("new-network").addEventListener("click", () => {
  $("seed").value = String(Math.floor(Math.random() * 100000));
  run();
});

/* ---------------------------------------------------------------- run + playback */

let runToken = 0;
let playback = null;

async function run() {
  const token = ++runToken;
  stopPlayback();
  const s = settings();
  $("run").disabled = true;
  $("run").textContent = "Simulating…";
  $("status-text").textContent = `Sending ${fmt(s.packets)} spoofed packets through the network…`;

  let data;
  try {
    const res = await fetch("/api/trace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scheme: s.scheme, p: s.p, path_length: s.hops, attackers: s.attackers, packets: s.packets, forge: s.forge, seed: s.seed }),
    });
    if (!res.ok) throw new Error(`The server answered ${res.status}.`);
    data = await res.json();
  } catch (err) {
    if (token !== runToken) return;
    $("status-text").textContent = `Couldn’t run the simulation. ${err.message} Check that the server is running, then try again.`;
    resetRunButton();
    return;
  }
  if (token !== runToken) return;

  map.render(data);
  charts.reset(data);
  inspector.load(data, interestingTrace(data));
  resetVerdict();
  $("r-forged-wrap").hidden = !data.config.forge;
  $("run").textContent = "Running…";
  startPlayback(data, token);
}

function resetRunButton() {
  $("run").disabled = false;
  $("run").textContent = "Run attack";
}

function startPlayback(data, token) {
  const frames = data.timeline;
  const reduced = prefersReducedMotion();
  const frameMs = PLAYBACK_MS / frames.length;
  let i = 0;
  let traceI = 0;

  const finish = () => {
    if (!playback || token !== runToken) return;
    clearTimeout(playback.timer);
    clearInterval(playback.dots);
    playback = null;
    map.stopPackets();
    showFrame(data, frames.length - 1);
    $("skip").hidden = true;
    $("status-text").textContent = `Done. The victim received ${fmt(data.config.packets)} packets.`;
    map.showReconstruction(!reduced);
    showVerdict(data);
    resetRunButton();
  };

  playback = { timer: null, dots: null, finish };

  if (reduced) { finish(); return; }

  $("skip").hidden = false;
  playback.dots = setInterval(() => {
    map.sendPacket(data.traces[traceI % data.traces.length], data.config.scheme);
    traceI++;
  }, 150);

  const tick = () => {
    if (token !== runToken) return;
    showFrame(data, i);
    $("status-text").textContent = `Flood in progress: ${fmt(frames[i].packets)} of ${fmt(data.config.packets)} packets received`;
    i++;
    if (i < frames.length) playback.timer = setTimeout(tick, frameMs);
    else playback.timer = setTimeout(finish, 600);
  };
  tick();
}

function stopPlayback() {
  if (!playback) return;
  clearTimeout(playback.timer);
  clearInterval(playback.dots);
  playback = null;
  map.stopPackets();
  $("skip").hidden = true;
}

$("skip").addEventListener("click", () => playback?.finish());

function showFrame(data, i) {
  const t = data.timeline[i];
  map.setTally(t.tally);
  charts.frame(i);
  $("r-packets").textContent = fmt(t.packets);
  $("r-sources").textContent = fmt(t.sources);
  $("r-unmarked").textContent = `${fmt(t.unmarked)} (${pct(t.unmarked / t.packets, 0)})`;
  $("r-forged").textContent = `${fmt(t.forged)} (${pct(t.forged / t.packets, 0)})`;
}

/** Pick a sample packet whose journey shows marking and overwriting. */
function interestingTrace(data) {
  const actions = (t) => t.hops.map((h) => h.action);
  let i = data.traces.findIndex((t) => actions(t).includes("overwrite"));
  if (i < 0) i = data.traces.findIndex((t) => actions(t).includes("mark"));
  return Math.max(0, i);
}

/* ---------------------------------------------------------------- verdict */

function resetVerdict() {
  $("verdict").className = "verdict";
  $("verdict-title").textContent = "Watching the flood arrive…";
  $("verdict-body").textContent = "";
  $("path-chain").replaceChildren();
}

function showVerdict(data) {
  const { score: s, config: c } = data;
  const v = $("verdict");
  const d = c.path_length;
  const done = data.first_complete;
  let title, body;

  if (s.recovered === 1 && s.false_links === 0) {
    v.className = "verdict ok";
    title = c.attackers > 1
      ? `All ${c.attackers} attack paths recovered.`
      : "Attack path recovered.";
    body = `Every one of the ${s.total_links} links was right by packet ${fmt(done)}. The victim traced the flood to ${c.attackers > 1 ? "each attacker’s" : "the attacker’s"} first router without trusting a single source address.`;
  } else if (s.recovered === 1) {
    v.className = "verdict ok";
    title = `Attack path recovered, plus ${s.false_links} fake link${s.false_links === 1 ? "" : "s"}.`;
    body = "Every real link was rebuilt. The forged edges only hang off the far end, beyond the attacker’s first router: a forged mark can describe routers farther away than the attacker, never closer, so it can’t hide the real path.";
  } else {
    v.className = "verdict fail";
    title = `Path not recovered: ${s.correct_links} of ${s.total_links} links correct.`;
    const far = data.theory.farthest_mark_probability;
    if (c.scheme === "node" && c.forge) {
      body = `A forged mark survives whenever no router on the path marks the packet, which happens with probability (1−p)^d = ${pct(data.theory.unmarked_probability)}. The fake addresses arrive more often than any real router, so they rank first and push every real router out of place.`;
    } else if (c.scheme === "node" && c.attackers > 1) {
      body = "Node sampling only ranks routers by count. With several attackers, routers from different paths fall into one list, so the order links routers that aren’t connected. Edge sampling keeps the paths apart.";
    } else if (c.scheme === "node") {
      body = `Not enough packets yet. The farthest router’s mark arrives with probability p(1−p)^(d−1) = ${pct(far, 2)} per packet, and neighbouring routers’ counts differ by only ${pct(c.p, 0)}, so the order takes many packets to settle. Send more packets or change p.`;
    } else {
      body = `Some edges haven’t arrived yet. The farthest edge arrives with probability ${pct(far, 2)} per packet. Send more packets.`;
    }
  }
  $("verdict-title").textContent = title;
  $("verdict-body").textContent = body;
  renderChains(data);
}

function chip(id, data) {
  const ip = id === "V" ? data.topology.nodes.find((n) => n.id === "V").ip : data.forged_ips[id] ?? data.topology.nodes.find((n) => n.id === id)?.ip;
  const cls = id === "V" ? "chip victim" : id.startsWith("F") ? "chip forged" : "chip";
  return el("span", { class: cls }, id === "V" ? "Victim" : nodeName(id), el("span", { class: "mono", text: ip ?? "" }));
}

function chainRow(name, ids, data, truth) {
  const row = el("div", { class: "chain" }, el("span", { class: "chain-name", text: name }));
  const MAX = 22;
  let prev = "V";
  row.append(chip("V", data));
  ids.slice(0, MAX).forEach((id) => {
    const ok = truth.has(`${id}>${prev}`);
    row.append(el("span", { class: ok ? "arrow" : "arrow bad", "aria-label": ok ? "correct link" : "wrong link", text: ok ? "←" : "✕" }));
    row.append(chip(id, data));
    prev = id;
  });
  if (ids.length > MAX) row.append(el("span", { class: "chain-name", text: `and ${ids.length - MAX} more` }));
  return row;
}

function renderChains(data) {
  const truth = new Set();
  for (const path of Object.values(data.topology.attack_paths)) {
    [...path, "V"].reduce((child, parent) => (truth.add(`${child}>${parent}`), parent));
  }
  const box = $("path-chain");
  if (data.config.scheme === "node") {
    const ids = data.reconstruction.ranking.map((r) => r.router);
    box.replaceChildren(chainRow("Routers ranked by marks received, read outward from the victim", ids, data, truth));
  } else {
    // Forged edges hang off the far end of a real path. Show each real path
    // once and list the fake addresses attached to its far end.
    const byKey = new Map();
    for (const raw of data.reconstruction.paths) {
      const outward = [...raw].reverse();
      const real = outward.filter((id) => !id.startsWith("F"));
      const fakes = outward.filter((id) => id.startsWith("F"));
      const key = real.join(">");
      if (!byKey.has(key)) byKey.set(key, { real, fakes: new Set() });
      fakes.forEach((f) => byKey.get(key).fakes.add(f));
    }
    // Drop paths that are a prefix of a longer one (left behind by forged leaves).
    const entries = [...byKey.values()].filter((e) =>
      ![...byKey.values()].some((o) => o !== e && o.real.length > e.real.length && e.real.every((id, i) => o.real[i] === id)));
    box.replaceChildren(...entries.map((e, i) => {
      const row = chainRow(`Rebuilt path ${i + 1}, outward from the victim`, e.real, data, truth);
      if (e.fakes.size) {
        row.append(el("span", { class: "arrow bad", text: "✕" }));
        [...e.fakes].sort().forEach((f) => row.append(chip(f, data)));
      }
      return row;
    }));
  }
}

/* ---------------------------------------------------------------- experiments */

async function loadExperiments() {
  try {
    const [pSweep, dSweep] = await Promise.all([
      fetch("/api/experiments?variable=p&fixed=15").then((r) => r.json()),
      fetch("/api/experiments?variable=d&fixed=0.04").then((r) => r.json()),
    ]);
    experimentChart($("exp-p-chart"), pSweep);
    experimentChart($("exp-d-chart"), dSweep);
    writeFindings(pSweep, dSweep);
  } catch {
    $("exp-summary").textContent = "Couldn’t load the experiments. Check that the server is running, then reload the page.";
  }
}

function writeFindings(pSweep, dSweep) {
  const at = pSweep.rows.find((r) => r.p === 0.04);
  const bestEdge = pSweep.rows.reduce((a, b) => (b.edge.median < a.edge.median ? b : a));
  const nodeOk = pSweep.rows.filter((r) => r.node.median != null);
  const bestNode = nodeOk.reduce((a, b) => (b.node.median < a.node.median ? b : a));
  const d25 = dSweep.rows.at(-1);
  const items = [];
  if (at?.node.median && at.edge.median) {
    items.push(`For a 15-hop path at p = 0.04, node sampling needed <strong>${fmt(at.node.median)}</strong> packets and edge sampling <strong>${fmt(at.edge.median)}</strong>, about ${fmt(at.node.median / at.edge.median)} times fewer.`);
    const round2 = (n) => { const m = 10 ** Math.max(0, Math.floor(Math.log10(n)) - 1); return Math.round(n / m) * m; };
    $("cmp-node").textContent = `about ${fmt(round2(at.node.median))}`;
    $("cmp-edge").textContent = `about ${fmt(round2(at.edge.median))}`;
  }
  items.push(`Edge sampling was fastest at p = ${bestEdge.p}. The paper recommends p close to 1/d, which is ${(1 / 15).toFixed(3)} for 15 hops.`);
  items.push(`Node sampling did best at p = ${bestNode.p}, but still needed ${fmt(bestNode.node.median)} packets. Large p hurts both schemes: marks from far routers are almost always overwritten.`);
  if (d25.edge.median) items.push(`Doubling the path length has little cost for edge sampling (${fmt(d25.edge.median)} packets at 25 hops) but raises node sampling to ${d25.node.median ? fmt(d25.node.median) : "more than 300,000"}.`);
  $("findings").replaceChildren(...items.map((h) => { const li = el("li"); li.innerHTML = h; return li; }));
}

/* ---------------------------------------------------------------- start */

renderScenarios();
applySettings(SCENARIOS[0].s);
markScenario(0);
run();
loadExperiments();
