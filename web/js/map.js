/* Network map: a horizontal tree with attackers on the left and the victim on
   the right, so packets visibly flow left to right. */

import { fmt, nodeName, prefersReducedMotion } from "./format.js";

const HOP_MS = 75;

export class NetworkMap {
  constructor(svg, tooltip) {
    this.svg = d3.select(svg);
    this.tooltipEl = tooltip;
    this.data = null;
    this.tally = {};
    this.maxTally = 1;
    this.overlay = false;
    this.pos = new Map();

    let resizeTimer;
    new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => this.data && this.redraw(), 120);
    }).observe(svg);
  }

  /** Draw a fresh network for a new simulation result. */
  render(data) {
    this.data = data;
    this.tally = {};
    this.overlay = false;
    const finalTally = data.timeline.at(-1)?.tally ?? {};
    this.maxTally = Math.max(1, ...Object.values(finalTally));
    this.redraw();
  }

  redraw() {
    const { data } = this;
    const svgEl = this.svg.node();
    const W = svgEl.clientWidth || 900;
    const H = svgEl.clientHeight || 520;
    this.svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove();

    const forgedIds = Object.keys(data.forged_ips);
    const narrow = W < 640;
    const margin = {
      top: 52,
      right: narrow ? 56 : 96,
      bottom: forgedIds.length ? 74 : 26,
      left: narrow ? 42 : 64,
    };
    const innerW = W - margin.left - margin.right;
    const innerH = H - margin.top - margin.bottom;

    const nodes = data.topology.nodes;
    const root = d3.stratify().id((d) => d.id).parentId((d) => d.parent)(nodes);
    // Keep attack branches together and in a stable order.
    root.sort((a, b) => d3.ascending(a.data.id, b.data.id));
    const maxDepth = d3.max(nodes, (d) => d.depth);
    d3.tree().size([innerH, innerW]).separation((a, b) => (a.parent === b.parent ? 1 : 1.25))(root);

    const step = innerW / maxDepth;
    this.pos.clear();
    root.each((n) => {
      this.pos.set(n.data.id, { x: margin.left + innerW - n.data.depth * step, y: margin.top + n.x, d: n.data });
    });

    const leaves = root.leaves().length;
    const spacing = innerH / Math.max(leaves, 1);
    this.r = Math.max(3.5, Math.min(7, spacing * 0.38, step * 0.3));
    const showRouterLabels = nodes.length <= 48 && step > 30;

    const attackLinks = new Set();
    for (const path of Object.values(data.topology.attack_paths)) {
      [...path, "V"].reduce((child, parent) => (attackLinks.add(`${child}>${parent}`), parent));
    }
    this.attackLinks = attackLinks;
    const onAttack = new Set(Object.values(data.topology.attack_paths).flat());

    // Forged addresses sit in a band under the tree.
    if (forgedIds.length) {
      const bandY = H - 34;
      const nodeScheme = data.config.scheme === "node";
      forgedIds.forEach((id, i) => {
        const x = nodeScheme
          ? margin.left + innerW - (i + 1) * Math.min(64, step * 1.6)
          : margin.left + innerW * (0.08 + i * 0.07);
        this.pos.set(id, { x, y: bandY, d: { id, kind: "forged", ip: data.forged_ips[id] } });
      });
      this.svg.append("text").attr("class", "band-label")
        .attr("x", nodeScheme ? margin.left + innerW - (forgedIds.length + 0.6) * Math.min(64, step * 1.6) : margin.left + innerW * 0.08 + forgedIds.length * innerW * 0.07)
        .attr("y", bandY + 4)
        .attr("text-anchor", nodeScheme ? "end" : "start")
        .text("Forged addresses (no such routers)");
    }

    // Base links
    const gLinks = this.svg.append("g");
    gLinks.selectAll("path").data(nodes.filter((d) => d.parent)).join("path")
      .attr("class", (d) => `link${attackLinks.has(`${d.id}>${d.parent}`) || d.kind === "attacker" ? " attack" : ""}`)
      .attr("d", (d) => this.linkPath(d.id, d.parent));

    this.gOverlay = this.svg.append("g");
    this.gPackets = this.svg.append("g");
    const gNodes = this.svg.append("g");

    const r = this.r;
    const sel = gNodes.selectAll("g").data([...this.pos.values()].map((p) => p.d)).join("g")
      .attr("transform", (d) => `translate(${this.pos.get(d.id).x},${this.pos.get(d.id).y})`)
      .attr("class", (d) => (d.kind === "forged" ? "forged-node" : d.kind === "router" && !onAttack.has(d.id) ? "router idle" : d.kind));

    sel.filter((d) => d.kind === "router").each(function () {
      const g = d3.select(this);
      g.append("circle").attr("class", "body").attr("r", r);
      g.append("circle").attr("class", "ink").attr("r", 0);
    });
    sel.filter((d) => d.kind === "forged").append("circle").attr("r", r + 1.5);
    sel.filter((d) => d.kind === "host").append("rect")
      .attr("x", -r * 0.85).attr("y", -r * 0.85).attr("width", r * 1.7).attr("height", r * 1.7).attr("rx", 1.5);
    sel.filter((d) => d.kind === "attacker").append("path")
      .attr("d", `M0,${-r * 1.5} L${r * 1.5},0 L0,${r * 1.5} L${-r * 1.5},0Z`);
    sel.filter((d) => d.kind === "victim").append("circle").attr("r", Math.max(10, r * 1.9));

    // Labels
    sel.filter((d) => d.kind === "victim").call((g) => {
      g.append("text").attr("class", "node-label strong").attr("x", 0).attr("y", -r * 1.9 - 10).attr("text-anchor", "middle").text("Victim");
      if (!narrow) g.append("text").attr("class", "node-ip").attr("x", 0).attr("y", r * 1.9 + 18).attr("text-anchor", "middle").text((d) => d.ip);
    });
    sel.filter((d) => d.kind === "attacker").append("text").attr("class", "node-label strong")
      .attr("x", -r * 1.5 - 6).attr("y", 4).attr("text-anchor", "end").text((d) => d.id);
    if (showRouterLabels) {
      sel.filter((d) => d.kind === "router" && onAttack.has(d.id)).append("text").attr("class", "node-label")
        .attr("x", 0).attr("y", -r - 5).attr("text-anchor", "middle").text((d) => d.id);
    }

    // Hover targets
    sel.append("circle").attr("class", "hit").attr("r", Math.max(r + 4, 10))
      .on("pointerenter", (event, d) => this.showTooltip(d))
      .on("pointerleave", () => (this.tooltipEl.hidden = true));

    this.nodeSel = sel;
    this.setTally(this.tally);
    if (this.overlay) this.showReconstruction(false);
  }

  linkPath(a, b) {
    const p = this.pos.get(a), q = this.pos.get(b);
    if (!p || !q) return null;
    const mx = (p.x + q.x) / 2;
    return `M${p.x},${p.y} C${mx},${p.y} ${mx},${q.y} ${q.x},${q.y}`;
  }

  arcPath(a, b) {
    const p = this.pos.get(a), q = this.pos.get(b);
    if (!p || !q) return null;
    const dx = q.x - p.x, dy = q.y - p.y;
    const bend = 0.25;
    const cx = (p.x + q.x) / 2 - dy * bend, cy = (p.y + q.y) / 2 + dx * bend;
    return `M${p.x},${p.y} Q${cx},${cy} ${q.x},${q.y}`;
  }

  showTooltip(d) {
    const p = this.pos.get(d.id);
    const marks = this.tally[d.id] ?? 0;
    const lines = [`<strong>${nodeName(d.id)}</strong>`];
    if (d.ip) lines.push(`<span class="mono">${d.ip}</span>`);
    if (d.kind === "router") lines.push(`${d.depth} hop${d.depth === 1 ? "" : "s"} from the victim`, `${fmt(marks)} marks received so far`);
    if (d.kind === "attacker") lines.push("Sends every packet with a random fake source address");
    if (d.kind === "host") lines.push("Ordinary host, sends no attack traffic");
    if (d.kind === "forged") lines.push(`Written by the attacker. ${fmt(marks)} packets arrived carrying it`);
    const tip = this.tooltipEl;
    tip.innerHTML = lines.join("<br>");
    tip.hidden = false;
    const box = this.svg.node().getBoundingClientRect();
    const scale = box.width / (this.svg.node().viewBox.baseVal.width || box.width);
    const left = Math.min(p.x * scale + 14, box.width - 250);
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${p.y * scale + 14}px`;
  }

  /** Shade each router by the share of marks it has received. */
  setTally(tally) {
    this.tally = tally;
    if (!this.nodeSel) return;
    const r = this.r, max = this.maxTally;
    this.nodeSel.select("circle.ink").attr("r", (d) => {
      const c = tally[d.id] ?? 0;
      return c ? Math.max(1.6, r * Math.sqrt(c / max)) : 0;
    });
  }

  /** Animate one packet from its attacker to the victim. */
  sendPacket(trace, scheme) {
    if (!this.gPackets || prefersReducedMotion()) return;
    const stops = [...trace.hops.map((h) => h), { at: "V", action: "arrive", mark: trace.hops.at(-1).mark }];
    const state = (mark) => {
      const v = scheme === "node" ? mark.node : mark.start;
      if (!v) return "";
      return v.startsWith("F") ? "forged" : "marked";
    };
    const first = this.pos.get(stops[0].at);
    if (!first) return;
    const dot = this.gPackets.append("circle").attr("class", `packet-dot ${state(stops[0].mark)}`)
      .attr("r", Math.max(2.4, this.r * 0.5)).attr("cx", first.x).attr("cy", first.y);

    let t = dot;
    stops.slice(1).forEach((stop) => {
      const p = this.pos.get(stop.at);
      if (!p) return;
      t = t.transition().duration(HOP_MS).ease(d3.easeLinear).attr("cx", p.x).attr("cy", p.y)
        .on("end", () => {
          dot.attr("class", `packet-dot ${state(stop.mark)}`);
          if (stop.action === "mark" || stop.action === "overwrite") this.pulse(p);
        });
    });
    t.transition().duration(160).attr("r", 0).remove();
  }

  pulse(p) {
    this.gPackets.append("circle").attr("class", "pulse").attr("cx", p.x).attr("cy", p.y).attr("r", this.r)
      .attr("opacity", 0.9)
      .transition().duration(520).attr("r", this.r * 3).attr("opacity", 0).remove();
  }

  stopPackets() {
    this.gPackets?.selectAll("*").interrupt().remove();
  }

  /** Draw the victim's reconstruction over the map. */
  showReconstruction(animate = true) {
    this.overlay = true;
    const { data } = this;
    const g = this.gOverlay;
    g.selectAll("*").remove();
    const links = data.reconstruction.links;
    const found = new Set(links.map((l) => `${l.from}>${l.to}`));

    // Real attack links the victim did not rebuild.
    const missed = [...this.attackLinks].filter((k) => !found.has(k)).map((k) => k.split(">"));
    g.selectAll(".missed-link").data(missed).join("path").attr("class", "missed-link")
      .attr("d", ([a, b]) => this.linkPath(a, b));

    // Order links outward from the victim so the reveal walks back toward the attacker.
    const level = (id) => this.pos.get(id)?.d.depth ?? 99;
    const ordered = [...links].sort((a, b) => level(a.to) - level(b.to));

    const paths = g.selectAll(".rec").data(ordered).join("path")
      .attr("class", (l) => (l.correct ? "found-link" : l.from.startsWith("F") || l.to.startsWith("F") ? "forged-link" : "wrong-link"))
      .attr("d", (l) => (l.correct ? this.linkPath(l.from, l.to) : this.arcPath(l.from, l.to)));

    if (animate && !prefersReducedMotion()) {
      const per = Math.min(70, 1400 / Math.max(ordered.length, 1));
      paths.each(function (l, i) {
        const len = this.getTotalLength();
        const solid = l.correct;
        d3.select(this)
          .attr("stroke-dasharray", `${len} ${len}`)
          .attr("stroke-dashoffset", len)
          .transition().delay(i * per).duration(320).ease(d3.easeCubicOut)
          .attr("stroke-dashoffset", 0)
          .on("end", function () {
            d3.select(this).attr("stroke-dasharray", solid ? null : "6 5").attr("stroke-dashoffset", null);
          });
      });
    }
  }
}
