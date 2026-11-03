/* Packet inspector: step one packet through the routers hop by hop. */

import { el, nodeName, pct } from "./format.js";

export class Inspector {
  constructor(root) {
    this.$ = (id) => root.querySelector(`#${id}`);
    this.traceIndex = 0;
    this.hop = 0;
    this.$("hop-prev").addEventListener("click", () => this.go(this.hop - 1));
    this.$("hop-next").addEventListener("click", () => this.go(this.hop + 1));
    this.$("packet-next").addEventListener("click", () => this.load(this.data, this.traceIndex + 1));

    const ruler = root.querySelector(".bit-ruler");
    for (let i = 0; i < 32; i++) ruler.append(el("span", { text: String(i) }));
  }

  load(data, index = 0) {
    this.data = data;
    this.ips = Object.fromEntries(data.topology.nodes.map((n) => [n.id, n.ip]));
    Object.assign(this.ips, data.forged_ips);
    // Prefer packets that actually got marked, so the demo has something to show.
    const traces = data.traces;
    this.traceIndex = ((index % traces.length) + traces.length) % traces.length;
    this.trace = traces[this.traceIndex];
    this.stops = [...this.trace.hops, { at: "V", action: "arrive", mark: this.trace.hops.at(-1).mark }];

    const list = this.$("hop-list");
    list.replaceChildren(...this.stops.map((s) => el("li", {
      class: s.at === "V" ? "victim" : s.at.startsWith("A") ? "attacker" : "",
      text: s.at === "V" ? "Victim" : s.at,
      title: nodeName(s.at),
    })));
    this.$("ip-src").textContent = this.trace.src;
    this.$("ip-dst").textContent = this.trace.dst;
    this.go(0);
  }

  go(i) {
    const n = this.stops.length;
    this.hop = Math.max(0, Math.min(n - 1, i));
    const stop = this.stops[this.hop];
    const scheme = this.data.config.scheme;

    [...this.$("hop-list").children].forEach((li, k) => {
      const s = this.stops[k];
      li.classList.toggle("current", k === this.hop);
      li.classList.toggle("done", k <= this.hop);
      li.classList.toggle("marked", k <= this.hop && (s.action === "mark" || s.action === "overwrite"));
    });

    const routersPassed = this.stops.slice(1, this.hop + 1).filter((s) => s.at !== "V").length;
    this.$("ip-ttl").textContent = String(64 - routersPassed);

    const prev = this.hop > 0 ? this.stops[this.hop - 1].mark : null;
    this.renderMark(stop.mark, scheme, prev);
    this.$("hop-caption").textContent = this.caption(stop, scheme);
    this.$("hop-prev").disabled = this.hop === 0;
    this.$("hop-next").disabled = this.hop === n - 1;
  }

  label(id) {
    if (!id) return null;
    return `${id.startsWith("F") ? nodeName(id) : id} (${this.ips[id]})`;
  }

  renderMark(mark, scheme, prev) {
    const dl = this.$("mark-fields");
    const fields = scheme === "node"
      ? [["node", mark.node]]
      : [["start", mark.start], ["end", mark.end], ["distance", mark.distance]];
    dl.replaceChildren(...fields.flatMap(([k, v]) => {
      const isAddr = k !== "distance";
      const text = v == null ? "empty" : isAddr ? this.label(v) : String(v);
      const cls = v == null ? "empty" : isAddr && String(v).startsWith("F") ? "forged" : "";
      return [el("dt", { text: k }), el("dd", { class: cls, text })];
    }));

    const bits = this.$("ip-mark-bits");
    const summary = scheme === "node"
      ? (mark.node ?? "empty")
      : mark.start ? `${mark.start}${mark.end ? `→${mark.end}` : ""} d=${mark.distance}` : "empty";
    const changed = prev && JSON.stringify(prev) !== JSON.stringify(mark);
    bits.textContent = summary;
    const cell = bits.parentElement;
    cell.classList.remove("changed");
    if (changed) { void cell.offsetWidth; cell.classList.add("changed"); }
  }

  caption(stop, scheme) {
    const p = this.data.config.p;
    const at = stop.at;
    const markOf = (m) => (scheme === "node" ? m.node : m.start);
    switch (stop.action) {
      case "send": {
        const m = markOf(stop.mark);
        const fake = m ? ` Before sending, it writes a fake router address, ${this.label(m)}, into the mark field.` : " The mark field is empty.";
        return `${nodeName(at)} sends the packet with source address ${this.trace.src}, which is made up.${fake}`;
      }
      case "mark":
        return `${at} marks the packet: it writes its own address into the ${scheme === "node" ? "mark" : "start"} field${scheme === "edge" ? " and sets distance to 0" : ""}. Each router does this for ${pct(p)} of packets.`;
      case "overwrite": {
        const before = this.stops[this.hop - 1].mark;
        return `${at} marks the packet too, overwriting the earlier mark from ${this.label(markOf(before))}. Only the last router to mark survives.`;
      }
      case "complete":
        return `${at} doesn’t mark, but distance is 0, so the edge was just started. ${at} writes itself into the end field and sets distance to 1.`;
      case "pass":
        if (scheme === "edge" && stop.mark.start) {
          return `${at} forwards the packet without marking (${pct(1 - p)} of the time) and adds 1 to distance, now ${stop.mark.distance}.`;
        }
        return `${at} forwards the packet without marking, which happens ${pct(1 - p)} of the time.`;
      case "arrive": {
        const m = markOf(stop.mark);
        if (!m) return "The victim receives the packet. No router marked it, so it carries no clue.";
        const what = scheme === "node" ? this.label(m) : `the edge ${m}${stop.mark.end ? ` → ${stop.mark.end}` : " → victim"} at distance ${stop.mark.distance}`;
        const fake = m.startsWith("F") ? " This mark is forged: no router overwrote the attacker’s fake address." : "";
        return `The victim receives the packet. It ignores the source address and records ${what}.${fake}`;
      }
      default:
        return "";
    }
  }
}
