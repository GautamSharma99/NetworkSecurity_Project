/* Chart.js wrappers for the live trace and the experiments. */

import { css, fmt, nodeName } from "./format.js";

function baseDefaults() {
  Chart.defaults.font.family = css("--sans");
  Chart.defaults.font.size = 12;
  Chart.defaults.color = css("--muted");
  Chart.defaults.borderColor = css("--rule-soft");
  Chart.defaults.plugins.legend.labels.boxWidth = 14;
  Chart.defaults.plugins.legend.labels.boxHeight = 2;
  Chart.defaults.plugins.tooltip.backgroundColor = css("--ink");
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 6;
  Chart.defaults.animation.duration = 250;
}

/** Vertical marker at a given x value (used for "path complete"). */
const markerPlugin = {
  id: "marker",
  afterDatasetsDraw(chart, _args, opts) {
    if (opts.x == null) return;
    const { ctx, chartArea, scales } = chart;
    const x = scales.x.getPixelForValue(opts.x);
    if (x < chartArea.left || x > chartArea.right) return;
    ctx.save();
    ctx.strokeStyle = opts.color;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(x, chartArea.top);
    ctx.lineTo(x, chartArea.bottom);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = opts.color;
    ctx.font = `600 11px ${css("--sans")}`;
    const label = opts.label;
    const w = ctx.measureText(label).width;
    const tx = x + 6 + w > chartArea.right ? x - 6 - w : x + 6;
    ctx.fillText(label, tx, chartArea.top + 12);
    ctx.restore();
  },
};

export class TraceCharts {
  constructor(tallyCanvas, recoveryCanvas) {
    baseDefaults();
    Chart.register(markerPlugin);
    this.tally = new Chart(tallyCanvas, {
      type: "bar",
      data: { labels: [], datasets: [] },
      options: {
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { position: "top", align: "end" },
          tooltip: {
            callbacks: {
              title: (items) => {
                const row = this.rows?.[items[0].dataIndex];
                if (!row) return "";
                return row.forged ? `${nodeName(row.router)} (forged), ${row.ip}` : `${row.router}, ${row.ip}, ${row.depth} hop${row.depth === 1 ? "" : "s"} away`;
              },
              label: (item) => `${item.dataset.label}: ${item.raw == null ? "n/a" : fmt(item.raw)}`,
            },
          },
        },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, autoSkipPadding: 6 }, title: { display: true, text: "Routers, nearest the victim first" } },
          y: { beginAtZero: true, ticks: { callback: (v) => fmt(v) }, title: { display: true, text: "Marks" } },
        },
      },
    });

    this.recovery = new Chart(recoveryCanvas, {
      type: "line",
      data: { datasets: [] },
      options: {
        maintainAspectRatio: false,
        animation: false,
        parsing: false,
        interaction: { mode: "nearest", axis: "x", intersect: false },
        plugins: {
          legend: { position: "top", align: "end" },
          marker: { x: null, color: css("--victim"), label: "" },
          tooltip: {
            callbacks: {
              title: (items) => `${fmt(items[0].parsed.x)} packets`,
              label: (item) => (item.datasetIndex === 0 ? `Path recovered: ${Math.round(item.parsed.y)}%` : `Wrong links: ${item.parsed.y}`),
            },
          },
        },
        scales: {
          x: { type: "logarithmic", title: { display: true, text: "Packets received (log scale)" }, ticks: { callback: (v) => (/^[125]/.test(String(v)) ? fmt(v) : "") } },
          y: { min: 0, max: 100, ticks: { callback: (v) => `${v}%` } },
          y1: { position: "right", beginAtZero: true, grid: { display: false }, display: false, ticks: { precision: 0 }, title: { display: true, text: "Wrong links" } },
        },
      },
    });
  }

  reset(data) {
    const mark = css("--mark"), forged = css("--forged"), ink = css("--ink");
    this.data = data;
    this.rows = data.tally;
    const rows = this.rows;
    this.tally.data.labels = rows.map((r) => (r.forged ? nodeName(r.router) : r.router));
    this.tally.data.datasets = [
      {
        type: "bar", label: "Marks counted", data: rows.map(() => 0),
        backgroundColor: rows.map((r) => (r.forged ? forged : mark)),
        borderRadius: 2, barPercentage: 0.82, categoryPercentage: 0.9, order: 2,
      },
      {
        type: "line", label: "Expected", data: rows.map((r) => (r.expected == null ? null : 0)),
        borderColor: ink, borderWidth: 1.5, borderDash: [5, 4], pointRadius: 0, tension: 0.25, spanGaps: false, order: 1,
      },
    ];
    this.tally.update();

    const anyFalse = data.timeline.some((t) => t.false_links > 0);
    this.recovery.options.scales.x.min = data.timeline[0]?.packets ?? 1;
    this.recovery.options.scales.x.max = data.config.packets;
    this.recovery.options.scales.y1.display = anyFalse;
    this.recovery.options.plugins.marker.x = null;
    this.recovery.data.datasets = [
      { label: "Path recovered", data: [], borderColor: mark, backgroundColor: mark, borderWidth: 2.5, pointRadius: 0, tension: 0.2, yAxisID: "y" },
    ];
    if (anyFalse) {
      this.recovery.data.datasets.push({ label: "Wrong links", data: [], borderColor: forged, backgroundColor: forged, borderWidth: 1.8, borderDash: [5, 4], pointRadius: 0, stepped: true, yAxisID: "y1" });
    }
    this.recovery.update();
  }

  /** Show the state after timeline frame ``i``. */
  frame(i) {
    const { data } = this;
    const t = data.timeline[i];
    const share = t.packets / data.config.packets;
    this.tally.data.datasets[0].data = this.rows.map((r) => t.tally[r.router] ?? 0);
    this.tally.data.datasets[1].data = this.rows.map((r) => (r.expected == null ? null : r.expected * share));
    this.tally.update("none");

    const pts = data.timeline.slice(0, i + 1);
    this.recovery.data.datasets[0].data = pts.map((p) => ({ x: p.packets, y: p.recovered * 100 }));
    if (this.recovery.data.datasets[1]) {
      this.recovery.data.datasets[1].data = pts.map((p) => ({ x: p.packets, y: p.false_links }));
    }
    const done = data.first_complete ?? data.first_recovered;
    if (done != null && t.packets >= done) {
      this.recovery.options.plugins.marker.x = done;
      this.recovery.options.plugins.marker.label = `Complete by ${fmt(done)}`;
    }
    this.recovery.update("none");
  }
}

export function experimentChart(canvas, sweep) {
  const mark = css("--mark"), ink = css("--ink"), muted = css("--muted");
  const rows = sweep.rows;
  const isP = sweep.variable === "p";
  const labels = rows.map((r) => (isP ? String(r.p) : String(r.d)));
  const series = (fn) => rows.map(fn);
  return new Chart(canvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Node sampling", data: series((r) => r.node.median), borderColor: ink, backgroundColor: ink, borderWidth: 2.2, pointRadius: 3.5, spanGaps: false },
        { label: "Edge sampling", data: series((r) => r.edge.median), borderColor: mark, backgroundColor: mark, borderWidth: 2.2, pointRadius: 3.5 },
        { label: "Edge sampling bound", data: series((r) => r.theory_edge_bound), borderColor: mark, borderWidth: 1.3, borderDash: [5, 4], pointRadius: 0 },
        { label: "Least possible for node sampling", data: series((r) => r.theory_node_minimum), borderColor: muted, borderWidth: 1.3, borderDash: [2, 4], pointRadius: 0 },
      ],
    },
    options: {
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "bottom", align: "start", labels: { padding: 14 } },
        tooltip: {
          callbacks: {
            title: (items) => (isP ? `p = ${items[0].label}, 15 hops` : `${items[0].label} hops, p = ${sweep.fixed}`),
            label: (item) => `${item.dataset.label}: ${item.raw == null ? "did not finish" : fmt(item.raw)}`,
          },
        },
      },
      scales: {
        x: { title: { display: true, text: isP ? "Marking probability p" : "Path length d (hops)" }, grid: { display: false } },
        y: { type: "logarithmic", title: { display: true, text: "Packets needed" }, ticks: { callback: (v) => (/^1/.test(String(v)) ? fmt(v) : "") } },
      },
    },
  });
}
