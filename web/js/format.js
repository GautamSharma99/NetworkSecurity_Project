export const fmt = (n) => Math.round(n).toLocaleString("en-US");

export const pct = (x, digits = 1) => `${(x * 100).toFixed(digits).replace(/\.0+$/, "")}%`;

export const prefersReducedMotion = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export const css = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(child));
  }
  return node;
}

/** Display name for any node id: routers keep their id, the rest get words. */
export function nodeName(id) {
  if (id === "V") return "Victim";
  if (id.startsWith("A")) return `Attacker ${id.slice(1)}`;
  if (id.startsWith("H")) return `Host ${id.slice(1)}`;
  if (id.startsWith("F")) return `Fake ${id.slice(1)}`;
  return id;
}
