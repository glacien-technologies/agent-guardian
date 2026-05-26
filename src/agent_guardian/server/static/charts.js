/* SVG radar chart for the six AIVSS sub-scores. Hand-rendered, no
 * dependencies. The host element exposes the data via a `data-radar`
 * attribute holding a JSON array of `{ name, score }` objects.
 */

const RADIUS = 90;

/** @param {HTMLElement} host */
export function mountRadar(host) {
  const raw = host.getAttribute("data-radar");
  if (!raw) return;
  let points;
  try {
    points = JSON.parse(raw);
  } catch (err) {
    return;
  }
  if (!Array.isArray(points) || points.length === 0) return;

  const svg = host.querySelector("svg.radar");
  if (!(svg instanceof SVGElement)) return;

  // Compute vertex positions on the polar grid; angle 0 = top.
  const n = points.length;
  const vertices = points.map((p, i) => {
    const angleDeg = -90 + (360 * i) / n;
    const angleRad = (Math.PI * angleDeg) / 180;
    const score = Math.max(0, Math.min(100, Number(p.score) || 0));
    const r = (RADIUS * score) / 100;
    return {
      x: r * Math.cos(angleRad),
      y: r * Math.sin(angleRad),
      labelX: (RADIUS + 14) * Math.cos(angleRad),
      labelY: (RADIUS + 14) * Math.sin(angleRad),
      name: String(p.name || ""),
    };
  });

  // Axes.
  for (let i = 0; i < n; i++) {
    const angleDeg = -90 + (360 * i) / n;
    const angleRad = (Math.PI * angleDeg) / 180;
    const x = RADIUS * Math.cos(angleRad);
    const y = RADIUS * Math.sin(angleRad);
    const axis = document.createElementNS("http://www.w3.org/2000/svg", "line");
    axis.setAttribute("x1", "0");
    axis.setAttribute("y1", "0");
    axis.setAttribute("x2", String(x));
    axis.setAttribute("y2", String(y));
    axis.setAttribute("class", "radar-axis");
    svg.appendChild(axis);
  }

  // Polygon.
  const polygon = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
  const pts = vertices.map((v) => `${v.x.toFixed(2)},${v.y.toFixed(2)}`).join(" ");
  polygon.setAttribute("points", pts);
  polygon.setAttribute("class", "radar-shape");
  svg.appendChild(polygon);

  // Vertex dots.
  for (const v of vertices) {
    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", v.x.toFixed(2));
    dot.setAttribute("cy", v.y.toFixed(2));
    dot.setAttribute("r", "2.5");
    dot.setAttribute("class", "radar-vertex");
    svg.appendChild(dot);
  }

  // Labels.
  for (const v of vertices) {
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", v.labelX.toFixed(2));
    text.setAttribute("y", v.labelY.toFixed(2));
    text.setAttribute("class", "radar-label");
    // Word-wrap the snake_case name by replacing underscores with line breaks
    // in two short halves for readability.
    const parts = v.name.split("_");
    if (parts.length > 1) {
      const mid = Math.ceil(parts.length / 2);
      text.textContent = parts.slice(0, mid).join(" ");
      const tspan = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
      tspan.setAttribute("x", v.labelX.toFixed(2));
      tspan.setAttribute("dy", "10");
      tspan.textContent = parts.slice(mid).join(" ");
      text.appendChild(tspan);
    } else {
      text.textContent = v.name;
    }
    svg.appendChild(text);
  }
}
