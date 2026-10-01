'use strict';

/**
 * Cerberus charts — dependency-free SVG chart helpers.
 * Every chart renders role="img" with a <title> for screen readers and
 * falls back to an .empty message when there is no data.
 */

window.Charts = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  const MONO = "ui-monospace, 'Cascadia Code', Consolas, monospace";

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function svgEl(tag, attrs = {}) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    return n;
  }

  function textEl(x, y, str, { size = 10, fill = '#8296ab', anchor = 'start', weight = 'normal' } = {}) {
    const t = svgEl('text', { x, y, 'font-size': size, fill, 'text-anchor': anchor, 'font-family': MONO, 'font-weight': weight });
    t.textContent = str;
    return t;
  }

  function fmtBytes(n) {
    if (!Number.isFinite(n)) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
    return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  function empty(el, msg) {
    el.innerHTML = `<div class="empty">${esc(msg || 'No data yet')}</div>`;
  }

  function titled(svg, title) {
    const t = document.createElementNS(NS, 'title');
    t.textContent = title;
    svg.appendChild(t);
    svg.setAttribute('role', 'img');
  }

  /**
   * Horizontal bar chart.
   * opts: { data: [{label, value, color}], unit?: string, max?: number, title?: string }
   */
  function bar(el, opts = {}) {
    const data = (opts.data || []).filter((d) => Number.isFinite(d.value));
    if (!data.length) return empty(el);
    const rowH = 20;
    const gap = 7;
    const labelW = 52;
    const valW = 78;
    const width = Math.max(el.clientWidth || 560, 320);
    const height = data.length * (rowH + gap);
    const plotW = width - labelW - valW;
    const max = opts.max || Math.max(...data.map((d) => d.value), 1);

    const svg = svgEl('svg', { viewBox: `0 0 ${width} ${height}`, width: '100%', height, 'aria-label': opts.title || 'bar chart' });
    titled(svg, opts.title || 'Bar chart');

    data.forEach((d, i) => {
      const y = i * (rowH + gap);
      const w = Math.max(2, (d.value / max) * plotW);
      svg.appendChild(svgEl('rect', { x: labelW, y, width: plotW, height: rowH, rx: 4, fill: 'rgba(34,48,66,0.4)' }));
      svg.appendChild(svgEl('rect', { x: labelW, y, width: w, height: rowH, rx: 4, fill: d.color || '#4da3ff' }));
      svg.appendChild(textEl(labelW - 8, y + rowH / 2 + 4, d.label, { anchor: 'end' }));
      svg.appendChild(textEl(labelW + plotW + 8, y + rowH / 2 + 4, opts.unit === 'bytes' ? fmtBytes(d.value) : `${d.value}`, { fill: '#d7e1ee' }));
    });
    el.innerHTML = '';
    el.appendChild(svg);
  }

  /**
   * Donut chart with side legend.
   * opts: { data: [{label, value, color}], centerLabel?, centerValue?, title? }
   */
  function donut(el, opts = {}) {
    const data = (opts.data || []).filter((d) => Number.isFinite(d.value) && d.value > 0);
    if (!data.length) return empty(el);
    const total = data.reduce((s, d) => s + d.value, 0);
    const size = 170;
    const r = 60;
    const cx = size / 2;
    const cy = size / 2;
    const C = 2 * Math.PI * r;

    const svg = svgEl('svg', { viewBox: `0 0 ${size} ${size}`, width: 170, height: 170, 'aria-label': opts.title || 'donut chart' });
    titled(svg, opts.title || 'Donut chart');
    svg.appendChild(svgEl('circle', { cx, cy, r, fill: 'none', stroke: 'rgba(34,48,66,0.6)', 'stroke-width': 26 }));

    let offset = 0;
    for (const d of data) {
      const frac = d.value / total;
      const seg = svgEl('circle', {
        cx, cy, r,
        fill: 'none',
        stroke: d.color || '#4da3ff',
        'stroke-width': 26,
        'stroke-dasharray': `${(frac * C).toFixed(2)} ${C.toFixed(2)}`,
        'stroke-dashoffset': (-offset * C).toFixed(2),
        transform: `rotate(-90 ${cx} ${cy})`,
      });
      const t = document.createElementNS(NS, 'title');
      t.textContent = `${d.label}: ${d.value} (${Math.round(frac * 100)}%)`;
      seg.appendChild(t);
      svg.appendChild(seg);
      offset += frac;
    }
    svg.appendChild(textEl(cx, cy - 2, String(opts.centerValue ?? total), { anchor: 'middle', size: 22, fill: '#d7e1ee', weight: '700' }));
    svg.appendChild(textEl(cx, cy + 16, opts.centerLabel || 'total', { anchor: 'middle', size: 9 }));

    const legend = data.map((d) => `
      <div style="display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text);margin:4px 0;">
        <span style="width:10px;height:10px;border-radius:3px;background:${d.color};flex:none;"></span>
        <span style="flex:1;">${esc(d.label)}</span>
        <span style="font-family:${MONO};color:var(--muted);">${d.value} · ${Math.round((d.value / total) * 100)}%</span>
      </div>`).join('');

    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">
        <div style="flex:none;" class="donut-slot"></div>
        <div style="flex:1;min-width:180px;">${legend}</div>
      </div>`;
    el.querySelector('.donut-slot').appendChild(svg);
  }

  /**
   * Area/time-series chart.
   * opts: { points: [{label, value}], color?, title?, unit? }
   */
  function area(el, opts = {}) {
    const points = (opts.points || []).filter((p) => Number.isFinite(p.value));
    if (!points.length) return empty(el);
    const width = Math.max(el.clientWidth || 560, 320);
    const height = 190;
    const padL = 34;
    const padR = 10;
    const padT = 12;
    const padB = 24;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;
    const max = Math.max(...points.map((p) => p.value), 1);
    const color = opts.color || '#e74c3c';
    const stepX = points.length > 1 ? plotW / (points.length - 1) : plotW;

    const xy = (i, v) => ({ x: padL + i * stepX, y: padT + plotH - (v / max) * plotH });

    const svg = svgEl('svg', { viewBox: `0 0 ${width} ${height}`, width: '100%', height, 'aria-label': opts.title || 'time series' });
    titled(svg, opts.title || 'Time series');

    // gridlines + y labels
    const gridLines = 4;
    for (let g = 0; g <= gridLines; g++) {
      const gy = padT + (plotH / gridLines) * g;
      const val = Math.round(max - (max / gridLines) * g);
      svg.appendChild(svgEl('line', { x1: padL, y1: gy, x2: width - padR, y2: gy, stroke: '#1c2836', 'stroke-width': 1 }));
      svg.appendChild(textEl(padL - 6, gy + 3, String(val), { anchor: 'end', size: 9 }));
    }

    // area + line
    const pts = points.map((p, i) => xy(i, p.value));
    const lineD = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaD = `${lineD} L${pts[pts.length - 1].x.toFixed(1)},${padT + plotH} L${pts[0].x.toFixed(1)},${padT + plotH} Z`;
    svg.appendChild(svgEl('path', { d: areaD, fill: color, opacity: 0.15 }));
    svg.appendChild(svgEl('path', { d: lineD, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linejoin': 'round' }));

    // dots + sparse x labels
    const labelEvery = Math.max(1, Math.ceil(points.length / 8));
    points.forEach((p, i) => {
      const { x, y } = xy(i, p.value);
      const dot = svgEl('circle', { cx: x, cy: y, r: p.value ? 3 : 2, fill: p.value ? color : '#223042' });
      const t = document.createElementNS(NS, 'title');
      t.textContent = `${p.label}: ${p.value}`;
      dot.appendChild(t);
      svg.appendChild(dot);
      if (i % labelEvery === 0 || i === points.length - 1) {
        svg.appendChild(textEl(x, height - 8, p.label, { anchor: 'middle', size: 9 }));
      }
    });

    el.innerHTML = '';
    el.appendChild(svg);
  }

  return { bar, donut, area, fmtBytes };
})();
