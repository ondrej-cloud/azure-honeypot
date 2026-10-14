/* Honeypot telemetry dashboard: renders data/stats.json with D3.
 *
 * Every string in the data (usernames, passwords, commands, URLs) was typed by
 * an attacker. It only ever reaches the DOM through textContent, createTextNode
 * or setAttribute - never innerHTML - and links are built only from values that
 * pass a strict format check. The same goes for the URL hash: drawer deep links
 * are parsed, validated and only ever compared or shown as text. */
'use strict';

(function () {
  const DEMO = new URLSearchParams(location.search).has('demo');
  const BASE = DEMO ? 'data/demo/' : 'data/';
  const DATA_URL = BASE + 'stats.json';
  const WINDOWS = ['7d', '30d', 'all'];
  const PERIOD = { '7d': '7 days', '30d': '30 days' };
  const PROTOCOL_KEY = { ssh: 's1', telnet: 's2' };   // color follows the protocol, not its rank

  // ---------------------------------------------------------------- formatting

  const nf = new Intl.NumberFormat('en-US');
  const cf = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
  const pf = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 1 });
  const full = (n) => nf.format(n);
  const compact = (n) => (Math.abs(n) < 1000 ? nf.format(n) : cf.format(n));
  const tileValue = (n) => (Math.abs(n) < 10000 ? nf.format(n) : cf.format(n));
  const share = (n, total) => pf.format(total ? n / total : 0);
  const pad2 = (n) => String(n).padStart(2, '0');

  const dayFmt = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  const dayYearFmt = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
  const weekdayFmt = new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
  const parseDay = (s) => new Date(s + 'T00:00:00Z');
  const todayUtc = () => new Date().toISOString().slice(0, 10);

  const regions = (() => {
    try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { return null; }
  })();
  function countryName(cc) {
    if (!cc || cc === '??') return 'Unknown';
    try { return (regions && regions.of(cc)) || cc; } catch (e) { return cc; }
  }

  function relativeTime(date) {
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    const minutes = Math.round((date - Date.now()) / 60000);
    if (Math.abs(minutes) < 60) return rtf.format(minutes, 'minute');
    const hours = Math.round(minutes / 60);
    if (Math.abs(hours) < 48) return rtf.format(hours, 'hour');
    return rtf.format(Math.round(hours / 24), 'day');
  }

  // ---------------------------------------------------------------- DOM helpers

  const $ = (sel) => document.querySelector(sel);

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value == null || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : String(value));
    }
    for (const child of children.flat()) {
      if (child == null || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const emptyNote = (text) => h('p', { class: 'empty-note', text: text || 'Nothing recorded in this period.' });

  /** Attacker text for display: empty strings become a visible placeholder. */
  function attackerText(value) {
    return value === '' ? h('span', { class: 'none', text: '(empty)' }) : document.createTextNode(value);
  }

  const SHA256 = /^[0-9a-f]{64}$/;
  const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  const IP_ANY = /^[0-9A-Fa-f.:]{2,45}$/;
  const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;
  const REPLAY_ID = /^[0-9a-f]{16}$/;
  const CAMPAIGN_ID = /^[a-z0-9-]{1,40}$/;
  const COUNTRY = /^(?:[A-Z]{2}|\?\?)$/;

  function externalLink(href, text, cls) {
    return h('a', { href, class: cls, target: '_blank', rel: 'noopener noreferrer', text });
  }

  const KIND_LABEL = { elf: 'ELF binary', script: 'Shell script', archive: 'Archive', html: 'HTML page',
    text: 'Text', data: 'Data', empty: 'Empty file' };

  function formatBytes(n) {
    if (!Number.isFinite(n)) return '–';
    if (n < 1024) return full(n) + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function formatDuration(ms) {
    if (!Number.isFinite(ms)) return '–';
    const s = ms / 1000;
    if (s < 60) return (s < 10 ? s.toFixed(1) : Math.round(s)) + ' s';
    const m = Math.floor(s / 60);
    if (m < 60) return m + ' min ' + Math.round(s % 60) + ' s';
    return Math.floor(m / 60) + ' h ' + (m % 60) + ' min';
  }

  /** "2026-10-14T07:46:08.72Z" -> "2026-10-14 07:46 UTC" */
  const fmtTs = (ts) => (typeof ts === 'string' && ts.length >= 16 ? ts.slice(0, 16).replace('T', ' ') + ' UTC' : '–');

  function typeLabel(meta) {
    if (!meta) return '–';
    const base = meta.kind === 'elf' ? meta.arch || 'ELF binary' : KIND_LABEL[meta.kind] || 'Unknown';
    return meta.packer ? `${base} · ${meta.packer}` : base;
  }

  function detections(intel) {
    if (!intel) return '–';
    const vt = intel.vt;
    if (vt && Number.isFinite(vt.malicious) && Number.isFinite(vt.total)) return `${vt.malicious}/${vt.total} engines`;
    if (intel.mb && intel.mb.signature) return intel.mb.signature;
    return '–';
  }

  // ---------------------------------------------------------------- tooltip

  const tip = $('#tooltip');

  function setTip(title, rows, titleClass) {
    const lines = rows.map((r) => h('div', { class: 'tip-row' },
      r.key ? h('span', { class: 'tip-key key-' + r.key }) : null,
      h('strong', { text: r.value }),
      h('span', { class: 'tip-label', text: r.label })));
    tip.replaceChildren(title ? h('div', { class: 'tip-title' + (titleClass ? ' ' + titleClass : ''), text: title }) : '', ...lines);
  }

  function placeTip(x, y) {
    tip.hidden = false;
    const gap = 14;
    const box = tip.getBoundingClientRect();
    let left = x + gap;
    let top = y + gap;
    if (left + box.width > window.innerWidth - 8) left = x - box.width - gap;
    if (top + box.height > window.innerHeight - 8) top = y - box.height - gap;
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.top = Math.max(8, top) + 'px';
  }

  const hideTip = () => { tip.hidden = true; };

  /** Hover + keyboard-focus tooltip for one mark. content() -> [title, rows, titleClass]. */
  function bindTip(node, content, onState) {
    const show = (x, y) => { setTip(...content()); placeTip(x, y); if (onState) onState(true); };
    const hide = () => { hideTip(); if (onState) onState(false); };
    node.addEventListener('pointerenter', (e) => show(e.clientX, e.clientY));
    node.addEventListener('pointermove', (e) => placeTip(e.clientX, e.clientY));
    node.addEventListener('pointerleave', hide);
    node.addEventListener('focus', () => {
      const b = node.getBoundingClientRect();
      show(b.left + Math.min(b.width / 2, 160), b.bottom - 4);
    });
    node.addEventListener('blur', hide);
  }

  window.addEventListener('scroll', hideTip, { passive: true });

  // ---------------------------------------------------------------- scales

  function roundNice(v) {
    if (v < 10) return Math.round(v);
    const p = 10 ** (Math.floor(Math.log10(v)) - 1);
    return Math.round(v / p) * p;
  }

  /** Quantile bins over non-zero values; 0 always gets the "none" step. */
  function binScale(values, bins = 6) {
    const sorted = values.filter((v) => v > 0).sort(d3.ascending);
    const thresholds = [];
    for (let i = 1; i < bins && sorted.length; i++) {
      const q = roundNice(d3.quantileSorted(sorted, i / bins));
      if (q > (thresholds.length ? thresholds[thresholds.length - 1] : 1)) thresholds.push(q);
    }
    const count = thresholds.length + 1;
    const bin = (v) => (v > 0 ? 1 + d3.bisectRight(thresholds, v) : 0);
    // Spread fewer bins over the whole ramp so a quiet week still reads light -> dark.
    const step = (b) => (b === 0 ? 0 : count === 1 ? 4 : Math.round(1 + ((b - 1) * 5) / (count - 1)));
    return { thresholds, count, bin, cls: (v) => 'seq-' + step(bin(v)), clsOfBin: (b) => 'seq-' + step(b) };
  }

  function scaleLegend(scale, unit) {
    const items = [h('span', { class: 'legend-item' }, h('span', { class: 'swatch seq-0' }), 'None')];
    for (let b = 1; b <= scale.count; b++) {
      const lo = b === 1 ? 1 : scale.thresholds[b - 2];
      const hi = b <= scale.thresholds.length ? scale.thresholds[b - 1] - 1 : null;
      const label = hi == null ? compact(lo) + '+' : lo >= hi ? compact(lo) : compact(lo) + '–' + compact(hi);
      items.push(h('span', { class: 'legend-item' }, h('span', { class: 'swatch ' + scale.clsOfBin(b) }), label));
    }
    return h('div', { class: 'legend', role: 'note', 'aria-label': 'Color scale, ' + unit }, ...items);
  }

  // ---------------------------------------------------------------- components

  /** Make a non-button element act like one (click, Enter, Space). */
  function actionable(node, action, label) {
    node.classList.add('clickable');
    node.setAttribute('role', 'button');
    if (label) node.setAttribute('aria-label', label);
    if (!node.hasAttribute('tabindex')) node.setAttribute('tabindex', '0');
    node.addEventListener('click', (e) => { if (!e.target.closest('a')) action(); });
    node.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); action(); }
    });
    return node;
  }

  /** Horizontal bar list: label, thin bar, value at the tip. Rows: {label, value, tip, text, open}. */
  function barList(body, rows, opts) {
    const o = Object.assign({ mono: false, stacked: false, wide: false, unit: 'connections', total: 0, showShare: false }, opts);
    if (!rows.length) return body.replaceChildren(emptyNote());
    const max = o.max || d3.max(rows, (r) => r.value) || 1;
    const list = h('ol', { class: 'bars' + (o.mono ? ' mono' : '') + (o.stacked ? ' stacked' : '') + (o.wide ? ' wide' : '') });
    for (const row of rows) {
      const bar = h('span', { class: 'bar' });
      bar.style.setProperty('--p', String(row.value / max));
      const val = h('span', { class: 'val' }, compact(row.value),
        o.showShare ? h('span', { class: 'share', text: share(row.value, o.total) }) : null);
      const label = row.label instanceof Node ? row.label : attackerText(row.label);
      const li = h('li', { tabindex: 0, 'aria-label': `${row.text != null ? row.text : row.label}: ${full(row.value)} ${o.unit}` },
        h('span', { class: 'label' }, label), h('span', { class: 'track' }, bar, val));
      bindTip(li, () => [
        row.text != null ? row.text : row.label === '' ? '(empty)' : row.label,
        [{ value: full(row.value), label: o.unit }].concat(o.total ? [{ value: share(row.value, o.total), label: 'of ' + (o.shareOf || 'total') }] : []).concat(row.tip || []),
        o.mono ? 'mono' : '',
      ]);
      if (row.open) actionable(li, row.open, li.getAttribute('aria-label') + '. Open details');
      list.append(li);
    }
    body.replaceChildren(list);
  }

  function renderTable(body, spec) {
    if (!spec.rows.length) return body.replaceChildren(emptyNote());
    const head = h('tr', {}, spec.columns.map((c) => h('th', { scope: 'col', class: c.num ? 'num' : null, text: c.label })));
    // Rows with an action open on click; keyboard users reach the same action through the button in the row.
    const rows = spec.rows.map((r) => h('tr', {
      class: spec.rowOpen ? 'clickable' : null,
      onclick: spec.rowOpen ? (e) => { if (!e.target.closest('a, button')) spec.rowOpen(r); } : null,
    }, spec.columns.map((c) => {
      const value = c.value(r);
      const cls = [c.num && 'num', c.mono && 'mono', c.nowrap && 'nowrap', c.cls].filter(Boolean).join(' ') || null;
      return h('td', { class: cls }, value instanceof Node ? value : c.num && typeof value === 'number' ? full(value) : String(value));
    })));
    body.replaceChildren(h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, head), h('tbody', {}, rows))));
  }

  function sparkline(values, hero) {
    if (values.length < 2) return null;
    const w = hero ? 320 : 120;
    const ht = hero ? 56 : 28;
    const x = d3.scaleLinear().domain([0, values.length - 1]).range([2, w - 4]);
    const y = d3.scaleLinear().domain([0, d3.max(values) || 1]).range([ht - 4, 4]);
    const svg = d3.create('svg').attr('class', 'spark').attr('viewBox', `0 0 ${w} ${ht}`)
      .attr('preserveAspectRatio', 'xMinYMid meet').attr('aria-hidden', 'true');
    svg.append('path').attr('class', 'spark-line').attr('d', d3.line((d, i) => x(i), y)(values));
    svg.append('circle').attr('class', 'spark-dot').attr('cx', x(values.length - 1)).attr('cy', y(values[values.length - 1])).attr('r', 3);
    return svg.node();
  }

  // ---------------------------------------------------------------- charts

  function renderActivity(body, w) {
    const data = w.daily.map((d) => Object.assign({ t: parseDay(d.date) }, d));
    const width = Math.max(300, Math.floor(body.clientWidth));
    const height = 260;
    const m = { top: 14, right: 48, bottom: 30, left: 44 };
    const x = d3.scaleUtc().range([m.left, width - m.right]);
    if (data.length > 1) x.domain(d3.extent(data, (d) => d.t));
    else x.domain([d3.utcHour.offset(data[0].t, -12), d3.utcHour.offset(data[0].t, 12)]);
    const y = d3.scaleLinear().domain([0, d3.max(data, (d) => d.sessions) || 1]).nice(4).range([height - m.bottom, m.top]);

    const svg = d3.create('svg').attr('class', 'chart').attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', width).attr('height', height).attr('role', 'img')
      .attr('aria-label', `Connections per day, ${w.label.toLowerCase()}. Use the table view for exact values.`);

    const yTicks = y.ticks(4);
    svg.append('g').selectAll('line').data(yTicks).join('line').attr('class', 'gridline')
      .attr('x1', m.left).attr('x2', width - m.right).attr('y1', (d) => y(d)).attr('y2', (d) => y(d));
    svg.append('g').attr('class', 'ticks').selectAll('text').data(yTicks).join('text')
      .attr('x', m.left - 8).attr('y', (d) => y(d)).attr('dy', '0.32em').attr('text-anchor', 'end').text(compact);
    svg.append('line').attr('class', 'baseline').attr('x1', m.left).attr('x2', width - m.right)
      .attr('y1', y(0)).attr('y2', y(0));

    // Date ticks anchored on the latest day so "today" is always labelled.
    const every = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor((width - m.left - m.right) / 84))));
    const xTicks = data.filter((d, i) => (data.length - 1 - i) % every === 0);
    svg.append('g').attr('class', 'ticks').selectAll('text').data(xTicks).join('text')
      .attr('x', (d) => x(d.t)).attr('y', height - 9).attr('text-anchor', 'middle').text((d) => dayFmt.format(d.t));

    const area = d3.area().x((d) => x(d.t)).y0(y(0)).y1((d) => y(d.sessions)).curve(d3.curveMonotoneX);
    const line = d3.line().x((d) => x(d.t)).y((d) => y(d.sessions)).curve(d3.curveMonotoneX);
    svg.append('path').attr('class', 'area').attr('d', area(data));
    svg.append('path').attr('class', 'line').attr('d', line(data));

    const last = data[data.length - 1];
    svg.append('text').attr('class', 'end-label').attr('x', x(last.t) + 8).attr('y', y(last.sessions)).attr('dy', '0.32em')
      .text(compact(last.sessions));

    const cross = svg.append('g').attr('class', 'crosshair').attr('display', 'none');
    cross.append('line').attr('y1', m.top).attr('y2', height - m.bottom);
    const dot = svg.append('circle').attr('class', 'dot').attr('r', 4).attr('display', 'none');

    const hit = svg.append('rect').attr('class', 'hit').attr('x', m.left - 8).attr('y', 0)
      .attr('width', width - m.left - m.right + 16).attr('height', height - m.bottom)
      .attr('tabindex', 0).attr('aria-label', 'Daily values. Use the left and right arrow keys to move between days.');
    let index = data.length - 1;
    const times = data.map((d) => +d.t);

    function show(i, clientX, clientY) {
      index = i;
      const d = data[i];
      cross.attr('display', null).attr('transform', `translate(${x(d.t)},0)`);
      dot.attr('display', null).attr('cx', x(d.t)).attr('cy', y(d.sessions));
      const title = weekdayFmt.format(d.t) + (d.date === todayUtc() ? ' · today, in progress' : '');
      setTip(title, [
        { value: full(d.sessions), label: 'connections', key: 's1' },
        { value: full(d.unique_ips), label: 'unique IPs' },
        { value: full(d.login_attempts), label: 'login attempts' },
        { value: full(d.commands), label: 'commands' },
      ]);
      if (clientX == null) {
        const box = svg.node().getBoundingClientRect();
        clientX = box.left + (x(d.t) * box.width) / width;
        clientY = box.top + (y(d.sessions) * box.height) / height;
      }
      placeTip(clientX, clientY);
    }
    function hide() { cross.attr('display', 'none'); dot.attr('display', 'none'); hideTip(); }

    hit.on('pointermove pointerenter', (event) => {
      const [px] = d3.pointer(event, svg.node());
      show(Math.min(data.length - 1, Math.max(0, d3.bisectCenter(times, +x.invert(px)))), event.clientX, event.clientY);
    }).on('pointerleave', hide)
      .on('focus', () => show(index))
      .on('blur', hide)
      .on('keydown', (event) => {
        const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
        if (!(event.key in moves)) return;
        event.preventDefault();
        show(Math.min(data.length - 1, Math.max(0, index + moves[event.key])));
      });

    body.replaceChildren(svg.node());
  }

  function renderMap(body, w) {
    if (!state.world) return body.replaceChildren(emptyNote('The map could not be loaded. The country list has the same data.'));
    const width = Math.max(300, Math.floor(body.clientWidth));
    const height = Math.round(width * 0.48);
    const projection = d3.geoNaturalEarth1().fitSize([width, height], state.world);
    const path = d3.geoPath(projection);
    const byCc = new Map(w.countries.map((c) => [c.cc, c]));
    const scale = binScale(w.countries.filter((c) => c.cc !== '??').map((c) => c.sessions));
    const total = w.totals.sessions;

    const svg = d3.create('svg').attr('class', 'chart map').attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', width).attr('height', height).attr('role', 'img')
      .attr('aria-label', 'World map of connections by source country. Use the table view for exact values.');
    svg.append('g').selectAll('path').data(state.world.features).join('path')
      .attr('d', path)
      .attr('class', (f) => 'country ' + scale.cls((byCc.get(f.properties.cc) || {}).sessions || 0))
      .each(function (f) {
        const c = byCc.get(f.properties.cc);
        if (c) actionable(this, () => openDrawer({ country: c.cc }), `${countryName(c.cc)}: ${full(c.sessions)} connections. Open details`);
        bindTip(this, () => [countryName(f.properties.cc), c ? [
          { value: full(c.sessions), label: 'connections' },
          { value: full(c.ips), label: 'unique IPs' },
          { value: share(c.sessions, total), label: 'of all connections' },
        ] : [{ value: '0', label: 'connections' }]], (on) => {
          d3.select(this).classed('hot', on);
          // Raising re-inserts the node, which would drop keyboard focus.
          if (on && document.activeElement !== this) d3.select(this).raise();
        });
      });
    body.replaceChildren(h('div', { class: 'map-wrap' }, svg.node()), scaleLegend(scale, 'connections per country'));
  }

  const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const DAY_LONG = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

  function renderHeatmap(body, w) {
    const width = Math.max(300, Math.floor(body.clientWidth));
    const left = 36;
    const top = 20;
    const gap = 2;
    const cellW = (width - left) / 24;
    const cellH = Math.min(28, Math.max(16, cellW));
    const height = top + 7 * cellH;
    const values = w.heatmap.flat();
    const total = d3.sum(values);
    const scale = binScale(values);

    const svg = d3.create('svg').attr('class', 'chart').attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', width).attr('height', height).attr('role', 'img')
      .attr('aria-label', 'Connections by weekday and hour (UTC). Use the table view for exact values.');
    const hourStep = cellW < 22 ? 6 : 3;
    svg.append('g').attr('class', 'ticks').selectAll('text').data(d3.range(0, 24, hourStep)).join('text')
      .attr('x', (hr) => left + hr * cellW + 1).attr('y', 12).text((hr) => pad2(hr) + ':00');
    svg.append('g').attr('class', 'ticks').selectAll('text').data(DAY_NAMES).join('text')
      .attr('x', left - 8).attr('y', (d, i) => top + i * cellH + cellH / 2).attr('dy', '0.32em')
      .attr('text-anchor', 'end').text((d) => d);
    const cells = [];
    w.heatmap.forEach((row, day) => row.forEach((value, hour) => cells.push({ day, hour, value })));
    svg.append('g').selectAll('rect').data(cells).join('rect')
      .attr('x', (c) => left + c.hour * cellW + gap / 2).attr('y', (c) => top + c.day * cellH + gap / 2)
      .attr('width', Math.max(1, cellW - gap)).attr('height', cellH - gap).attr('rx', 2)
      .attr('class', (c) => 'cell ' + scale.cls(c.value))
      .each(function (c) {
        bindTip(this, () => [`${DAY_LONG[c.day]} · ${pad2(c.hour)}:00–${pad2((c.hour + 1) % 24)}:00 UTC`, [
          { value: full(c.value), label: 'connections' },
          { value: share(c.value, total), label: 'of this period' },
        ]], (on) => { d3.select(this).classed('hot', on); if (on) d3.select(this).raise(); });
      });
    body.replaceChildren(svg.node(), scaleLegend(scale, 'connections per hour'));
  }

  function funnelStages(w) {
    const tried = (w.techniques.find((t) => t.id === 'T1110.001') || {}).sessions || 0;
    return [
      { label: 'Connected', value: w.totals.sessions },
      { label: 'Tried a password', value: tried },
      { label: 'Got into the fake shell', value: w.totals.login_success },
      { label: 'Ran commands', value: w.totals.interactive_sessions },
    ];
  }

  function renderFunnel(body, w) {
    barList(body, funnelStages(w), { unit: 'sessions', total: w.totals.sessions, shareOf: 'all connections', showShare: true });
  }

  function renderProtocols(body, w) {
    const entries = Object.entries(w.protocols);
    const total = d3.sum(entries, (e) => e[1]);
    if (!total) return body.replaceChildren(emptyNote());
    const stack = h('div', { class: 'stack', role: 'img',
      'aria-label': entries.map(([p, n]) => `${p.toUpperCase()} ${share(n, total)}`).join(', ') });
    const legend = h('div', { class: 'proto-legend' });
    for (const [proto, n] of entries) {
      const key = PROTOCOL_KEY[proto] || 's1';
      const seg = h('span', { class: 'seg key-' + key, tabindex: 0 });
      seg.style.setProperty('--p', String(n / total));
      bindTip(seg, () => [proto.toUpperCase(), [
        { value: full(n), label: 'connections', key },
        { value: share(n, total), label: 'of all connections' },
      ]]);
      stack.append(seg);
      legend.append(h('div', { class: 'row' }, h('span', { class: 'swatch key-' + key }),
        h('strong', { text: proto.toUpperCase() }), full(n), h('span', { class: 'share', text: share(n, total) })));
    }
    body.replaceChildren(stack, legend);
  }

  function techniqueLabel(t) {
    const id = TECHNIQUE.test(t.id) ? t.id : '';
    return h('span', {}, id ? externalLink('https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/', id) : null, t.name);
  }

  function renderTechniques(body, w) {
    if (!w.techniques.length) return body.replaceChildren(emptyNote());
    const max = d3.max(w.techniques, (t) => t.sessions);
    const groups = d3.groups(w.techniques, (t) => t.tactic);
    const sections = groups.map(([tactic, rows]) => {
      const list = h('div');
      barList(list, rows.map((t) => ({ label: techniqueLabel(t), text: `${t.id} ${t.name}`, value: t.sessions })),
        { unit: 'sessions', total: w.totals.sessions, shareOf: 'all sessions', max, wide: true });
      return h('section', {}, h('h3', { class: 'group', text: tactic }), list);
    });
    body.replaceChildren(h('div', { class: 'columns' }, sections));
  }

  const pairs = (list) => list.map(([label, value]) => ({ label, value }));

  function credentialLabel(user, password) {
    return h('span', {}, attackerText(user), h('span', { class: 'sep', text: ' / ' }), attackerText(password));
  }

  // ---------------------------------------------------------------- v2 cards

  /** Does any window of these stats carry a schema-2 field? Old stats.json files simply hide the new cards. */
  const hasField = (stats, key) => Object.values(stats.windows || {}).some((w) => Array.isArray(w[key]) || (w[key] && typeof w[key] === 'object'));

  function navButton(content, params, cls) {
    const label = content instanceof Node ? content : attackerText(String(content));
    return h('button', { type: 'button', class: 'linkish' + (cls ? ' ' + cls : ''), onclick: () => openDrawer(params) }, label);
  }

  const ipButton = (ip) => (IP_ANY.test(ip) ? navButton(ip, { ip }, 'mono') : document.createTextNode(String(ip)));
  const sampleButton = (sha) => (SHA256.test(sha) ? navButton(sha.slice(0, 16) + '…', { sample: sha }, 'mono') : document.createTextNode('–'));

  function campaignName(id) {
    for (const w of Object.values(state.stats.windows)) {
      const c = (w.campaigns || []).find((x) => x.id === id);
      if (c) return c.name;
    }
    return id;
  }

  const campaignButton = (id, name) => (CAMPAIGN_ID.test(id) ? navButton(name || campaignName(id), { campaign: id }) : document.createTextNode(String(name || id)));

  function badge(text, cls) { return h('span', { class: 'badge' + (cls ? ' ' + cls : ''), text }); }

  function techniqueName(id) {
    for (const w of Object.values(state.stats.windows)) {
      const t = (w.techniques || []).find((x) => x.id === id);
      if (t) return t.name;
    }
    return '';
  }

  function techniqueChip(id, withName) {
    if (!TECHNIQUE.test(id)) return null;
    const name = techniqueName(id);
    const a = externalLink('https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/', withName && name ? `${id} ${name}` : id, 'chip mono');
    if (name) a.setAttribute('title', name);
    return a;
  }

  function campaignCell(c) {
    return h('div', { class: 'campaign-cell' },
      campaignButton(c.id, c.name),
      h('span', { class: 'badges' }, badge(c.known ? 'Known family' : 'Cluster', c.known ? 'known' : ''), c.new ? badge('New', 'new') : null));
  }

  function countriesText(list) {
    const names = (list || []).map(([cc]) => countryName(cc));
    return names.slice(0, 2).join(', ') + (names.length > 2 ? ` +${names.length - 2}` : '') || '–';
  }

  const campaignsTable = (w) => ({
    rowOpen: (c) => openDrawer({ campaign: c.id }),
    columns: [
      col('Campaign', (c) => campaignCell(c), { cls: 'wide-cell' }),
      col('Sessions', (c) => c.sessions, { num: true }),
      col('IPs', (c) => c.ips, { num: true }),
      col('Top countries', (c) => countriesText(c.countries), { nowrap: true }),
      col('Last seen', (c) => fmtTs(c.last), { nowrap: true }),
      col('Techniques', (c) => h('span', { class: 'chips' }, (c.techniques || []).slice(0, 3).map((t) => techniqueChip(t)),
        (c.techniques || []).length > 3 ? h('span', { class: 'more', text: `+${c.techniques.length - 3}` }) : null)),
      col('Replay', (c) => (REPLAY_ID.test(c.replay || '') ? h('button', {
        type: 'button', class: 'btn small', 'aria-label': 'Watch a session of ' + c.name, onclick: () => openDrawer({ replay: c.replay }),
      }, '▶ Watch') : '–'), { nowrap: true }),
    ],
    rows: w.campaigns || [],
  });

  function recordItems(w) {
    const r = w.records || {};
    const sessionTarget = (x) => (REPLAY_ID.test(x.replay || '') ? { replay: x.replay } : { ip: x.ip });
    return [
      r.longest_session && r.longest_session.duration_ms ? {
        label: 'Longest session', value: formatDuration(r.longest_session.duration_ms), sub: r.longest_session.ip,
        open: sessionTarget(r.longest_session), hint: REPLAY_ID.test(r.longest_session.replay || '') ? 'Watch it' : 'Open the IP',
      } : null,
      r.most_commands && r.most_commands.commands ? {
        label: 'Most commands in one session', value: full(r.most_commands.commands) + ' commands', sub: r.most_commands.ip,
        open: sessionTarget(r.most_commands), hint: REPLAY_ID.test(r.most_commands.replay || '') ? 'Watch it' : 'Open the IP',
      } : null,
      r.longest_password && r.longest_password.length ? {
        label: 'Longest password tried', value: full(r.longest_password.length) + ' characters',
        sub: r.longest_password.password, mono: true, open: { password: r.longest_password.password }, hint: 'Who tried it',
      } : null,
      r.most_attempts_ip && r.most_attempts_ip.attempts ? {
        label: 'Most login attempts from one IP', value: full(r.most_attempts_ip.attempts), sub: r.most_attempts_ip.ip,
        open: { ip: r.most_attempts_ip.ip }, hint: 'Open the IP',
      } : null,
      r.most_persistent_ip && r.most_persistent_ip.days ? {
        label: 'Most persistent attacker', value: full(r.most_persistent_ip.days) + (r.most_persistent_ip.days === 1 ? ' day' : ' days'),
        sub: r.most_persistent_ip.ip, open: { ip: r.most_persistent_ip.ip }, hint: 'Open the IP',
      } : null,
    ].filter(Boolean);
  }

  function renderRecords(body, w) {
    const items = recordItems(w);
    if (!items.length) return body.replaceChildren(emptyNote());
    body.replaceChildren(h('div', { class: 'records' }, items.map((it) => h('button', {
      type: 'button', class: 'record',
      'aria-label': `${it.label}: ${it.value}, ${it.sub === '' ? '(empty)' : it.sub}. ${it.hint}`,
      onclick: () => openDrawer(it.open),
    },
    h('span', { class: 'record-label', text: it.label }),
    h('span', { class: 'record-value', text: it.value }),
    h('span', { class: 'record-sub' + (it.mono || IP_ANY.test(it.sub || '') ? ' mono' : '') }, attackerText(String(it.sub == null ? '' : it.sub))),
    h('span', { class: 'record-hint', text: it.hint + ' →' })))));
  }

  // ------------------------------------------------ replays

  const replayCache = new Map();

  function loadReplay(id) {
    if (!REPLAY_ID.test(id)) return Promise.resolve(null);
    if (!replayCache.has(id)) {
      replayCache.set(id, fetch(BASE + 'replays/' + id + '.json', { cache: 'no-cache' })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => (d && Array.isArray(d.frames) ? d : null))
        .catch(() => null));
    }
    return replayCache.get(id);
  }

  function findReplay(id) {
    const order = [state.window].concat(WINDOWS.filter((k) => k !== state.window));
    for (const key of order) {
      const r = ((state.stats.windows[key] || {}).replays || []).find((x) => x.id === id);
      if (r) return r;
    }
    return null;
  }

  /** Mount a player for replay `id` into `slot`; resolves to the player (or null). */
  function mountReplay(slot, id, autoplay, label) {
    slot.replaceChildren(h('p', { class: 'loading', text: 'Loading the recording…' }));
    return loadReplay(id).then((doc) => {
      if (!slot.isConnected) return null;
      if (!doc || !window.HoneypotReplay) {
        slot.replaceChildren(emptyNote('This recording is not available yet. It is published with the next data refresh.'));
        return null;
      }
      return window.HoneypotReplay.createPlayer(slot, doc, { autoplay, label });
    });
  }

  function replayMeta(r) {
    const bits = [countryName(r.cc), (r.protocol || '').toUpperCase(), Number.isFinite(r.commands) ? `${full(r.commands)} command${r.commands === 1 ? '' : 's'}` : null,
      Number.isFinite(r.duration_ms) ? formatDuration(r.duration_ms) : null];
    return bits.filter(Boolean).join(' · ');
  }

  function renderReplayCard(body, w, card) {
    if (card.player) { card.player.destroy(); card.player = null; }
    const list = (w.replays || []).filter((r) => REPLAY_ID.test(r.id));
    if (!list.length) return body.replaceChildren(emptyNote('No recorded sessions in this period.'));
    if (!list.some((r) => r.id === card.selected)) card.selected = list[0].id;
    const stage = h('div', { class: 'replay-stage' });
    const head = h('div', { class: 'replay-head' });
    const slot = h('div', { class: 'replay-slot' });
    stage.append(head, slot);
    const buttons = [];

    function select(r, autoplay) {
      card.selected = r.id;
      buttons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.id === r.id)));
      head.replaceChildren(
        h('div', {}, h('strong', {}, r.campaign && CAMPAIGN_ID.test(r.campaign) ? campaignButton(r.campaign, r.campaign_name) : 'Recorded session'),
          h('div', { class: 'replay-sub' }, ipButton(r.ip), ' · ', fmtTs(r.ts))),
        h('button', { type: 'button', class: 'btn small', onclick: () => openDrawer({ replay: r.id }) }, 'Details'));
      if (card.player) card.player.destroy();
      card.player = null;
      mountReplay(slot, r.id, autoplay, 'Session from ' + r.ip).then((p) => {
        if (card.selected === r.id) card.player = p; else if (p) p.destroy();
      });
    }

    const items = list.slice(0, 12).map((r) => {
      const b = h('button', { type: 'button', class: 'replay-item', 'data-id': r.id, 'aria-pressed': 'false', onclick: () => select(r, true) },
        h('span', { class: 'replay-title' }, attackerText(r.campaign_name || 'Recorded session')),
        h('span', { class: 'replay-sub' }, h('span', { class: 'mono', text: r.ip }), ' · ', replayMeta(r)));
      buttons.push(b);
      return h('li', {}, b);
    });
    body.replaceChildren(h('div', { class: 'replay-card' }, h('ol', { class: 'replay-list', 'aria-label': 'Recorded sessions' }, items), stage));
    select(list.find((r) => r.id === card.selected), false);
  }

  // ---------------------------------------------------------------- card registry

  const col = (label, value, extra) => Object.assign({ label, value }, extra);
  const cardById = (id) => CARDS.find((c) => c.id === id);

  const CARDS = [
    {
      id: 'activity', span: 12, title: 'Connections per day',
      sub: 'Every session that reached the fake SSH or Telnet service',
      chart: renderActivity,
      table: (w) => ({
        columns: [col('Date', (d) => d.date, { nowrap: true }), col('Connections', (d) => d.sessions, { num: true }),
          col('Unique IPs', (d) => d.unique_ips, { num: true }), col('Login attempts', (d) => d.login_attempts, { num: true }),
          col('Successful logins', (d) => d.login_success, { num: true }), col('Commands', (d) => d.commands, { num: true })],
        rows: w.daily.slice().reverse(),
      }),
    },
    {
      id: 'campaigns', span: 12, title: 'Attack campaigns',
      sub: 'Sessions grouped by the commands they ran. Names of known families are heuristic matches. Open one for details.',
      available: (s) => hasField(s, 'campaigns'), resize: false,
      table: campaignsTable,
    },
    {
      id: 'map', span: 8, title: 'Where connections come from',
      sub: 'Source country of each connection, by registered network',
      chart: renderMap,
      table: (w) => ({
        columns: [col('Country', (c) => countryName(c.cc)), col('Connections', (c) => c.sessions, { num: true }),
          col('Unique IPs', (c) => c.ips, { num: true }), col('Share', (c) => share(c.sessions, w.totals.sessions), { num: true })],
        rows: w.countries,
      }),
    },
    {
      id: 'countries', span: 4, title: 'Top countries', sub: 'Connections by source country',
      chart: (body, w) => barList(body, w.countries.slice(0, 10).map((c) => ({
        label: countryName(c.cc), value: c.sessions, tip: [{ value: full(c.ips), label: 'unique IPs' }],
        open: () => openDrawer({ country: c.cc }),
      })), { total: w.totals.sessions, shareOf: 'all connections' }),
      table: (w) => cardById('map').table(w),
    },
    {
      id: 'replays', span: 12, title: 'Watch an attack',
      sub: 'Sessions recorded by the honeypot, replayed exactly as the attacker saw the fake shell',
      available: (s) => hasField(s, 'replays'), resize: false,
      chart: renderReplayCard,
    },
    {
      id: 'heatmap', span: 8, title: 'When attacks happen', sub: 'Connections by weekday and hour, UTC',
      chart: renderHeatmap,
      table: (w) => ({
        columns: [col('Day', (r) => r.day)].concat(d3.range(24).map((hr) => col(pad2(hr), (r) => r.values[hr], { num: true }))),
        rows: w.heatmap.map((values, i) => ({ day: DAY_NAMES[i], values })),
      }),
    },
    {
      id: 'funnel', span: 4, title: 'How far attackers get', sub: 'Sessions reaching each stage',
      chart: renderFunnel,
      table: (w) => ({
        columns: [col('Stage', (s) => s.label), col('Sessions', (s) => s.value, { num: true }),
          col('Share', (s) => share(s.value, w.totals.sessions), { num: true })],
        rows: funnelStages(w),
      }),
    },
    {
      id: 'records', span: 12, title: 'Records', sub: 'The extremes of this period. Open any of them.',
      available: (s) => hasField(s, 'records'), resize: false,
      chart: renderRecords,
    },
    {
      id: 'usernames', span: 4, title: 'Top usernames', sub: 'Login attempts per username',
      chart: (body, w) => barList(body, w.usernames.slice(0, 10).map(([label, value]) => ({ label, value, open: () => openDrawer({ username: label }) })),
        { mono: true, unit: 'attempts', total: w.totals.login_attempts, shareOf: 'all attempts' }),
      table: (w) => ({ columns: [col('Username', (r) => attackerText(r[0]), { mono: true }), col('Attempts', (r) => r[1], { num: true })], rows: w.usernames }),
    },
    {
      id: 'passwords', span: 4, title: 'Top passwords', sub: 'Login attempts per password',
      chart: (body, w) => barList(body, w.passwords.slice(0, 10).map(([label, value]) => ({ label, value, open: () => openDrawer({ password: label }) })),
        { mono: true, unit: 'attempts', total: w.totals.login_attempts, shareOf: 'all attempts' }),
      table: (w) => ({ columns: [col('Password', (r) => attackerText(r[0]), { mono: true }), col('Attempts', (r) => r[1], { num: true })], rows: w.passwords }),
    },
    {
      id: 'credentials', span: 4, title: 'Top credential pairs', sub: 'Username / password combinations',
      chart: (body, w) => barList(body, w.credentials.slice(0, 10).map(([u, p, n]) => ({
        label: credentialLabel(u, p), text: `${u || '(empty)'} / ${p || '(empty)'}`, value: n,
        open: () => openDrawer({ username: u, password: p }),
      })), { mono: true, unit: 'attempts', total: w.totals.login_attempts, shareOf: 'all attempts' }),
      table: (w) => ({
        columns: [col('Username', (r) => attackerText(r[0]), { mono: true }), col('Password', (r) => attackerText(r[1]), { mono: true }),
          col('Attempts', (r) => r[2], { num: true })],
        rows: w.credentials,
      }),
    },
    {
      id: 'techniques', span: 7, title: 'MITRE ATT&CK techniques',
      sub: 'Sessions showing each technique, matched from commands typed into the fake shell',
      chart: renderTechniques,
      table: (w) => ({
        columns: [col('Technique', (t) => techniqueLabel(t)), col('Tactic', (t) => t.tactic),
          col('Sessions', (t) => t.sessions, { num: true })],
        rows: w.techniques,
      }),
    },
    {
      id: 'commands', span: 5, title: 'Most common commands', sub: 'Command lines typed after logging in',
      chart: (body, w) => barList(body, pairs(w.commands.slice(0, 12)), { mono: true, stacked: true, unit: 'runs' }),
      table: (w) => ({ columns: [col('Command', (r) => attackerText(r[0]), { mono: true }), col('Runs', (r) => r[1], { num: true })], rows: w.commands }),
    },
    {
      id: 'protocols', span: 4, title: 'Protocols', sub: 'Share of connections per service',
      chart: renderProtocols,
      table: (w) => ({
        columns: [col('Protocol', (r) => r[0].toUpperCase()), col('Connections', (r) => r[1], { num: true })],
        rows: Object.entries(w.protocols),
      }),
    },
    {
      id: 'clients', span: 4, title: 'SSH client software', sub: 'Version banner sent by the client',
      chart: (body, w) => barList(body, pairs(w.clients.slice(0, 8)), { mono: true, wide: true, unit: 'sessions' }),
      table: (w) => ({ columns: [col('Client banner', (r) => attackerText(r[0]), { mono: true }), col('Sessions', (r) => r[1], { num: true })], rows: w.clients }),
    },
    {
      id: 'asns', span: 4, title: 'Top networks', sub: 'Autonomous systems the connections come from',
      chart: (body, w) => barList(body, w.asns.slice(0, 8).map((a) => ({
        label: `AS${a.asn} ${a.name}`, value: a.sessions,
        tip: [{ value: full(a.ips), label: 'unique IPs' }, { value: countryName(a.cc), label: '' }],
      })), { total: w.totals.sessions, shareOf: 'all connections', wide: true }),
      table: (w) => ({
        columns: [col('Network', (a) => `AS${a.asn} ${a.name}`), col('Country', (a) => countryName(a.cc)),
          col('Connections', (a) => a.sessions, { num: true }), col('Unique IPs', (a) => a.ips, { num: true })],
        rows: w.asns,
      }),
    },
    {
      id: 'ips', span: 12, title: 'Most active source IPs',
      sub: 'Usually compromised hosts or rented servers. Open one for its full profile.',
      table: (w) => ({
        rowOpen: (r) => openDrawer({ ip: r.ip }),
        columns: [
          col('IP address', (r) => ipButton(r.ip), { nowrap: true }),
          col('Country', (r) => countryName(r.cc), { nowrap: true }),
          col('Network', (r) => (r.asn ? `AS${r.asn} ${r.as_name}` : 'Unknown')),
          col('Connections', (r) => r.sessions, { num: true }),
          col('Login attempts', (r) => r.login_attempts, { num: true }),
          col('Commands', (r) => r.commands, { num: true }),
          col('Reputation', (r) => (IPV4.test(r.ip) ? externalLink('https://www.abuseipdb.com/check/' + r.ip, 'AbuseIPDB') : '–'), { nowrap: true }),
        ],
        rows: w.ips,
      }),
    },
    {
      id: 'filetypes', span: 5, title: 'Malware by file type', sub: 'Captured samples per format and CPU architecture',
      available: (s) => hasField(s, 'malware_arch'),
      chart: (body, w) => barList(body, pairs((w.malware_arch || []).slice(0, 10)),
        { unit: 'samples', total: d3.sum(w.malware_arch || [], (r) => r[1]), shareOf: 'all samples', wide: true }),
      table: (w) => ({ columns: [col('File type', (r) => r[0]), col('Samples', (r) => r[1], { num: true })], rows: w.malware_arch || [] }),
    },
    {
      id: 'failed', span: 7, title: 'Downloads that failed', sub: 'URLs the attackers fetched that were dead or empty. Defanged.',
      available: (s) => hasField(s, 'failed_downloads'),
      chart: (body, w) => barList(body, pairs((w.failed_downloads || []).slice(0, 8)), { mono: true, stacked: true, unit: 'attempts' }),
      table: (w) => ({ columns: [col('URL (defanged)', (r) => attackerText(r[0]), { mono: true }), col('Attempts', (r) => r[1], { num: true })], rows: w.failed_downloads || [] }),
    },
    {
      id: 'downloads', span: 12, title: 'Captured malware downloads',
      sub: 'Files attackers fetched into the fake shell. Open a sample for its type, threat intel and who fetched it. URLs are defanged.',
      table: (w) => ({
        rowOpen: (d) => SHA256.test(d.sha256) && openDrawer({ sample: d.sha256 }),
        columns: [
          col('SHA-256', (d) => sampleButton(d.sha256), { nowrap: true }),
          col('Type', (d) => typeLabel(d.meta), { nowrap: true }),
          col('Size', (d) => (d.meta ? formatBytes(d.meta.size) : '–'), { num: true }),
          col('Detections', (d) => detections(d.intel), { nowrap: true }),
          col('Source (defanged)', (d) => (d.url ? attackerText(d.url) : '–'), { mono: true }),
          col('Times seen', (d) => d.count, { num: true }),
          col('Last seen', (d) => fmtTs(d.last), { nowrap: true }),
        ],
        rows: w.downloads,
      }),
    },
  ];

  // ---------------------------------------------------------------- page

  const DRAWER_KEYS = ['ip', 'country', 'campaign', 'sample', 'replay', 'username', 'password'];

  /** "#30d&ip=1.2.3.4" -> {window: '30d', params: {ip: '1.2.3.4'}}. Old "#7d" hashes still work. */
  function parseHash() {
    const out = { window: null, params: {} };
    for (const part of location.hash.slice(1).split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      if (eq < 0) { if (WINDOWS.includes(part)) out.window = part; continue; }
      const key = part.slice(0, eq);
      let value;
      try { value = decodeURIComponent(part.slice(eq + 1)); } catch (e) { continue; }
      if (key === 'w' && WINDOWS.includes(value)) out.window = value;
      else if (DRAWER_KEYS.includes(key) && value.length <= 600) out.params[key] = value;
    }
    return out;
  }

  const hashFor = (win, params) => '#' + [win].concat(DRAWER_KEYS.filter((k) => params && k in params)
    .map((k) => k + '=' + encodeURIComponent(params[k]))).join('&');

  const state = { stats: null, world: null, window: initialWindow(), width: 0, cards: [] };

  function initialWindow() {
    const fromHash = parseHash().window;
    if (fromHash) return fromHash;
    try {
      const saved = localStorage.getItem('window');
      if (WINDOWS.includes(saved)) return saved;
    } catch (e) { /* storage blocked */ }
    return '30d';
  }

  const currentWindow = () => state.stats.windows[state.window];

  function buildCards() {
    state.cards = CARDS.filter((card) => !card.available || card.available(state.stats));
    $('#grid').replaceChildren(...state.cards.map((card) => {
      card.body = h('div', { class: 'card-body' });
      card.asTable = !card.chart;
      const toggle = card.chart && card.table ? h('button', {
        class: 'btn small', type: 'button', 'aria-pressed': 'false', text: 'Table',
        'aria-label': 'Show ' + card.title.toLowerCase() + ' as a table',
        onclick: () => {
          card.asTable = !card.asTable;
          toggle.setAttribute('aria-pressed', String(card.asTable));
          renderCard(card);
        },
      }) : null;
      return h('article', { class: 'card span-' + card.span, id: 'card-' + card.id, 'aria-labelledby': 'title-' + card.id },
        h('header', { class: 'card-head' },
          h('div', {}, h('h2', { id: 'title-' + card.id, text: card.title }), h('p', { class: 'card-sub', text: card.sub })),
          toggle),
        card.body);
    }));
  }

  function renderCard(card) {
    const w = currentWindow();
    if (card.asTable) renderTable(card.body, card.table(w));
    else card.chart(card.body, w, card);
  }

  // ---------------------------------------------------------------- drawer

  let profilesPromise = null;

  /** profiles.json is the largest file and only needed once someone opens a drawer. */
  function loadProfiles() {
    if (!profilesPromise) {
      profilesPromise = fetch(BASE + 'profiles.json', { cache: 'no-cache' })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => (d && d.ips && typeof d.ips === 'object' ? d.ips : null))
        .catch(() => null);
    }
    return profilesPromise;
  }

  const dsec = (title, ...content) => h('section', { class: 'd-sec' }, h('h3', { class: 'd-h', text: title }), ...content);

  function facts(rows) {
    return h('dl', { class: 'facts' }, rows.filter(Boolean).map(([k, v]) => h('div', {},
      h('dt', { text: k }), h('dd', {}, v instanceof Node ? v : String(v == null ? '–' : v)))));
  }

  function mini(items) {
    return h('div', { class: 'mini' }, items.filter(Boolean).map(([label, value]) =>
      h('div', { class: 'mini-item' }, h('span', { class: 'mini-value', text: value }), h('span', { class: 'mini-label', text: label }))));
  }

  const loadingNote = () => h('p', { class: 'loading', text: 'Loading…' });
  const listOf = (items) => h('ul', { class: 'd-list' }, items.map((x) => h('li', {}, x)));

  /** Sessions per day for the 30 days up to the sensor's last day, as small bars. */
  function dailyBars(daily) {
    const end = parseDay(state.stats.sensor.last_day);
    const byDay = new Map((daily || []).map(([d, n]) => [d, n]));
    const days = d3.range(29, -1, -1).map((i) => {
      const t = d3.utcDay.offset(end, -i);
      const key = t.toISOString().slice(0, 10);
      return { t, key, n: byDay.get(key) || 0 };
    });
    const width = 300;
    const height = 56;
    const step = width / days.length;
    const y = d3.scaleLinear().domain([0, d3.max(days, (d) => d.n) || 1]).range([0, height - 4]);
    const svg = d3.create('svg').attr('class', 'chart daily-bars').attr('viewBox', `0 0 ${width} ${height + 16}`)
      .attr('role', 'img').attr('aria-label', `Sessions per day over the last 30 days, ${days.filter((d) => d.n).length} active days`);
    svg.append('line').attr('class', 'baseline').attr('x1', 0).attr('x2', width).attr('y1', height).attr('y2', height);
    svg.append('g').selectAll('rect').data(days).join('rect')
      .attr('class', 'mark').attr('x', (d, i) => i * step + 1).attr('width', Math.max(1, step - 2))
      .attr('y', (d) => height - Math.max(d.n ? 2 : 0, y(d.n))).attr('height', (d) => Math.max(d.n ? 2 : 0, y(d.n))).attr('rx', 1.5)
      .each(function (d) { bindTip(this, () => [weekdayFmt.format(d.t), [{ value: full(d.n), label: 'sessions' }]]); });
    svg.append('g').attr('class', 'ticks').selectAll('text').data([days[0], days[days.length - 1]]).join('text')
      .attr('x', (d, i) => (i ? width : 0)).attr('y', height + 13).attr('text-anchor', (d, i) => (i ? 'end' : 'start'))
      .text((d) => dayFmt.format(d.t));
    return svg.node();
  }

  function windowsInOrder() {
    return [state.window].concat(WINDOWS.filter((k) => k !== state.window)).map((k) => state.stats.windows[k]).filter(Boolean);
  }

  function findIn(key, pred) {
    for (const w of windowsInOrder()) {
      const hit = (w[key] || []).find(pred);
      if (hit) return { item: hit, window: w };
    }
    return null;
  }

  const periodNote = (w) => h('p', { class: 'd-note', text: 'Numbers cover ' + (w.label || 'this period').toLowerCase() + '.' });

  // ------------------------------------------------ drawer builders: each returns {kicker, title, mono, body}

  function ipDrawer(ip) {
    if (!IP_ANY.test(ip)) return { kicker: 'Source IP', title: 'Unknown address', body: emptyNote('That is not an IP address.') };
    const row = findIn('ips', (r) => r.ip === ip);
    const body = h('div', {}, loadingNote());
    loadProfiles().then((profiles) => {
      const p = profiles && profiles[ip];
      const base = p || (row && row.item);
      if (!base) {
        body.replaceChildren(emptyNote('No profile for this IP in the published data. Profiles cover IPs active in the last 30 days.'),
          IPV4.test(ip) ? h('p', {}, externalLink('https://www.abuseipdb.com/check/' + ip, 'Check it on AbuseIPDB')) : null);
        return;
      }
      const protocols = Object.entries((p && p.protocols) || {}).map(([k, n]) => `${k.toUpperCase()} ${full(n)}`).join(' · ');
      const parts = [
        facts([
          ['Country', COUNTRY.test(base.cc || '') ? navButton(countryName(base.cc), { country: base.cc }) : countryName(base.cc)],
          ['Network', base.asn ? `AS${base.asn} ${base.as_name || ''}` : 'Unknown'],
          p ? ['First seen', fmtTs(p.first)] : null,
          p ? ['Last seen', fmtTs(p.last)] : null,
          p && Number.isFinite(p.days_active) ? ['Active on', full(p.days_active) + (p.days_active === 1 ? ' day' : ' days')] : null,
          protocols ? ['Protocols', protocols] : null,
        ]),
        mini([['Connections', full(base.sessions || 0)], ['Login attempts', full(base.login_attempts || 0)],
          ['Logins to the shell', full(base.login_success || 0)], ['Commands', full(base.commands || 0)]]),
      ];
      if (!p) parts.push(h('p', { class: 'd-note', text: 'Only the totals are published for this IP.' }));
      if (p && p.daily && p.daily.length) parts.push(dsec('Activity, last 30 days', dailyBars(p.daily)));
      if (p && p.campaigns && p.campaigns.length) {
        const list = h('div');
        barList(list, p.campaigns.slice(0, 8).map(([id, n]) => ({ label: campaignName(id), value: n,
          open: CAMPAIGN_ID.test(id) ? () => openDrawer({ campaign: id }) : null })), { unit: 'sessions', wide: true });
        parts.push(dsec('Campaigns', list));
      }
      if (p && p.replays && p.replays.length) {
        const ids = p.replays.filter((id) => REPLAY_ID.test(id)).slice(0, 5);
        if (ids.length) parts.push(dsec('Recorded sessions', listOf(ids.map((id) => {
          const meta = findReplay(id);
          return h('button', { type: 'button', class: 'btn small', onclick: () => openDrawer({ replay: id }) },
            '▶ ' + (meta ? `${meta.campaign_name || 'Session'} · ${fmtTs(meta.ts)}` : 'Watch session ' + id.slice(0, 8)));
        }))));
      }
      if (p && p.credentials && p.credentials.length) {
        const list = h('div');
        barList(list, p.credentials.slice(0, 10).map(([u, pw, n]) => ({ label: credentialLabel(u, pw), text: `${u || '(empty)'} / ${pw || '(empty)'}`,
          value: n, open: () => openDrawer({ username: u, password: pw }) })), { mono: true, unit: 'attempts' });
        parts.push(dsec('Credentials tried', list));
      }
      if (p && p.top_commands && p.top_commands.length) {
        const list = h('div');
        barList(list, pairs(p.top_commands.slice(0, 10)), { mono: true, stacked: true, unit: 'runs' });
        parts.push(dsec('Commands', list));
      }
      if (p && p.downloads && p.downloads.length) parts.push(dsec('Malware it fetched', listOf(p.downloads.slice(0, 10).map(sampleButton))));
      if (p && p.clients && p.clients.length) {
        const list = h('div');
        barList(list, pairs(p.clients.slice(0, 3)), { mono: true, wide: true, unit: 'sessions' });
        parts.push(dsec('Client software', list));
      }
      parts.push(dsec('Look it up', h('p', { class: 'd-links' },
        IPV4.test(ip) ? externalLink('https://www.abuseipdb.com/check/' + ip, 'AbuseIPDB') : null),
      h('p', { class: 'd-note', text: 'Most sources are compromised machines or rented servers, not the people behind them. Report abuse, don\'t retaliate.' })));
      body.replaceChildren(...parts);
    });
    return { kicker: 'Source IP', title: ip, mono: true, body };
  }

  function countryDrawer(cc) {
    if (!COUNTRY.test(cc)) return { kicker: 'Country', title: 'Unknown country', body: emptyNote() };
    const w = currentWindow();
    const c = (w.countries || []).find((x) => x.cc === cc);
    if (!c) return { kicker: 'Country · ' + w.label, title: countryName(cc), body: emptyNote('No connections from here in this period.') };
    const parts = [mini([['Connections', full(c.sessions)], ['Unique IPs', full(c.ips)], ['Share of all', share(c.sessions, w.totals.sessions)]])];
    const topIps = (c.top_ips && c.top_ips.length ? c.top_ips : w.ips.filter((r) => r.cc === cc).map((r) => r.ip)).slice(0, 10);
    if (topIps.length) parts.push(dsec('Most active IPs', listOf(topIps.map(ipButton))));
    if (c.campaigns && c.campaigns.length) {
      const list = h('div');
      barList(list, c.campaigns.map(([id, n]) => ({ label: campaignName(id), value: n,
        open: CAMPAIGN_ID.test(id) ? () => openDrawer({ campaign: id }) : null })), { unit: 'sessions', wide: true });
      parts.push(dsec('Campaigns', list));
    }
    const asns = c.asns && c.asns.length ? c.asns : w.asns.filter((a) => a.cc === cc).map((a) => [a.asn, a.name, a.sessions]);
    if (asns.length) {
      const list = h('div');
      barList(list, asns.slice(0, 5).map(([asn, name, n]) => ({ label: `AS${asn} ${name}`, value: n })), { unit: 'connections', wide: true });
      parts.push(dsec('Networks', list));
    }
    parts.push(periodNote(w));
    return { kicker: 'Country', title: countryName(cc), body: h('div', {}, ...parts) };
  }

  function campaignDrawer(id) {
    const hit = CAMPAIGN_ID.test(id) ? findIn('campaigns', (c) => c.id === id) : null;
    if (!hit) return { kicker: 'Campaign', title: 'Unknown campaign', body: emptyNote('This campaign is not in the published data.') };
    const c = hit.item;
    const parts = [
      h('p', { class: 'badges' }, badge(c.known ? 'Known family' : 'Cluster of identical sessions', c.known ? 'known' : ''), c.new ? badge('New this period', 'new') : null),
      mini([['Sessions', full(c.sessions)], ['IPs', full(c.ips)]]),
      facts([['First seen', fmtTs(c.first)], ['Last seen', fmtTs(c.last)]]),
    ];
    if (c.commands && c.commands.length) {
      parts.push(dsec('What it runs', h('ol', { class: 'cmd-seq' }, c.commands.map((cmd) => h('li', {}, attackerText(cmd)))),
        h('p', { class: 'd-note', text: 'Command sequence from the most complete session. Download URLs are defanged.' })));
    }
    if (REPLAY_ID.test(c.replay || '')) {
      const slot = h('div', { class: 'replay-slot' });
      parts.push(dsec('Watch a session', slot));
      setTimeout(() => mountReplay(slot, c.replay, false, c.name).then((p) => { if (p) drawer.players.push(p); }));
    }
    const techs = (c.techniques || []).map((t) => techniqueChip(t, true)).filter(Boolean);
    if (techs.length) parts.push(dsec('MITRE ATT&CK techniques', h('div', { class: 'chips' }, techs)));
    if (c.countries && c.countries.length) {
      const list = h('div');
      barList(list, c.countries.map(([cc, n]) => ({ label: countryName(cc), value: n, open: () => openDrawer({ country: cc }) })),
        { unit: 'sessions', total: c.sessions, shareOf: 'this campaign' });
      parts.push(dsec('Where it comes from', list));
    }
    if (c.downloads && c.downloads.length) parts.push(dsec('Malware it fetches', listOf(c.downloads.map(sampleButton))));
    const ipSlot = h('div', {}, loadingNote());
    parts.push(dsec('IPs running it', ipSlot));
    loadProfiles().then((profiles) => {
      const rows = Object.entries(profiles || {}).map(([ip, p]) => [ip, ((p.campaigns || []).find(([cid]) => cid === id) || [])[1] || 0])
        .filter((r) => r[1] > 0).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 20);
      if (!rows.length) return ipSlot.replaceChildren(emptyNote('No IP profiles mention this campaign.'));
      const list = h('div');
      barList(list, rows.map(([ip, n]) => ({ label: ip, value: n, open: () => openDrawer({ ip }) })), { mono: true, unit: 'sessions' });
      ipSlot.replaceChildren(list);
    });
    parts.push(h('p', { class: 'd-note', text: (c.known
      ? 'The family name is a heuristic match on known command patterns, not a malware verdict. '
      : 'Sessions that typed the same command sequence. ') + 'Numbers cover ' + hit.window.label.toLowerCase() + '.' }));
    return { kicker: 'Campaign', title: c.name, body: h('div', {}, ...parts) };
  }

  function sampleDrawer(sha) {
    const hit = SHA256.test(sha) ? findIn('downloads', (d) => d.sha256 === sha) : null;
    if (!hit) return { kicker: 'Malware sample', title: 'Unknown sample', body: emptyNote('This sample is not in the published data.') };
    const d = hit.item;
    const m = d.meta;
    const parts = [
      h('p', { class: 'hash mono', text: sha }),
      facts([
        ['Type', typeLabel(m)],
        m ? ['Size', formatBytes(m.size)] : null,
        m && m.kind === 'elf' && m.static != null ? ['Linking', m.static ? 'Static' : 'Dynamic'] : null,
        m && m.kind === 'elf' && m.stripped != null ? ['Symbols', m.stripped ? 'Stripped' : 'Not stripped'] : null,
        m && m.packer ? ['Packer', m.packer] : null,
        ['First seen', fmtTs(d.first)],
        ['Last seen', fmtTs(d.last)],
        ['Times fetched', full(d.count)],
        Number.isFinite(d.ips) ? ['Fetched by', full(d.ips) + (d.ips === 1 ? ' IP' : ' IPs')] : null,
      ]),
    ];
    if (d.url) parts.push(dsec('Downloaded from (defanged)', h('p', { class: 'mono break' }, attackerText(d.url))));
    if (m && ((m.script_urls || []).length || (m.script_archs || []).length)) {
      parts.push(dsec('What the script fetches',
        (m.script_archs || []).length ? h('div', { class: 'chips' }, m.script_archs.map((a) => h('span', { class: 'chip mono' }, attackerText(a)))) : null,
        (m.script_urls || []).length ? h('ul', { class: 'd-list mono' }, m.script_urls.slice(0, 20).map((u) => h('li', {}, attackerText(u)))) : null,
        h('p', { class: 'd-note', text: 'Droppers usually download one build per CPU architecture. URLs are defanged.' })));
    }
    if (m && (m.hints || []).length) parts.push(dsec('Strings found', h('div', { class: 'chips' }, m.hints.map((t) => h('span', { class: 'chip mono' }, attackerText(t))))));
    const intel = d.intel || {};
    const intelRows = [];
    if (intel.vt && Number.isFinite(intel.vt.malicious)) {
      intelRows.push(['VirusTotal', `${full(intel.vt.malicious)} of ${full(intel.vt.total || 0)} engines flag it` + (intel.vt.label ? ` · ${intel.vt.label}` : '')]);
    }
    if (intel.mb && (intel.mb.signature || (intel.mb.tags || []).length)) {
      intelRows.push(['MalwareBazaar', [intel.mb.signature, (intel.mb.tags || []).join(', ')].filter(Boolean).join(' · ')]);
    }
    parts.push(dsec('Threat intel', intelRows.length ? facts(intelRows) : emptyNote('No lookup result yet.'),
      h('p', { class: 'd-links' }, externalLink('https://www.virustotal.com/gui/file/' + sha, 'VirusTotal'), ' ',
        externalLink('https://bazaar.abuse.ch/sample/' + sha + '/', 'MalwareBazaar'))));
    const who = [];
    if ((d.top_ips || []).length) who.push(h('p', {}, h('span', { class: 'd-label', text: 'IPs ' }), ...d.top_ips.slice(0, 8).map((ip, i) => [i ? ', ' : '', ipButton(ip)])));
    if ((d.campaigns || []).length) who.push(h('p', {}, h('span', { class: 'd-label', text: 'Campaigns ' }), ...d.campaigns.map((id, i) => [i ? ', ' : '', campaignButton(id)])));
    if (who.length) parts.push(dsec('Who fetched it', ...who));
    parts.push(h('p', { class: 'd-note', text: 'The file itself never leaves the honeypot. Never download samples to your own machine.' }));
    return { kicker: 'Malware sample', title: sha.slice(0, 16) + '…', mono: true, body: h('div', {}, ...parts) };
  }

  function credentialDrawer(params) {
    const hasUser = 'username' in params;
    const hasPass = 'password' in params;
    const u = params.username;
    const pw = params.password;
    const w = currentWindow();
    let attempts = null;
    if (hasUser && hasPass) attempts = (w.credentials.find((r) => r[0] === u && r[1] === pw) || [])[2];
    else if (hasPass) attempts = (w.passwords.find((r) => r[0] === pw) || [])[1];
    else attempts = (w.usernames.find((r) => r[0] === u) || [])[1];
    const kicker = hasUser && hasPass ? 'Credential pair' : hasPass ? 'Password' : 'Username';
    const value = h('div', { class: 'cred' },
      hasUser ? h('div', {}, h('span', { class: 'd-label', text: 'Username' }), h('code', {}, attackerText(u))) : null,
      hasPass ? h('div', {}, h('span', { class: 'd-label', text: 'Password' }), h('code', {}, attackerText(pw))) : null);
    const parts = [value, mini([[attempts != null ? 'Login attempts' : 'Not in this period\'s top list', attempts != null ? full(attempts) : '–']])];
    const ipSlot = h('div', {}, loadingNote());
    parts.push(dsec('IPs that tried it', ipSlot));
    loadProfiles().then((profiles) => {
      const rows = [];
      for (const [ip, p] of Object.entries(profiles || {})) {
        let n = 0;
        for (const [cu, cp, k] of p.credentials || []) {
          if ((!hasUser || cu === u) && (!hasPass || cp === pw)) n += k;
        }
        if (n) rows.push([ip, n]);
      }
      rows.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
      if (!rows.length) return ipSlot.replaceChildren(emptyNote('None of the published IP profiles lists it.'));
      const list = h('div');
      barList(list, rows.slice(0, 25).map(([ip, n]) => ({ label: ip, value: n, open: () => openDrawer({ ip }) })), { mono: true, unit: 'attempts' });
      ipSlot.replaceChildren(list, h('p', { class: 'd-note', text: `${full(rows.length)} IP${rows.length === 1 ? '' : 's'}, based on each IP's ten most-used credentials over the last 30 days.` }));
    });
    parts.push(periodNote(w));
    const title = hasUser && hasPass ? `${u === '' ? '(empty)' : u} / ${pw === '' ? '(empty)' : pw}` : hasPass ? (pw === '' ? '(empty)' : pw) : (u === '' ? '(empty)' : u);
    return { kicker, title, mono: true, body: h('div', {}, ...parts) };
  }

  function replayDrawer(id) {
    if (!REPLAY_ID.test(id)) return { kicker: 'Session replay', title: 'Unknown recording', body: emptyNote() };
    const meta = findReplay(id);
    const slot = h('div', { class: 'replay-slot' });
    const info = h('div');
    const fill = (r) => info.replaceChildren(facts([
      ['Source IP', ipButton(r.ip)],
      r.cc ? ['Country', COUNTRY.test(r.cc) ? navButton(countryName(r.cc), { country: r.cc }) : countryName(r.cc)] : null,
      r.protocol ? ['Protocol', String(r.protocol).toUpperCase()] : null,
      ['Started', fmtTs(r.ts || r.start)],
      Number.isFinite(r.duration_ms) ? ['Duration', formatDuration(r.duration_ms)] : Number.isFinite(r.duration) ? ['Duration', formatDuration(r.duration * 1000)] : null,
      Number.isFinite(r.commands) ? ['Commands', full(r.commands)] : null,
      r.campaign && CAMPAIGN_ID.test(r.campaign) ? ['Campaign', campaignButton(r.campaign, r.campaign_name)] : null,
    ]));
    if (meta) fill(meta);
    setTimeout(() => mountReplay(slot, id, true, 'Session from ' + ((meta && meta.ip) || 'an attacker')).then((p) => {
      if (p) drawer.players.push(p);
      if (!meta) loadReplay(id).then((doc) => { if (doc) fill(doc); });
    }));
    return { kicker: meta && meta.campaign_name ? meta.campaign_name : 'Session replay', title: 'Session replay', body: h('div', {}, slot, info) };
  }

  function buildDrawer(params) {
    if ('replay' in params) return replayDrawer(params.replay);
    if ('sample' in params) return sampleDrawer(params.sample);
    if ('campaign' in params) return campaignDrawer(params.campaign);
    if ('ip' in params) return ipDrawer(params.ip);
    if ('country' in params) return countryDrawer(params.country);
    return credentialDrawer(params);
  }

  // ------------------------------------------------ drawer shell, history and focus

  const drawer = { open: false, key: '', opener: null, players: [], closing: false };
  const drawerDepth = () => (history.state && history.state.drawerDepth) || 0;
  const paramsKey = (params) => DRAWER_KEYS.filter((k) => k in params).map((k) => k + '=' + params[k]).join('&');

  /** Open a drawer as a new history entry, so Back steps through drawers and finally closes them. */
  function openDrawer(params) {
    if (!state.stats) return;
    hideTip();
    history.pushState({ drawerDepth: drawerDepth() + 1 }, '', hashFor(state.window, params));
    showDrawer(params);
  }

  function closeDrawer() {
    const depth = drawerDepth();
    if (depth > 0) {
      drawer.closing = true;
      history.go(-depth);         // popstate finishes the job
    } else {
      history.replaceState({ drawerDepth: 0 }, '', hashFor(state.window, {}));
      hideDrawer();
    }
  }

  function setInert(on) {
    for (const node of document.body.children) {
      if (node.id === 'drawer' || node.id === 'tooltip' || node.tagName === 'SCRIPT') continue;
      if (on) node.setAttribute('inert', ''); else node.removeAttribute('inert');
    }
  }

  function destroyPlayers() {
    drawer.players.forEach((p) => p.destroy());
    drawer.players = [];
  }

  function showDrawer(params) {
    const key = paramsKey(params);
    if (drawer.open && key === drawer.key) return;
    const layer = $('#drawer');
    if (!drawer.open) {
      drawer.opener = document.activeElement;
      layer.hidden = false;
      document.body.classList.add('drawer-open');
      setInert(true);
      state.cards.forEach((c) => { if (c.player) c.player.pause(); });
    }
    destroyPlayers();
    drawer.open = true;
    drawer.key = key;
    const d = buildDrawer(params);
    $('#drawer-kicker').textContent = d.kicker || '';
    const title = $('#drawer-title');
    title.textContent = d.title;
    title.classList.toggle('mono', !!d.mono);
    const body = $('#drawer-body');
    body.replaceChildren(d.body);
    body.scrollTop = 0;
    $('#drawer-panel').focus();
  }

  function hideDrawer() {
    if (!drawer.open) return;
    destroyPlayers();
    hideTip();
    drawer.open = false;
    drawer.key = '';
    $('#drawer').hidden = true;
    $('#drawer-body').replaceChildren();
    document.body.classList.remove('drawer-open');
    setInert(false);
    const back = drawer.opener && drawer.opener.isConnected && drawer.opener !== document.body ? drawer.opener : $('#main');
    drawer.opener = null;
    if (back.id === 'main') back.setAttribute('tabindex', '-1');
    back.focus({ preventScroll: true });
  }

  /** Apply the hash (after Back/Forward, a pasted link or the initial load). */
  function syncFromHash() {
    const { window: win, params } = parseHash();
    if (drawer.closing) {
      drawer.closing = false;
      if (Object.keys(params).length) history.replaceState({ drawerDepth: 0 }, '', hashFor(win || state.window, {}));
      hideDrawer();
      return;
    }
    if (win && win !== state.window && state.stats) {
      state.window = win;
      render();
    }
    if (Object.keys(params).length && state.stats) showDrawer(params);
    else hideDrawer();
  }

  function wireDrawer() {
    const layer = $('#drawer');
    $('#drawer-close').addEventListener('click', closeDrawer);
    layer.querySelector('.drawer-backdrop').addEventListener('click', closeDrawer);
    layer.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); closeDrawer(); return; }
      if (e.key !== 'Tab') return;
      const focusable = [...layer.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])')]
        .filter((n) => n.offsetParent !== null || n === document.activeElement);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === $('#drawer-panel'))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    $('#drawer-body').addEventListener('scroll', hideTip, { passive: true });
    window.addEventListener('popstate', syncFromHash);
    window.addEventListener('hashchange', syncFromHash);
  }

  function renderKpis(w) {
    const firstDay = state.stats.sensor.first_day;
    const KPIS = [
      { key: 'sessions', label: 'Connections', hero: true },
      { key: 'unique_ips', label: 'Unique attacker IPs' },
      { key: 'login_attempts', label: 'Login attempts' },
      { key: 'login_success', label: 'Logins to the fake shell' },
      { key: 'commands', label: 'Commands run' },
      { key: 'downloads', label: 'Malware samples', series: false },
      { key: 'countries', label: 'Countries', series: false },
    ];
    $('#kpis').replaceChildren(...KPIS.map((k) => {
      const value = w.totals[k.key];
      const prev = w.previous ? w.previous[k.key] : null;
      let delta;
      if (state.window === 'all') delta = 'since ' + dayYearFmt.format(parseDay(firstDay));
      else if (prev == null) delta = k.hero ? 'no full previous ' + PERIOD[state.window] + ' to compare yet' : null;
      else if (prev === 0) delta = value ? 'new vs previous ' + PERIOD[state.window] : 'none in either period';
      else {
        const change = (value - prev) / prev;
        const arrow = change > 0.005 ? '▲ ' : change < -0.005 ? '▼ ' : '';
        delta = `${arrow}${pf.format(Math.abs(change))} vs previous ${PERIOD[state.window]}`;
      }
      return h('div', { class: 'tile' + (k.hero ? ' hero' : '') },
        h('div', { class: 'tile-label', text: k.label }),
        h('div', { class: 'tile-value', text: k.hero ? full(value) : tileValue(value) }),
        delta ? h('div', { class: 'tile-delta', text: delta }) : null,
        k.series === false ? null : sparkline(w.daily.map((d) => d[k.key]), k.hero));
    }));
  }

  function renderStatus(stats) {
    const node = $('#status');
    if (DEMO || !stats.sensor) { node.hidden = true; return; }
    const ageDays = Math.round((parseDay(todayUtc()) - parseDay(stats.sensor.last_day)) / 864e5);
    const live = ageDays <= 1;
    node.className = 'status ' + (live ? 'good' : 'warning');
    node.replaceChildren(h('span', { class: 'status-icon', 'aria-hidden': 'true', text: live ? '●' : '▲' }),
      live ? 'Live · updated ' + relativeTime(new Date(stats.generated_at))
        : 'No new data since ' + dayFmt.format(parseDay(stats.sensor.last_day)));
    node.hidden = false;
  }

  function render() {
    const w = currentWindow();
    document.querySelectorAll('.segmented button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.window === state.window)));
    const start = parseDay(w.start);
    const end = parseDay(w.end);
    $('#range').textContent = (w.start === w.end ? dayYearFmt.format(end) : `${dayFmt.format(start)} – ${dayYearFmt.format(end)}`) + ' · UTC';
    renderKpis(w);
    state.cards.forEach(renderCard);
  }

  function wireWindows() {
    document.querySelectorAll('.segmented button').forEach((button) => button.addEventListener('click', () => {
      state.window = button.dataset.window;
      try { localStorage.setItem('window', state.window); } catch (e) { /* storage blocked */ }
      history.replaceState({ drawerDepth: 0 }, '', hashFor(state.window, {}));
      hideTip();
      render();
    }));
  }

  function wireTheme() {
    const button = $('#theme');
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const current = () => document.documentElement.dataset.theme || (media.matches ? 'dark' : 'light');
    const sync = () => {
      const dark = current() === 'dark';
      button.setAttribute('aria-pressed', String(dark));
      button.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    };
    button.addEventListener('click', () => {
      const next = current() === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem('theme', next); } catch (e) { /* storage blocked */ }
      sync();
    });
    media.addEventListener('change', sync);
    sync();
  }

  function debounce(fn, ms) {
    let timer;
    return () => { clearTimeout(timer); timer = setTimeout(fn, ms); };
  }

  async function init() {
    wireTheme();
    if (DEMO) $('#demo-banner').hidden = false;
    if (typeof d3 === 'undefined') {
      $('#empty').hidden = false;
      $('#empty').replaceChildren(h('h2', { text: 'Charts failed to load' }),
        h('p', { text: 'The page needs D3 from cdn.jsdelivr.net. Check your connection or content blocker.' }));
      return;
    }
    let stats = null;
    try {
      const res = await fetch(DATA_URL, { cache: 'no-cache' });
      if (res.ok) stats = await res.json();
    } catch (e) { /* fall through to the empty state */ }
    if (!stats || !stats.windows || !stats.windows[state.window]) {
      $('#empty').hidden = false;
      document.querySelector('.toolbar').hidden = true;
      if (DEMO) $('#empty').replaceChildren(h('h2', { text: 'No demo data here' }),
        h('p', {}, 'Run ', h('code', { text: 'make demo' }), ' to generate it, then reload.'));
      return;
    }
    state.stats = stats;
    try {
      const topo = await (await fetch('assets/world-110m.json')).json();
      const features = topojson.feature(topo, topo.objects.countries).features.filter((f) => f.properties.cc !== 'AQ');
      state.world = { type: 'FeatureCollection', features };
    } catch (e) { state.world = null; }

    wireWindows();
    wireDrawer();
    renderStatus(stats);
    buildCards();
    $('#dashboard').hidden = false;
    render();
    syncFromHash();                 // a deep link may open a drawer straight away
    state.width = $('#grid').clientWidth;
    new ResizeObserver(debounce(() => {
      const width = $('#grid').clientWidth;
      if (width === state.width) return;
      state.width = width;
      state.cards.filter((card) => card.resize !== false).forEach(renderCard);
    }, 150)).observe($('#grid'));
  }

  init();
})();
