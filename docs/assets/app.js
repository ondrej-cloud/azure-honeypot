/* Honeypot telemetry dashboard: renders data/stats.json with D3.
 *
 * Every string in the data (usernames, passwords, commands, URLs) was typed by
 * an attacker. It only ever reaches the DOM through textContent, createTextNode
 * or setAttribute - never innerHTML - and links are built only from values that
 * pass a strict format check. */
'use strict';

(function () {
  const DEMO = new URLSearchParams(location.search).has('demo');
  const DATA_URL = DEMO ? 'data/stats.demo.json' : 'data/stats.json';
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
  const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;

  function externalLink(href, text, cls) {
    return h('a', { href, class: cls, target: '_blank', rel: 'noopener noreferrer', text });
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

  /** Horizontal bar list: label, thin bar, value at the tip. Rows: {label, value, tip, text}. */
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
      list.append(li);
    }
    body.replaceChildren(list);
  }

  function renderTable(body, spec) {
    if (!spec.rows.length) return body.replaceChildren(emptyNote());
    const head = h('tr', {}, spec.columns.map((c) => h('th', { scope: 'col', class: c.num ? 'num' : null, text: c.label })));
    const rows = spec.rows.map((r) => h('tr', {}, spec.columns.map((c) => {
      const value = c.value(r);
      const cls = [c.num && 'num', c.mono && 'mono', c.nowrap && 'nowrap'].filter(Boolean).join(' ') || null;
      return h('td', { class: cls }, value instanceof Node ? value : c.num ? full(value) : String(value));
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
        if (c) this.setAttribute('tabindex', '0');
        bindTip(this, () => [countryName(f.properties.cc), c ? [
          { value: full(c.sessions), label: 'connections' },
          { value: full(c.ips), label: 'unique IPs' },
          { value: share(c.sessions, total), label: 'of all connections' },
        ] : [{ value: '0', label: 'connections' }]], (on) => {
          d3.select(this).classed('hot', on);
          if (on) d3.select(this).raise();
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

  // ---------------------------------------------------------------- card registry

  const col = (label, value, extra) => Object.assign({ label, value }, extra);

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
      })), { total: w.totals.sessions, shareOf: 'all connections' }),
      table: (w) => CARDS[1].table(w),
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
      id: 'usernames', span: 4, title: 'Top usernames', sub: 'Login attempts per username',
      chart: (body, w) => barList(body, pairs(w.usernames.slice(0, 10)), { mono: true, unit: 'attempts', total: w.totals.login_attempts, shareOf: 'all attempts' }),
      table: (w) => ({ columns: [col('Username', (r) => attackerText(r[0]), { mono: true }), col('Attempts', (r) => r[1], { num: true })], rows: w.usernames }),
    },
    {
      id: 'passwords', span: 4, title: 'Top passwords', sub: 'Login attempts per password',
      chart: (body, w) => barList(body, pairs(w.passwords.slice(0, 10)), { mono: true, unit: 'attempts', total: w.totals.login_attempts, shareOf: 'all attempts' }),
      table: (w) => ({ columns: [col('Password', (r) => attackerText(r[0]), { mono: true }), col('Attempts', (r) => r[1], { num: true })], rows: w.passwords }),
    },
    {
      id: 'credentials', span: 4, title: 'Top credential pairs', sub: 'Username / password combinations',
      chart: (body, w) => barList(body, w.credentials.slice(0, 10).map(([u, p, n]) => ({
        label: credentialLabel(u, p), text: `${u || '(empty)'} / ${p || '(empty)'}`, value: n,
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
      sub: 'Usually compromised hosts or rented servers. Look them up before drawing conclusions.',
      table: (w) => ({
        columns: [
          col('IP address', (r) => r.ip, { mono: true }),
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
      id: 'downloads', span: 12, title: 'Captured malware downloads',
      sub: 'Files attackers fetched into the fake shell. URLs are defanged; hashes open VirusTotal.',
      table: (w) => ({
        columns: [
          col('SHA-256', (d) => (SHA256.test(d.sha256)
            ? externalLink('https://www.virustotal.com/gui/file/' + d.sha256, d.sha256.slice(0, 16) + '…') : '–'), { mono: true, nowrap: true }),
          col('Source (defanged)', (d) => d.url || '–', { mono: true }),
          col('Times seen', (d) => d.count, { num: true }),
          col('First seen', (d) => d.first.slice(0, 16).replace('T', ' '), { nowrap: true }),
          col('Last seen', (d) => d.last.slice(0, 16).replace('T', ' '), { nowrap: true }),
        ],
        rows: w.downloads,
      }),
    },
  ];

  // ---------------------------------------------------------------- page

  const state = { stats: null, world: null, window: initialWindow(), width: 0 };

  function initialWindow() {
    const fromHash = location.hash.slice(1);
    if (WINDOWS.includes(fromHash)) return fromHash;
    try {
      const saved = localStorage.getItem('window');
      if (WINDOWS.includes(saved)) return saved;
    } catch (e) { /* storage blocked */ }
    return '30d';
  }

  const currentWindow = () => state.stats.windows[state.window];

  function buildCards() {
    $('#grid').replaceChildren(...CARDS.map((card) => {
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
    else card.chart(card.body, w);
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
    CARDS.forEach(renderCard);
  }

  function wireWindows() {
    document.querySelectorAll('.segmented button').forEach((button) => button.addEventListener('click', () => {
      state.window = button.dataset.window;
      try { localStorage.setItem('window', state.window); } catch (e) { /* storage blocked */ }
      history.replaceState(null, '', '#' + state.window);
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
    renderStatus(stats);
    buildCards();
    $('#dashboard').hidden = false;
    render();
    state.width = $('#grid').clientWidth;
    new ResizeObserver(debounce(() => {
      const width = $('#grid').clientWidth;
      if (width === state.width) return;
      state.width = width;
      CARDS.forEach(renderCard);
    }, 150)).observe($('#grid'));
  }

  init();
})();
