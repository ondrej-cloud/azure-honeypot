/* Session replay player: a small terminal emulator for Cowrie recordings.
 *
 * A recording is what an attacker saw in the fake shell, so it is hostile
 * input. Text only ever reaches the DOM through textContent; escape sequences
 * are interpreted here (a safe subset) and everything else is dropped.
 * xterm.js is not an option: the page's CSP forbids the <style> it injects. */
'use strict';

(function () {
  const COLS = 80;
  const ROWS = 24;
  const MAX_LINES = 3000;
  const IDLE_CAP = 1.5;            // seconds; long pauses are shortened
  const SPEEDS = [1, 2, 4, 8];
  const players = new Set();

  // ---------------------------------------------------------------- screen model

  class Screen {
    constructor() { this.reset(); }

    reset() {
      this.lines = [{ c: [], s: [] }];
      this.row = 0;
      this.col = 0;
      this.top = 0;                // first line of the visible 80x24 screen
      this.bold = false;
      this.dim = false;
      this.fg = 0;
      this.style = '';
      this.mode = 'text';
      this.params = '';
      this.oscLength = 0;
      this.dirty = new Set();
      this.full = true;            // the whole view must be rebuilt
    }

    line(r) {
      while (this.lines.length <= r) this.lines.push({ c: [], s: [] });
      return this.lines[r];
    }

    touch(r) { this.dirty.add(r); }

    newline() {
      this.touch(this.row);
      this.row += 1;
      this.col = 0;
      this.line(this.row);
      if (this.row - this.top >= ROWS) this.top = this.row - ROWS + 1;
      if (this.lines.length > MAX_LINES) {
        const drop = this.lines.length - MAX_LINES;
        this.lines.splice(0, drop);
        this.row -= drop;
        this.top = Math.max(0, this.top - drop);
        this.full = true;
      }
      this.touch(this.row);
    }

    put(ch) {
      if (this.col >= COLS) this.newline();
      const ln = this.line(this.row);
      while (ln.c.length < this.col) { ln.c.push(' '); ln.s.push(''); }
      ln.c[this.col] = ch;
      ln.s[this.col] = this.style;
      this.col += 1;
      this.touch(this.row);
    }

    write(text) {
      for (const ch of text) {
        const code = ch.codePointAt(0);
        switch (this.mode) {
          case 'esc':
            if (ch === '[') { this.mode = 'csi'; this.params = ''; }
            else if (ch === ']') { this.mode = 'osc'; this.oscLength = 0; }
            else if ('()*+#'.includes(ch)) this.mode = 'skip1';
            else this.mode = 'text';
            continue;
          case 'skip1':
            this.mode = 'text';
            continue;
          case 'csi':
            if (code >= 0x20 && code <= 0x3f && this.params.length < 32) { this.params += ch; continue; }
            this.mode = 'text';
            if (code >= 0x40 && code <= 0x7e) this.csi(ch, this.params);
            continue;
          case 'osc':                 // window titles etc.: ignored up to BEL or ESC \
            if (ch === '\x07' || ++this.oscLength > 512) this.mode = 'text';
            else if (ch === '\x1b') this.mode = 'osc-esc';
            continue;
          case 'osc-esc':
            this.mode = ch === '\\' ? 'text' : 'osc';
            continue;
          default:
            break;
        }
        if (ch === '\x1b') this.mode = 'esc';
        else if (ch === '\n') this.newline();          // the recording has no tty layer: \n means CR LF
        else if (ch === '\r') this.col = 0;
        else if (ch === '\b') { this.col = Math.max(0, Math.min(this.col, COLS) - 1); this.touch(this.row); }
        else if (ch === '\t') this.col = Math.min(COLS - 1, (Math.floor(this.col / 8) + 1) * 8);
        else if (code < 0x20 || (code >= 0x7f && code < 0xa0)) continue;
        else this.put(ch);
      }
    }

    csi(final, raw) {
      const nums = raw.replace(/[^0-9;]/g, '').split(';').map((n) => (n === '' ? NaN : parseInt(n, 10)));
      const n = (i, d) => (Number.isFinite(nums[i]) ? nums[i] : d);
      const ln = this.line(this.row);
      switch (final) {
        case 'K': {
          const mode = n(0, 0);
          if (mode === 0) { ln.c.length = Math.min(ln.c.length, this.col); ln.s.length = ln.c.length; }
          else if (mode === 1) for (let i = 0; i <= this.col && i < ln.c.length; i++) { ln.c[i] = ' '; ln.s[i] = ''; }
          else { ln.c = []; ln.s = []; }
          this.touch(this.row);
          break;
        }
        case 'J': {
          const mode = n(0, 0);
          if (mode === 0) {
            ln.c.length = Math.min(ln.c.length, this.col);
            ln.s.length = ln.c.length;
            this.lines.length = this.row + 1;
            this.full = true;
          } else if (mode >= 2) {
            // Keep what was on screen as history and start a fresh screen below it.
            this.lines.push({ c: [], s: [] });
            this.top = this.lines.length - 1;
            this.row = this.top;
            this.col = 0;
            this.full = true;
          }
          break;
        }
        case 'H': case 'f':
          this.touch(this.row);
          this.row = this.top + Math.min(ROWS - 1, Math.max(0, n(0, 1) - 1));
          this.col = Math.min(COLS - 1, Math.max(0, n(1, 1) - 1));
          this.line(this.row);
          this.touch(this.row);
          break;
        case 'A': this.touch(this.row); this.row = Math.max(this.top, this.row - n(0, 1)); this.touch(this.row); break;
        case 'B': this.touch(this.row); this.row += n(0, 1); this.line(this.row); this.touch(this.row); break;
        case 'C': this.col = Math.min(COLS - 1, this.col + n(0, 1)); this.touch(this.row); break;
        case 'D': this.col = Math.max(0, this.col - n(0, 1)); this.touch(this.row); break;
        case 'G': this.col = Math.min(COLS - 1, Math.max(0, n(0, 1) - 1)); this.touch(this.row); break;
        case 'P': ln.c.splice(this.col, n(0, 1)); ln.s.splice(this.col, n(0, 1)); this.touch(this.row); break;
        case '@': {
          const count = Math.min(COLS, n(0, 1));
          ln.c.splice(this.col, 0, ...Array(count).fill(' '));
          ln.s.splice(this.col, 0, ...Array(count).fill(''));
          ln.c.length = Math.min(ln.c.length, COLS);
          ln.s.length = ln.c.length;
          this.touch(this.row);
          break;
        }
        case 'm': this.sgr(nums); break;
        default: break;                 // modes (4h insert, ?25l cursor...) and the rest: ignored
      }
    }

    sgr(nums) {
      if (!nums.length) nums = [0];
      for (const v of nums) {
        if (!Number.isFinite(v) || v === 0) { this.bold = false; this.dim = false; this.fg = 0; }
        else if (v === 1) this.bold = true;
        else if (v === 2) this.dim = true;
        else if (v === 22) { this.bold = false; this.dim = false; }
        else if (v >= 30 && v <= 37) this.fg = v - 29;
        else if (v >= 90 && v <= 97) this.fg = v - 89;
        else if (v === 39) this.fg = 0;
      }
      this.style = [this.bold ? 'b' : '', this.dim ? 'd' : '', this.fg ? 'f' + this.fg : ''].filter(Boolean).join(' ');
    }
  }

  // ---------------------------------------------------------------- view

  function fillRow(el, ln, cursorCol) {
    const frag = document.createDocumentFragment();
    let text = '';
    let style = null;
    const flush = () => {
      if (!text) return;
      if (style) {
        const span = document.createElement('span');
        span.className = style.split(' ').map((s) => 't-' + s).join(' ');
        span.textContent = text;
        frag.append(span);
      } else frag.append(document.createTextNode(text));
      text = '';
    };
    const width = Math.max(ln.c.length, cursorCol >= 0 ? cursorCol + 1 : 0);
    for (let i = 0; i < width; i++) {
      const ch = i < ln.c.length ? ln.c[i] : ' ';
      const st = i < ln.s.length ? ln.s[i] || '' : '';
      if (i === cursorCol) {
        flush();
        const cur = document.createElement('span');
        cur.className = 'cursor';
        cur.textContent = ch;
        frag.append(cur);
        style = null;
        continue;
      }
      if (st !== style) { flush(); style = st; }
      text += ch;
    }
    flush();
    el.replaceChildren(frag);
  }

  class View {
    constructor(node) {
      this.node = node;
      this.rows = [];
      this.cursorRow = -1;
      this.showCursor = true;
    }

    render(screen) {
      const atBottom = this.node.scrollHeight - this.node.scrollTop - this.node.clientHeight < 32;
      if (screen.full) {
        this.node.replaceChildren();
        this.rows = [];
        screen.full = false;
        for (let r = 0; r < screen.lines.length; r++) screen.dirty.add(r);
      }
      while (this.rows.length > screen.lines.length) this.rows.pop().remove();
      while (this.rows.length < screen.lines.length) {
        const div = document.createElement('div');
        div.className = 'term-row';
        this.node.append(div);
        this.rows.push(div);
        screen.dirty.add(this.rows.length - 1);
      }
      if (this.cursorRow !== screen.row) {
        screen.dirty.add(this.cursorRow);
        screen.dirty.add(screen.row);
        this.cursorRow = screen.row;
      }
      for (const r of screen.dirty) {
        if (r < 0 || r >= this.rows.length) continue;
        fillRow(this.rows[r], screen.lines[r], this.showCursor && r === screen.row ? Math.min(screen.col, COLS - 1) : -1);
      }
      screen.dirty.clear();
      if (atBottom) this.node.scrollTop = this.node.scrollHeight;
    }
  }

  // ---------------------------------------------------------------- player

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  };

  const clock = (s) => {
    const t = Math.max(0, Math.round(s));
    return Math.floor(t / 60) + ':' + String(t % 60).padStart(2, '0');
  };

  /** Normalize frames: [[seconds, text], ...], monotonic, idle gaps capped. */
  function timeline(frames) {
    const out = [];
    let prevT = 0;
    let at = 0;
    for (const f of Array.isArray(frames) ? frames : []) {
      if (!Array.isArray(f) || typeof f[1] !== 'string') continue;
      const t = Number.isFinite(+f[0]) ? Math.max(prevT, +f[0]) : prevT;
      at += Math.min(IDLE_CAP, t - prevT);
      prevT = t;
      out.push({ at, text: f[1] });
    }
    return out;
  }

  /**
   * Mount a player for one replay document into `root`.
   * opts: {autoplay, label}. Returns {play, pause, destroy}.
   */
  function createPlayer(root, replay, opts) {
    const o = Object.assign({ autoplay: false, label: 'Session replay' }, opts);
    const frames = timeline(replay && replay.frames);
    const total = frames.length ? frames[frames.length - 1].at + 0.4 : 0;
    const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const wrap = el('div', 'player');
    const term = el('div', 'term');
    term.tabIndex = 0;
    term.setAttribute('role', 'log');
    term.setAttribute('aria-live', 'off');     // never read out every echoed keystroke
    term.setAttribute('aria-label', o.label + '. Terminal output. Space plays or pauses, arrow keys seek.');
    const screenNode = el('div', 'term-screen');
    term.append(screenNode);

    const controls = el('div', 'player-controls');
    const playBtn = el('button', 'btn small play');
    playBtn.type = 'button';
    const restartBtn = el('button', 'btn small', 'Restart');
    restartBtn.type = 'button';
    const scrub = el('input', 'scrub');
    scrub.type = 'range';
    scrub.min = '0';
    scrub.max = '1000';
    scrub.step = '1';
    scrub.value = '0';
    scrub.setAttribute('aria-label', 'Position in the recording');
    const time = el('span', 'player-time');
    const speeds = el('div', 'speeds');
    speeds.setAttribute('role', 'group');
    speeds.setAttribute('aria-label', 'Playback speed');
    const speedBtns = SPEEDS.map((s) => {
      const b = el('button', 'btn small', s + '×');
      b.type = 'button';
      b.setAttribute('aria-label', 'Speed ' + s + ' times');
      b.addEventListener('click', () => setSpeed(s));
      speeds.append(b);
      return b;
    });
    const transcriptBtn = el('button', 'btn small', 'Show transcript');
    transcriptBtn.type = 'button';
    controls.append(playBtn, restartBtn, scrub, time, speeds, transcriptBtn);

    const notes = el('p', 'player-note');
    notes.textContent = 'What the attacker saw in the fake shell. Pauses over ' + IDLE_CAP + ' s are shortened; URLs are defanged.' +
      (replay && replay.truncated ? ' The recording was cut at 64 KB.' : '');
    wrap.append(term, controls, notes);
    root.replaceChildren(wrap);

    const screen = new Screen();
    const view = new View(screenNode);
    let pos = 0;
    let next = 0;
    let playing = false;
    let speed = 1;
    let raf = 0;
    let last = 0;

    function apply(until) {
      while (next < frames.length && frames[next].at <= until + 1e-9) {
        screen.write(frames[next].text);
        next += 1;
      }
      view.showCursor = next < frames.length || playing;
      view.render(screen);
    }

    function seek(p, scrollEnd) {
      p = Math.max(0, Math.min(total, p));
      if (p < pos || (next > 0 && frames[next - 1].at > p)) {
        screen.reset();
        next = 0;
      }
      pos = p;
      apply(pos);
      if (scrollEnd) term.scrollTop = term.scrollHeight;
      sync();
    }

    function sync() {
      const ended = pos >= total;
      playBtn.textContent = playing ? 'Pause' : ended && total ? 'Replay' : 'Play';
      playBtn.setAttribute('aria-label', playing ? 'Pause replay' : ended && total ? 'Play again from the start' : 'Play replay');
      scrub.value = String(total ? Math.round((pos / total) * 1000) : 0);
      scrub.setAttribute('aria-valuetext', clock(pos) + ' of ' + clock(total));
      time.textContent = clock(pos) + ' / ' + clock(total);
      speedBtns.forEach((b, i) => b.setAttribute('aria-pressed', String(SPEEDS[i] === speed)));
      wrap.classList.toggle('is-playing', playing);
    }

    function tick(ts) {
      if (!playing) return;
      const dt = last ? Math.min(0.25, (ts - last) / 1000) : 0;
      last = ts;
      pos = Math.min(total, pos + dt * speed);
      apply(pos);
      if (pos >= total) { pause(); return; }
      sync();
      raf = requestAnimationFrame(tick);
    }

    function play() {
      if (!frames.length) return;
      players.forEach((p) => { if (p !== api) p.pause(); });
      if (pos >= total) seek(0);
      playing = true;
      last = 0;
      sync();
      raf = requestAnimationFrame(tick);
    }

    function pause() {
      playing = false;
      cancelAnimationFrame(raf);
      apply(pos);
      sync();
    }

    function setSpeed(s) { speed = s; sync(); }

    playBtn.addEventListener('click', () => (playing ? pause() : play()));
    restartBtn.addEventListener('click', () => { seek(0); play(); });
    transcriptBtn.addEventListener('click', () => { pause(); seek(total, true); });
    scrub.addEventListener('input', () => { seek((+scrub.value / 1000) * total, true); });
    term.addEventListener('keydown', (e) => {
      if (e.key === ' ' || e.key === 'k') { e.preventDefault(); playing ? pause() : play(); }
      else if (e.key === 'ArrowRight') { e.preventDefault(); seek(pos + 5, true); }
      else if (e.key === 'ArrowLeft') { e.preventDefault(); seek(pos - 5, true); }
      else if (e.key === 'End') { e.preventDefault(); pause(); seek(total, true); }
      else if (e.key === 'Home') { e.preventDefault(); seek(0); }
    });

    const api = {
      play,
      pause,
      destroy() { pause(); players.delete(api); },
    };
    players.add(api);

    if (!frames.length) {
      screenNode.append(el('div', 'term-row', '(this recording has no visible output)'));
      [playBtn, restartBtn, scrub, transcriptBtn].forEach((b) => { b.disabled = true; });
      sync();
      return api;
    }
    if (reduced) seek(total, true);     // no animation: show the whole transcript
    else {
      seek(0);
      if (o.autoplay) play();
    }
    sync();
    return api;
  }

  window.HoneypotReplay = { createPlayer, Screen, COLS };
})();
