/* ───────────────────────────────────────────────────────────
   SOFT MACHINE — the memory deck
   Eight authored SVG layers, a cartridge, and one mechanical
   refusal. Ported from the hero prototype and generalised so
   both surfaces drive the same object from real verdicts.

   Nothing in here decides anything. It is handed an outcome the
   gate already reached and plays it back: the deck closes and
   prints the terms, or the shutter slams on steps(3) in 90ms,
   the cartridge ejects on a spring-back arc, and the DENIED
   legend -- moulded into the SVG at opacity 0 from the start --
   becomes visible with the failing clause under it.
   ─────────────────────────────────────────────────────────── */
(function (global) {
  "use strict";

  var VB_W = 720, VB_H = 420;
  var SLOT = { x: 196, y: 300, w: 328, h: 58 };
  var LG = "font-family:'Azeret Mono',monospace;font-weight:500;letter-spacing:.08em";
  var uid = 0;

  function reduced() {
    return global.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function rng(seed) {
    return function () {
      seed |= 0; seed = seed + 0x6D2B79F5 | 0;
      var t = Math.imul(seed ^ seed >>> 15, 1 | seed);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }

  function hashSeed(s) {
    var h = 2166136261;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  /* ── the cartridge: silkscreen plus procedural wear ───────
     Wear is derived from the real session count -- the number of
     memories the store actually holds about this counterparty --
     so a heavily used cartridge looks it. */
  function cartridgeSVG(p, big, widthPx) {
    var w = widthPx || 260;
    var scale = big ? 176 / (w * 0.244) : 2.6;
    var rp = Math.max(3, Math.min(22, 0.008 * global.innerWidth * (VB_W / (w || 720)) * scale));
    if (!isFinite(rp)) rp = 6;
    var seed = hashSeed(String(p.id) + String(p.sessions));
    var rnd = rng(seed);
    var key = "c" + (uid++) + "_" + seed;
    var body = p.ok ? "var(--shell)" : "var(--safety)";
    var ink = p.ok ? "var(--ink)" : "#fff5ef";
    var inkF = p.ok ? "var(--ink-faint)" : "rgba(255,245,239,.7)";

    var scratches = "", n = 6 + Math.min(40, p.sessions || 0) * 3;
    for (var i = 0; i < n; i++) {
      var x = 6 + rnd() * 164, y = 6 + rnd() * 100;
      var len = 4 + rnd() * 26, ang = (rnd() - .5) * 0.7;
      scratches += '<line x1="' + x.toFixed(1) + '" y1="' + y.toFixed(1) +
        '" x2="' + (x + Math.cos(ang) * len).toFixed(1) + '" y2="' + (y + Math.sin(ang) * len).toFixed(1) +
        '" style="stroke:' + (p.ok ? "#000" : "#fff") + ";stroke-opacity:" + (0.03 + rnd() * 0.07).toFixed(3) +
        ";stroke-width:" + (rnd() > .8 ? 1.4 : .8).toFixed(1) + '" stroke-dasharray="' +
        (1 + rnd() * 3).toFixed(1) + " " + (1 + rnd() * 2).toFixed(1) + '"/>';
    }

    /* the verdict strip, straight off the record: one bar per memory,
       tall for admitted, mid for a refusal that is not an accusation,
       short for a forgery or a body we cannot read */
    var glyphs = "", marks = (p.marks || []).slice(0, 14);
    marks.forEach(function (o, i) {
      var f = o === 2 ? "var(--anodize)" : (o === 1 ? "var(--amber-key)" : (p.ok ? "var(--ink-faint)" : "rgba(255,240,235,.55)"));
      glyphs += '<rect x="' + (14 + i * 11) + '" y="86" width="7" height="' + (o === 0 ? 3 : (o === 1 ? 7 : 11)) +
        '" style="fill:' + f + '" transform="translate(0,' + (o === 0 ? 8 : (o === 1 ? 4 : 0)) + ')"/>';
    });

    var fingers = "";
    for (var k = 0; k < 9; k++) {
      fingers += '<rect x="' + (22 + k * 15) + '" y="0" width="9" height="7" rx="1" style="fill:var(--seam);opacity:.75"/>';
    }

    var hazard = p.ok ? "" :
      '<path d="M176 0 L176 26 L150 0 Z" style="fill:var(--safety-deep)"/>' +
      '<path d="M176 4 L176 26 L154 4 Z" style="fill:none;stroke:#fff;stroke-opacity:.35;stroke-width:1;stroke-dasharray:3 3"/>';

    return '<svg viewBox="0 0 176 112" role="img" aria-label="' + esc(p.label || p.id) + ' cartridge, ' +
      esc(p.tier) + ', ' + (p.sessions || 0) + ' memories">' +
      '<defs><linearGradient id="g' + key + '" x1="0" y1="0" x2=".25" y2="1">' +
      '<stop offset="0" stop-color="#ffffff" stop-opacity=".5"/>' +
      '<stop offset=".55" stop-color="#ffffff" stop-opacity="0"/></linearGradient>' +
      '<filter id="w' + key + '"><feTurbulence type="fractalNoise" baseFrequency=".8" numOctaves="2" seed="' + (seed % 90) + '"/><feColorMatrix type="saturate" values="0"/></filter>' +
      "</defs>" +
      '<rect x="2" y="4" width="172" height="106" rx="' + rp.toFixed(1) + '" style="fill:' + body + '"/>' +
      '<rect x="2" y="4" width="172" height="106" rx="' + rp.toFixed(1) + '" filter="url(#w' + key + ')" opacity=".05"/>' +
      fingers + hazard +
      '<rect x="12" y="18" width="152" height="52" rx="' + (rp * .35).toFixed(1) + '" style="fill:#000;fill-opacity:' + (p.ok ? ".07" : ".16") + '"/>' +
      '<text x="20" y="38" style="font-family:\'Azeret Mono\',monospace;font-weight:600;font-size:11px;letter-spacing:.04em;fill:' + ink + '">' + esc(p.id) + "</text>" +
      '<text x="20" y="56" style="font-family:\'Azeret Mono\',monospace;font-weight:500;font-size:8.5px;letter-spacing:.12em;fill:' + inkF + '">' + esc(p.tier) + " &middot; S/" + (p.sessions || 0) + "</text>" +
      glyphs +
      "<g>" + scratches + "</g>" +
      '<rect x="2" y="4" width="172" height="106" rx="' + rp.toFixed(1) + '" fill="url(#g' + key + ')"/>' +
      '<rect x="2" y="4" width="172" height="106" rx="' + rp.toFixed(1) + '" style="fill:none;stroke:var(--seam);stroke-opacity:' + (p.ok ? ".9" : ".35") + ';stroke-width:1"/>' +
      "</svg>";
  }

  /* ── the deck ─────────────────────────────────────────── */
  function makeDeck(stage, options) {
    var opts = options || {};
    var deck = stage.querySelector(".deck");
    var inner = stage.querySelector(".deck-inner");
    var cart = stage.querySelector(".cart");
    var mesh = stage.querySelector(".shadowmesh");
    var key = "d" + (uid++);
    var party = opts.party || { id: "—", tier: "—", sessions: 0, ok: true, marks: [] };
    var busy = false;
    var timers = [];

    function q(cls) { return stage.querySelector("." + cls); }
    function at(ms, fn) { timers.push(setTimeout(fn, ms)); }
    function clearAll() { timers.forEach(clearTimeout); timers = []; }

    function radii() {
      var w = deck.getBoundingClientRect().width || 720;
      var scale = VB_W / w;
      return {
        obj: 0.022 * global.innerWidth * scale,
        panel: 0.008 * global.innerWidth * scale,
        width: w
      };
    }

    function buildDeck() {
      var R = radii();
      var ro = Math.max(6, Math.min(64, R.obj));
      var rp = Math.max(3, Math.min(30, R.panel));

      var defs =
        "<defs>" +
        '<linearGradient id="chassis' + key + '" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0" style="stop-color:var(--shell)"/>' +
        '<stop offset=".62" style="stop-color:var(--shell)"/>' +
        '<stop offset="1" style="stop-color:var(--shell-shade)"/></linearGradient>' +
        '<pattern id="brush' + key + '" width="3" height="3" patternUnits="userSpaceOnUse">' +
        '<line x1="0" y1="0" x2="0" y2="3" style="stroke:var(--seam);stroke-width:1;opacity:.06"/></pattern>' +
        '<filter id="cast' + key + '" x="0" y="0" width="100%" height="100%">' +
        '<feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" seed="4" result="n"/>' +
        '<feColorMatrix type="saturate" values="0"/></filter>' +
        '<linearGradient id="face' + key + '" x1="0" y1="0" x2=".3" y2="1">' +
        '<stop offset="0" style="stop-color:var(--graphite);stop-opacity:.92"/>' +
        '<stop offset="1" style="stop-color:var(--graphite)"/></linearGradient>' +
        '<linearGradient id="spec' + key + '" x1="0" y1="0" x2=".8" y2="1">' +
        '<stop offset="0" stop-color="#ffffff" stop-opacity=".55"/>' +
        '<stop offset=".38" stop-color="#ffffff" stop-opacity=".06"/>' +
        '<stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>' +
        '<linearGradient id="slot' + key + '" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0" style="stop-color:#000000;stop-opacity:.55"/>' +
        '<stop offset="1" style="stop-color:#000000;stop-opacity:.18"/></linearGradient>' +
        "</defs>";

      /* L1 — base plate */
      var base = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<rect x="8" y="34" width="704" height="376" rx="' + (ro * 1.06).toFixed(1) + '" style="fill:var(--shell-shade)"/>' +
        '<rect x="8" y="34" width="704" height="376" rx="' + (ro * 1.06).toFixed(1) + '" style="fill:none;stroke:var(--seam);stroke-width:1;opacity:.6"/>' +
        "</svg>";

      /* L2 — chassis, anodised brushed metal */
      var chassis = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<rect x="20" y="14" width="680" height="384" rx="' + ro.toFixed(1) + '" fill="url(#chassis' + key + ')"/>' +
        '<rect x="20" y="14" width="680" height="384" rx="' + ro.toFixed(1) + '" fill="url(#brush' + key + ')"/>' +
        '<rect x="20" y="14" width="680" height="384" rx="' + ro.toFixed(1) + '" style="fill:none;stroke:var(--seam);stroke-width:1"/>' +
        '<rect x="30" y="24" width="660" height="364" rx="' + (ro * .92).toFixed(1) + '" style="fill:none;stroke:#ffffff;stroke-opacity:.5;stroke-width:1"/>' +
        '<line x1="20" y1="286" x2="700" y2="286" style="stroke:var(--seam);stroke-width:1;opacity:.55"/>' +
        '<line x1="20" y1="287.2" x2="700" y2="287.2" style="stroke:#ffffff;stroke-opacity:.55;stroke-width:1"/>' +
        '<rect x="86" y="392" width="58" height="16" rx="6" style="fill:var(--shell-shade)"/>' +
        '<rect x="576" y="392" width="58" height="16" rx="6" style="fill:var(--shell-shade)"/>' +
        "</svg>";

      /* L3 — faceplate, cast plastic */
      var face = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<rect x="52" y="42" width="616" height="222" rx="' + rp.toFixed(1) + '" fill="url(#face' + key + ')"/>' +
        '<rect x="52" y="42" width="616" height="222" rx="' + rp.toFixed(1) + '" filter="url(#cast' + key + ')" opacity=".04"/>' +
        '<rect x="52" y="42" width="616" height="222" rx="' + rp.toFixed(1) + '" style="fill:none;stroke:#000;stroke-opacity:.35;stroke-width:1"/>' +
        '<rect x="53.5" y="43.5" width="613" height="219" rx="' + (rp * .95).toFixed(1) + '" style="fill:none;stroke:#fff;stroke-opacity:.07;stroke-width:1"/>' +
        "</svg>";

      /* L4 — slot bezel */
      var slot = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<rect x="' + SLOT.x + '" y="' + SLOT.y + '" width="' + SLOT.w + '" height="' + SLOT.h + '" rx="' + (rp * .5).toFixed(1) + '" style="fill:var(--shell-shade)"/>' +
        '<rect x="' + (SLOT.x + 7) + '" y="' + (SLOT.y + 7) + '" width="' + (SLOT.w - 14) + '" height="' + (SLOT.h - 14) + '" rx="' + (rp * .32).toFixed(1) + '" fill="url(#slot' + key + ')"/>' +
        '<rect x="' + (SLOT.x + 7) + '" y="' + (SLOT.y + 7) + '" width="' + (SLOT.w - 14) + '" height="' + (SLOT.h - 14) + '" rx="' + (rp * .32).toFixed(1) + '" style="fill:none;stroke:#000;stroke-opacity:.5;stroke-width:1"/>' +
        '<rect x="' + (SLOT.x + 7) + '" y="' + (SLOT.y + 8.4) + '" width="' + (SLOT.w - 14) + '" height="' + (SLOT.h - 14) + '" rx="' + (rp * .32).toFixed(1) + '" style="fill:none;stroke:#fff;stroke-opacity:.45;stroke-width:1"/>' +
        "</svg>";

      /* L5 — shutter */
      var shutter = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<g class="shutterG" transform="translate(0,58)">' +
        '<rect x="' + (SLOT.x + 8) + '" y="' + (SLOT.y + 8) + '" width="' + (SLOT.w - 16) + '" height="' + (SLOT.h - 16) + '" rx="' + (rp * .3).toFixed(1) + '" fill="url(#chassis' + key + ')"/>' +
        '<rect x="' + (SLOT.x + 8) + '" y="' + (SLOT.y + 8) + '" width="' + (SLOT.w - 16) + '" height="' + (SLOT.h - 16) + '" rx="' + (rp * .3).toFixed(1) + '" fill="url(#brush' + key + ')"/>' +
        '<rect x="' + (SLOT.x + 8) + '" y="' + (SLOT.y + 8) + '" width="' + (SLOT.w - 16) + '" height="' + (SLOT.h - 16) + '" rx="' + (rp * .3).toFixed(1) + '" style="fill:none;stroke:var(--seam);stroke-width:1"/>' +
        '<g style="stroke:var(--seam);stroke-width:1;opacity:.45">' +
        '<line x1="' + (SLOT.x + 150) + '" y1="' + (SLOT.y + 20) + '" x2="' + (SLOT.x + 178) + '" y2="' + (SLOT.y + 20) + '"/>' +
        '<line x1="' + (SLOT.x + 150) + '" y1="' + (SLOT.y + 26) + '" x2="' + (SLOT.x + 178) + '" y2="' + (SLOT.y + 26) + '"/>' +
        '<line x1="' + (SLOT.x + 150) + '" y1="' + (SLOT.y + 32) + '" x2="' + (SLOT.x + 178) + '" y2="' + (SLOT.y + 32) + '"/>' +
        "</g></g></svg>";

      /* L6 — silkscreen legends, set into the object */
      var legend = '<svg viewBox="0 0 720 420" aria-hidden="true">' +
        '<text x="80" y="76" style="' + LG + ';font-size:11px;fill:#f5f2e9;fill-opacity:.5">ADMISSIBILITY GATE</text>' +
        '<line x1="80" y1="88" x2="640" y2="88" style="stroke:#f5f2e9;stroke-opacity:.14;stroke-width:1"/>' +
        '<text x="80" y="126" style="' + LG + ';font-size:10px;fill:#f5f2e9;fill-opacity:.38">SUBJECT</text>' +
        '<text class="lg-subject" x="80" y="150" style="' + LG + ';font-size:17px;font-weight:600;fill:#f5f2e9;fill-opacity:.92">' + esc(party.id) + "</text>" +
        '<text x="80" y="186" style="' + LG + ';font-size:10px;fill:#f5f2e9;fill-opacity:.38">TERMS</text>' +
        '<text class="lg-terms" x="80" y="210" style="' + LG + ';font-size:15px;fill:var(--amber-key);fill-opacity:.95">AWAITING CARTRIDGE</text>' +
        '<text x="80" y="240" style="' + LG + ';font-size:10px;fill:#f5f2e9;fill-opacity:.3">RE-DERIVED FROM PROVENANCE &middot; NEVER FROM ASSERTION</text>' +
        '<g class="lg-trace" transform="translate(452,110)" opacity="0">' +
        '<rect x="-8" y="-18" width="180" height="126" rx="4" style="fill:#ffffff;fill-opacity:.04"/>' +
        '<text x="0" y="-4" style="' + LG + ';font-size:9px;fill:#f5f2e9;fill-opacity:.4">MEMORY READ</text>' +
        '<path class="lg-path" d="" style="fill:none;stroke:var(--anodize);stroke-width:2;stroke-linejoin:round"/>' +
        "</g>" +
        /* moulded-in denial: present from the factory, revealed on refusal */
        '<g class="lg-denied" opacity="0">' +
        '<rect x="422" y="96" width="212" height="112" rx="6" style="fill:none;stroke:var(--safety);stroke-width:2;stroke-opacity:.75"/>' +
        '<text x="528" y="146" text-anchor="middle" style="font-family:\'Panchang\',sans-serif;font-weight:700;font-size:38px;letter-spacing:.02em;fill:var(--safety)">DENIED</text>' +
        '<text class="lg-clause1" x="528" y="170" text-anchor="middle" style="' + LG + ';font-size:9px;fill:var(--safety);fill-opacity:.9"></text>' +
        '<text class="lg-clause2" x="528" y="186" text-anchor="middle" style="' + LG + ';font-size:8px;fill:var(--safety);fill-opacity:.7"></text>' +
        "</g>" +
        '<text x="60" y="332" style="' + LG + ';font-size:10px;fill:var(--ink-faint)">SLOT A</text>' +
        '<text x="60" y="352" style="' + LG + ';font-size:9px;fill:var(--ink-faint);letter-spacing:.06em">INSERT COUNTERPARTY</text>' +
        '<text x="556" y="332" style="' + LG + ';font-size:10px;fill:var(--ink-faint)">STATUS</text>' +
        '<text class="lg-chain" x="556" y="384" style="' + LG + ';font-size:9px;fill:var(--ink-faint)">AD&middot;1 / BASE</text>' +
        "</svg>";

      /* L7 — LED and eject */
      var led = '<svg viewBox="0 0 720 420" aria-hidden="true">' +
        '<rect class="ledPill" x="556" y="342" width="46" height="14" rx="7" style="fill:var(--amber-key)"/>' +
        '<circle class="ledGlow" cx="579" cy="349" r="16" style="fill:var(--amber-key);opacity:.22"/>' +
        '<rect x="616" y="340" width="44" height="18" rx="9" style="fill:var(--shell-shade);stroke:var(--seam);stroke-width:1"/>' +
        '<text x="638" y="353" text-anchor="middle" style="font-family:\'Azeret Mono\',monospace;font-size:8px;letter-spacing:.1em;fill:var(--ink-faint)">EJECT</text>' +
        "</svg>";

      /* L8 — specular sheet */
      var spec = '<svg viewBox="0 0 720 420" aria-hidden="true">' + defs +
        '<path d="M20 ' + (14 + ro) + " Q20 14 " + (20 + ro) + " 14 L470 14 L150 398 L" + (20 + ro) + " 398 Q20 398 20 " + (398 - ro) +
        ' Z" fill="url(#spec' + key + ')"/>' +
        "</svg>";

      inner.innerHTML =
        '<div class="layer" style="--z:-30px">' + base + "</div>" +
        '<div class="layer" style="--z:0px">' + chassis + "</div>" +
        '<div class="layer" style="--z:16px">' + face + "</div>" +
        '<div class="layer" style="--z:22px">' + slot + "</div>" +
        '<div class="layer shutterLayer" style="--z:26px">' + shutter + "</div>" +
        '<div class="layer" style="--z:30px">' + legend + "</div>" +
        '<div class="layer" style="--z:34px">' + led + "</div>" +
        '<div class="layer l-spec" style="--z:56px">' + spec + "</div>";
    }

    function paintCart() {
      cart.innerHTML = cartridgeSVG(party, true, deck.getBoundingClientRect().width);
    }

    function mount() { buildDeck(); paintCart(); applyChain(); }

    var chainLabel = opts.chain || "";
    function applyChain() {
      var el = q("lg-chain");
      if (el) el.textContent = ("AD·1 / " + (chainLabel || "BASE")).toUpperCase();
    }

    /* ── spring: stiffness 260 / damping 22 ─────────────── */
    function spring(from, to, k, d, onUpdate, onDone) {
      var x = from, v = 0, dt = 1 / 60, raf;
      function step() {
        for (var i = 0; i < 2; i++) {
          var a = -k * (x - to) - d * v;
          v += a * dt; x += v * dt;
        }
        onUpdate(x);
        if (Math.abs(x - to) < 0.1 && Math.abs(v) < 0.6) { onUpdate(to); if (onDone) onDone(); return; }
        raf = requestAnimationFrame(step);
      }
      step();
      return function () { cancelAnimationFrame(raf); };
    }

    function setCart(dx, dy, rot, sc) {
      cart.style.transform = "translate(" + dx + "px," + dy + "px) rotate(" + (rot || 0) + "deg) scale(" + (sc || 1) + ")";
    }

    function shutterTo(v, ms, steps) {
      var layer = stage.querySelector(".shutterLayer");
      if (!layer) return;
      var g = layer.querySelector(".shutterG");
      g.style.transition = reduced() ? "none" :
        "transform " + ms + "ms " + (steps ? "steps(" + steps + ", end)" : "cubic-bezier(.2,1.1,.35,1)");
      g.style.transform = "translate(0px," + v + "px)";
    }

    function silkscreen(el, text, colour) {
      if (!el) return;
      el.style.fill = colour;
      if (reduced()) { el.textContent = text; return; }
      var i = 0;
      (function step() {
        i++;
        el.textContent = text.slice(0, i);
        if (i < text.length) timers.push(setTimeout(step, 35));
      })();
    }

    function drawTrace() {
      var tr = q("lg-trace"), path = q("lg-path");
      if (!tr || !path) return;
      tr.setAttribute("opacity", 1);
      var marks = (party.marks || []).slice(0, 13);
      if (!marks.length) { tr.setAttribute("opacity", 0); return; }
      var d = marks.map(function (o, i) {
        return (i ? "L" : "M") + (i * 14) + " " + (78 - o * 24);
      }).join(" ");
      path.setAttribute("d", d);
      var L = path.getTotalLength ? path.getTotalLength() : 0;
      if (!L || reduced()) { path.style.strokeDasharray = ""; path.style.strokeDashoffset = 0; return; }
      path.style.strokeDasharray = L; path.style.strokeDashoffset = L;
      path.style.transition = "stroke-dashoffset 900ms cubic-bezier(.2,1,.3,1)";
      requestAnimationFrame(function () { path.style.strokeDashoffset = 0; });
    }

    function travel() {
      var r = deck.getBoundingClientRect();
      var sx = (SLOT.x + SLOT.w / 2) / VB_W * r.width;
      var sy = (SLOT.y + SLOT.h / 2) / VB_H * r.height;
      var c = cart.getBoundingClientRect();
      return { dx: sx - (c.left - r.left + c.width / 2), dy: sy - (c.top - r.top + c.height / 2) };
    }

    function status(text) {
      if (opts.onStatus) opts.onStatus(text);
    }

    function reset() {
      clearAll();
      busy = false;
      last = null;
      cart.style.transition = "none";
      setCart(0, 0, 0, 1);
      cart.style.opacity = 1;
      var layer = stage.querySelector(".shutterLayer");
      if (layer) {
        var g = layer.querySelector(".shutterG");
        g.style.transition = "none";
        g.style.transform = "translate(0px,58px)";
      }
      var denied = q("lg-denied"); if (denied) denied.setAttribute("opacity", 0);
      var tr = q("lg-trace"); if (tr) tr.setAttribute("opacity", 0);
      var terms = q("lg-terms");
      if (terms) { terms.textContent = "AWAITING CARTRIDGE"; terms.style.fill = "var(--amber-key)"; }
      var subject = q("lg-subject"); if (subject) subject.textContent = party.id;
      var pill = q("ledPill"), glow = q("ledGlow");
      if (pill) pill.style.fill = "var(--amber-key)";
      if (glow) glow.style.fill = "var(--amber-key)";
      status("SLOT A — IDLE");
    }

    var pending = null;

    function accept(outcome) {
      cart.style.opacity = 0;
      shutterTo(0, reduced() ? 1 : 320, 0);
      at(reduced() ? 1 : 340, function () {
        silkscreen(q("lg-terms"), outcome.terms || "TERMS WRITTEN", outcome.action === "escrow" ? "var(--amber-key)" : "var(--anodize)");
        drawTrace();
        var pill = q("ledPill"), glow = q("ledGlow");
        var colour = outcome.action === "escrow" ? "var(--amber-key)" : "var(--anodize)";
        if (pill) pill.style.fill = colour;
        if (glow) glow.style.fill = colour;
        status("SLOT A — " + (outcome.action === "escrow" ? "HELD" : "ADMITTED"));
        if (opts.onSettled) opts.onSettled(outcome);
      });
      at(1600, function () { busy = false; });
    }

    function refuse(outcome) {
      /* mechanisms do not ease */
      shutterTo(0, reduced() ? 1 : 90, reduced() ? 0 : 3);
      at(reduced() ? 1 : 95, function () {
        var pill = q("ledPill"), glow = q("ledGlow");
        if (pill) pill.style.fill = "var(--safety)";
        if (glow) glow.style.fill = "var(--safety)";
        var terms = q("lg-terms");
        if (terms) { terms.textContent = outcome.terms || "NO TRANSFER"; terms.style.fill = "var(--safety)"; }
        var c1 = q("lg-clause1"), c2 = q("lg-clause2");
        if (c1) c1.textContent = (outcome.clause || "CANNOT RE-DERIVE").toUpperCase();
        if (c2) c2.textContent = (outcome.clauseDetail || "").toUpperCase();
        var denied = q("lg-denied"); if (denied) denied.setAttribute("opacity", 1);
        status("SLOT A — REFUSED");
        if (opts.onSettled) opts.onSettled(outcome);
      });
      /* the cartridge comes back out on a real spring-back arc */
      at(reduced() ? 2 : 150, function () {
        if (reduced()) { setCart(0, 0, 0, 1); busy = false; return; }
        var t = travel();
        var t0 = performance.now(), dur = 620;
        (function arc(now) {
          var k = Math.min(1, (now - t0) / dur);
          var e = 1 - Math.pow(1 - k, 3);
          setCart(t.dx * (1 - e), t.dy * (1 - e) - Math.sin(k * Math.PI) * 46,
            -14 * Math.sin(k * Math.PI) + (1 - e) * -2, 0.94 + 0.06 * e);
          if (k < 1) requestAnimationFrame(arc);
          else setCart(0, 0, 0, 1);
        })(t0);
      });
      at(900, function () { busy = false; });
    }

    var last = null;

    function settle(outcome) {
      last = outcome;
      if (outcome.ok) accept(outcome); else refuse(outcome);
    }

    /* Put the object straight into a settled state, with no choreography.
       Used after a remount -- a window resize must not quietly un-refuse a
       counterparty that was refused. */
    function restore(outcome) {
      if (!outcome) return;
      last = outcome;
      var layer = stage.querySelector(".shutterLayer");
      if (layer) {
        var g = layer.querySelector(".shutterG");
        g.style.transition = "none";
        g.style.transform = "translate(0px,0px)";
      }
      var pill = q("ledPill"), glow = q("ledGlow");
      var colour = outcome.ok
        ? (outcome.action === "escrow" ? "var(--amber-key)" : "var(--anodize)")
        : "var(--safety)";
      if (pill) pill.style.fill = colour;
      if (glow) glow.style.fill = colour;
      var terms = q("lg-terms");
      if (terms) { terms.textContent = outcome.terms || ""; terms.style.fill = colour; }
      if (outcome.ok) {
        cart.style.opacity = 0;
        drawTrace();
        status("SLOT A — " + (outcome.action === "escrow" ? "HELD" : "ADMITTED"));
      } else {
        var c1 = q("lg-clause1"), c2 = q("lg-clause2");
        if (c1) c1.textContent = (outcome.clause || "CANNOT RE-DERIVE").toUpperCase();
        if (c2) c2.textContent = (outcome.clauseDetail || "").toUpperCase();
        var denied = q("lg-denied"); if (denied) denied.setAttribute("opacity", 1);
        status("SLOT A — REFUSED");
      }
    }

    /* Slot the cartridge, then play whatever verdict arrives. If the verdict is
       not in yet the deck holds at READING -- it never guesses an outcome. */
    function run(outcome) {
      if (busy) { pending = outcome || pending; return; }
      busy = true;
      clearAll();
      reset();
      busy = true;
      pending = outcome || null;
      status("SLOT A — READING");
      var t = travel();
      cart.style.transition = "none";
      if (reduced()) {
        setCart(t.dx, t.dy, 0, 0.94);
        if (pending) settle(pending);
        return;
      }
      var cancel = spring(0, 1, 260, 22, function (x) {
        setCart(t.dx * x, t.dy * x, (1 - x) * -2, 1 - 0.06 * x);
      }, function () {
        if (pending) settle(pending);
      });
      timers.push(setTimeout(cancel, 1400));
    }

    function resolve(outcome) {
      pending = outcome;
      if (!busy) { run(outcome); return; }
      /* the travel is already under way; hand it the verdict for the landing */
      var t = travel();
      var c = cart.getBoundingClientRect(), r = deck.getBoundingClientRect();
      var reachedSlot = Math.abs((c.left - r.left + c.width / 2) - (r.width * (SLOT.x + SLOT.w / 2) / VB_W)) < 24;
      if (reachedSlot) settle(outcome);
    }

    function subject(next) {
      party = next;
      paintCart();
      var el = q("lg-subject");
      if (el) el.textContent = party.id;
    }

    function chain(label) { chainLabel = label; applyChain(); }

    /* ── parallax: the object sits in a real scene ──────── */
    if (!reduced()) {
      stage.addEventListener("pointermove", function (e) {
        var r = stage.getBoundingClientRect();
        var nx = (e.clientX - r.left) / r.width - .5;
        var ny = (e.clientY - r.top) / r.height - .5;
        inner.style.transition = "transform 120ms linear";
        inner.style.transform = "rotateX(" + (-ny * 7).toFixed(2) + "deg) rotateY(" + (nx * 10).toFixed(2) + "deg)";
        if (mesh) mesh.style.transform = "translate(" + (nx * -16).toFixed(1) + "px," + (ny * -6).toFixed(1) + "px)";
      });
      stage.addEventListener("pointerleave", function () {
        inner.style.transition = "transform 620ms cubic-bezier(.2,1.1,.35,1)";
        inner.style.transform = "rotateX(0deg) rotateY(0deg)";
        if (mesh) mesh.style.transform = "none";
      });
    }

    /* ── drag the cartridge ─────────────────────────────── */
    var drag = null;
    cart.addEventListener("pointerdown", function (e) {
      if (busy) return;
      reset();
      drag = { x: e.clientX, y: e.clientY };
      cart.setPointerCapture(e.pointerId);
      cart.classList.add("dragging");
      cart.style.transition = "none";
    });
    cart.addEventListener("pointermove", function (e) {
      if (!drag) return;
      setCart(e.clientX - drag.x, e.clientY - drag.y, (e.clientX - drag.x) * 0.02, 1);
    });
    cart.addEventListener("pointerup", function (e) {
      if (!drag) return;
      var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      drag = null;
      cart.classList.remove("dragging");
      var t = travel();
      if (Math.abs(dx - t.dx) < 110 && Math.abs(dy - t.dy) < 90) {
        setCart(t.dx, t.dy, 0, 0.94);
        busy = true;
        if (opts.onSlot) opts.onSlot();
        if (pending) settle(pending);
      } else {
        cart.style.transition = "transform 420ms cubic-bezier(.2,1.1,.35,1)";
        setCart(0, 0, 0, 1);
      }
    });

    var rz, lastWidth = deck.getBoundingClientRect().width;
    global.addEventListener("resize", function () {
      clearTimeout(rz);
      rz = setTimeout(function () {
        var width = deck.getBoundingClientRect().width;
        if (Math.abs(width - lastWidth) < 2) return;   /* a mobile URL bar is not a resize */
        lastWidth = width;
        var keep = last;
        mount(); reset();
        restore(keep);
      }, 160);
    });

    mount();
    reset();

    return {
      mount: mount, reset: reset, run: run, resolve: resolve, restore: restore,
      subject: subject, chain: chain, settle: settle,
      get party() { return party; },
      get outcome() { return last; }
    };
  }

  /* ── theme: the room darkens, not the object ──────────── */
  function wireTheme(button) {
    if (!button) return;
    var root = document.documentElement;
    var stored = null;
    try { stored = localStorage.getItem("admissible-theme"); } catch (e) { stored = null; }
    if (stored === "dark" || stored === "light") root.setAttribute("data-theme", stored);
    function label() {
      button.textContent = root.getAttribute("data-theme") === "dark" ? "Daylight" : "Desk lamp";
    }
    label();
    button.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") === "dark";
      root.setAttribute("data-theme", dark ? "light" : "dark");
      try { localStorage.setItem("admissible-theme", dark ? "light" : "dark"); } catch (e) { /* private mode */ }
      label();
    });
  }

  global.SoftMachine = {
    cartridgeSVG: cartridgeSVG,
    makeDeck: makeDeck,
    wireTheme: wireTheme,
    reduced: reduced,
    escape: esc
  };
})(window);
