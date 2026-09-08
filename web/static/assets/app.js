/* THE RECORD.

   Where enforcement becomes visible. Nothing here decides anything: the gate
   and the trust policy run on the server, and this file draws what they said.
   Refused memories are rendered exactly as loudly as admitted ones, because a
   refusal you cannot see is an attack you cannot see. */
(function () {
  "use strict";
  var SM = window.SoftMachine;
  var esc = SM.escape;
  var $ = function (id) { return document.getElementById(id); };

  SM.wireTheme($("theme"));

  var state = {
    chain: null,
    counterparties: [],
    current: null,
    ask: 1.0,
    asOf: null,          /* null means now */
    span: null,          /* {min, max} epoch ms for the scrubber */
    ticks: [],
    trace: [],
    source: null,
    graph: null
  };

  /* ── plumbing ─────────────────────────────────────────────────────── */
  function get(url) {
    return fetch(url, { headers: { accept: "application/json" } }).then(function (r) {
      if (!r.ok) throw new Error(url + " " + r.status);
      return r.json();
    });
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (!r.ok) throw new Error(url + " " + r.status);
      return r.json();
    });
  }
  function money(v) { return "$" + (Number(v) || 0).toFixed(2); }
  function ms(iso) { var t = Date.parse(iso); return isNaN(t) ? null : t; }
  function stamp(iso) {
    var t = ms(iso);
    if (t === null) return String(iso || "—");
    var d = new Date(t);
    return d.toISOString().slice(0, 16).replace("T", " ") + "Z";
  }
  function ago(iso) {
    var t = ms(iso);
    if (t === null) return "";
    var s = (Date.now() - t) / 1000;
    if (s < 90) return Math.max(0, Math.round(s)) + "s ago";
    if (s < 5400) return Math.round(s / 60) + "m ago";
    if (s < 172800) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }
  function short(addr) {
    if (!addr) return "—";
    return addr.length > 12 ? addr.slice(0, 6) + "…" + addr.slice(-4) : addr;
  }
  function code(text) { return String(text || "").replace(/_/g, " "); }

  /* ── the deck ─────────────────────────────────────────────────────── */
  var deck = SM.makeDeck($("stage"), {
    party: { id: "—", tier: "—", sessions: 0, ok: true, marks: [] },
    onStatus: function (text) { $("deckStatus").textContent = text; },
    onSlot: function () { runStream(); }
  });

  function partyOf(cp) {
    return {
      id: short(cp.address),
      label: cp.handle || cp.address,
      tier: cp.standing,
      sessions: cp.sessions,
      marks: cp.marks,
      ok: cp.action !== "refuse"
    };
  }

  function outcomeOf(payload) {
    var d = payload.decision;
    var lead = null;
    (payload.trace || []).forEach(function (m) { if (!lead && m.forgery) lead = m; });
    if (!lead) (payload.trace || []).forEach(function (m) { if (!lead && !m.verdict.admits) lead = m; });
    var verdict = (d.blocked_by && d.blocked_by.verdict) || (lead && lead.verdict.code) || "";
    var field = (lead && lead.verdict.fields && lead.verdict.fields[0]) || "";
    var terms = d.action === "pay" ? "PAY " + d.unsecured_usd.toFixed(2) + " USDC"
      : d.action === "escrow" ? "HOLD " + d.collateral_usd.toFixed(2) + " USDC"
        : "NO TRANSFER";
    return {
      ok: d.action !== "refuse", action: d.action, terms: terms,
      clause: code(verdict), clauseDetail: field
    };
  }

  /* ── the rack ─────────────────────────────────────────────────────── */
  function renderRack() {
    var host = $("rack");
    host.innerHTML = state.counterparties.map(function (cp, i) {
      var party = partyOf(cp);
      var flagged = cp.flagged ? " · FLAGGED" : "";
      return '<button class="slotcard" type="button" data-i="' + i + '" aria-pressed="' +
        (state.current && state.current.address === cp.address) + '">' +
        '<div class="thumb">' + SM.cartridgeSVG(party, false, 260) + "</div>" +
        '<div class="nm">' + esc(cp.handle || short(cp.address)) + " &middot; " + esc(cp.standing) + esc(flagged) + "</div>" +
        '<div class="dsc">' + esc(describe(cp)) + "</div></button>";
    }).join("");
    Array.prototype.forEach.call(host.querySelectorAll(".slotcard"), function (button) {
      button.addEventListener("click", function () {
        select(state.counterparties[Number(button.dataset.i)]);
      });
    });
  }

  function describe(cp) {
    var tiers = cp.tiers || {};
    var parts = [];
    ["ATTESTED", "WITNESSED", "HEARSAY", "MALFORMED"].forEach(function (t) {
      if (tiers[t]) parts.push(tiers[t] + " " + t.toLowerCase());
    });
    var lead = parts.join(", ");
    if (cp.laundering) {
      return lead + ". " + cp.laundering + " memor" + (cp.laundering === 1 ? "y" : "ies") +
        " cite evidence that does not hold up.";
    }
    if (cp.credit_usd > 0) {
      return lead + ". " + money(cp.credit_usd) + " of re-derivable history.";
    }
    return lead + ". Nothing re-derivable to draw on.";
  }

  /* ── the decision panel ───────────────────────────────────────────── */
  function renderDecision(payload) {
    var d = payload.decision;
    $("verdictLine").setAttribute("data-action", d.action);
    $("actionText").textContent = d.action.toUpperCase();
    $("counterpartyLabel").textContent =
      (state.current ? (state.current.handle || "") + " " : "") + short(d.counterparty) +
      " · asked " + money(d.requested_usd);
    $("decisionWhen").textContent = payload.as_of ? "replayed at " + stamp(payload.as_of) : "now";

    $("money").innerHTML = [
      ['<span class="leg">Credit line</span><b>' + money(d.credit_usd) + "</b>"],
      ['<span class="leg">Unsecured</span><b>' + money(d.unsecured_usd) + "</b>"],
      ['<span class="leg">Held as collateral</span><b>' + money(d.collateral_usd) + "</b>"],
      ['<span class="leg">Memories weighed</span><b>' + d.considered.length +
        (payload.trace.length !== d.considered.length
          ? ' <span class="muted" style="font-size:14px">of ' + payload.trace.length + "</span>" : "") +
        "</b>"]
    ].map(function (row) { return "<div>" + row[0] + "</div>"; }).join("");

    var split = $("split");
    var total = Math.max(d.requested_usd, d.unsecured_usd + d.collateral_usd);
    if (total > 0 && d.action !== "refuse") {
      split.hidden = false;
      split.querySelector(".unsec").style.width = (100 * d.unsecured_usd / total) + "%";
      split.querySelector(".coll").style.width = (100 * d.collateral_usd / total) + "%";
    } else {
      split.hidden = true;
    }

    $("explain").textContent = d.explain;

    $("blocked").innerHTML = d.blocked_by
      ? '<div class="blocked"><b>Blocked by &middot; ' + esc(code(d.blocked_by.kind || "")) + "</b>" +
        esc(blockedText(d.blocked_by)) + "</div>"
      : "";

    $("cites").innerHTML = d.citations.length
      ? '<span class="leg">Cited by digest</span>' + d.citations.map(function (c) {
        return '<span class="cite">' + esc(c.slice(0, 14)) + "…</span>";
      }).join("")
      : '<span class="leg">No memory carried weight in this decision</span>';

    var gaps = payload.unreconstructible || [];
    $("gaps").innerHTML = gaps.length
      ? '<div class="blocked" style="border-color:var(--amber-key);color:var(--ink);background:none">' +
        '<b style="color:var(--amber-key)">Gaps in the replay</b>' +
        gaps.map(function (g) {
          return esc(g.name) + ": " + g.records.length + " earlier version" +
            (g.records.length === 1 ? "" : "s") + " proven to have existed by the journal, body no longer held.";
        }).join("<br>") + "</div>"
      : "";
  }

  function blockedText(blocked) {
    if (blocked.kind === "laundering_attempt") {
      return "verdict " + code(blocked.verdict) + " on " + (blocked.digest || "").slice(0, 12) +
        "…, asserted by " + short(blocked.actor) +
        ". Collateral protects against failure, not against fraud, so this refuses outright.";
    }
    if (blocked.reason) return blocked.reason;
    if (blocked.actor_address || blocked.actor_handle) {
      return (blocked.actor_handle || short(blocked.actor_address)) + " — " + (blocked.reason || blocked.flag || "");
    }
    return JSON.stringify(blocked);
  }

  function renderDossier(cp) {
    var host = $("dossier");
    if (!cp || !cp.dossier) { host.textContent = "No consolidated dossier for this counterparty."; return; }
    var claim = cp.dossier;
    $("dossierTier").textContent = "folded as " + (cp.dossier_tier || "—");
    var tiers = Object.keys(claim.tiers || {}).map(function (k) {
      return k.toLowerCase() + " " + claim.tiers[k];
    }).join(" · ");
    var totals = Object.keys(claim.totals || {}).map(function (k) {
      return claim.totals[k] + " " + k;
    }).join(", ");
    var attested = Object.keys(claim.attested_totals || {}).map(function (k) {
      return claim.attested_totals[k] + " " + k;
    }).join(", ");
    host.innerHTML =
      '<dl style="display:grid;grid-template-columns:minmax(110px,auto) 1fr;gap:4px var(--s2);margin:0">' +
      row("Interactions", claim.interactions + " · " + claim.journal_events + " journal events") +
      row("Tiers", tiers || "—") +
      row("Totals", totals || "—") +
      row("Attested subtotal", attested || "none") +
      row("First seen", claim.first_seen ? stamp(claim.first_seen) : "—") +
      row("Last seen", claim.last_seen ? stamp(claim.last_seen) : "—") +
      "</dl>" +
      '<p class="note" style="margin-top:var(--s2)"><b style="color:var(--ink)">Claimed against ' +
      "re-derived.</b> This file asserts " + esc(totals || "nothing") + ", of which " +
      esc(attested || "none") + " carries the ATTESTED label. The gate re-derives " +
      esc(money(cp.credit_usd)) + " of it. The label is what the writer chose; the credit is what " +
      "the chain agreed to.</p>" +
      '<p class="note" style="margin-top:var(--s1)">The dossier is a fold, not a summary: counts, ' +
      "sums and histograms, re-derivable by anyone holding the database. Its tier is the weakest " +
      "tier among its inputs, which is why a file with one hearsay note in it folds to hearsay.</p>";
  }
  function row(label, value) {
    return '<dt class="leg" style="padding-top:3px">' + esc(label) + "</dt>" +
      '<dd style="margin:0;font-size:12.5px;color:var(--ink);overflow-wrap:anywhere">' + esc(value) + "</dd>";
  }

  /* ── the memory read trace ────────────────────────────────────────── */
  function verdictBadge(memory) {
    var v = memory.verdict;
    var cls = v.admits ? "admit" : (memory.forgery || v.code === "malformed" ? "hard" : "soft");
    return '<span class="badge ' + cls + '">' + esc(code(v.code)) + "</span>";
  }

  function traceRow(memory, index) {
    var tier = memory.tier || "MALFORMED";
    var counted = memory.counted;
    var admitted = memory.verdict.admits;
    var classes = ["row"];
    if (!admitted) classes.push("refused");
    if (memory.forgery || memory.verdict.code === "malformed") classes.push("forgery");
    else if (counted) classes.push("counted");

    var meta = [
      memory.source || "unparseable body",
      memory.actor_handle || short(memory.actor_address),
      memory.observed_at ? stamp(memory.observed_at) + " (" + ago(memory.observed_at) + ")" : "no readable clock"
    ].filter(Boolean).join(" · ");

    var weight = admitted
      ? (memory.weight_usd > 0 ? money(memory.weight_usd) : "counted once")
      : "$0.00";

    var links = (memory.evidence_links || []).map(function (link) {
      return '<a class="evlink" href="' + esc(link.url) + '" target="_blank" rel="noreferrer">' +
        esc(link.label) +
        (link.recorded
          ? ' <span class="tag fixture" title="recorded fixture: this hash was never mined">fixture</span>'
          : ' <span class="tag">basescan</span>') +
        "</a>";
    }).join("");

    var detail = Object.keys(memory.verdict.detail || {}).map(function (key) {
      var value = memory.verdict.detail[key];
      return row(key, typeof value === "object" ? JSON.stringify(value) : String(value));
    }).join("");

    var notes = (memory.evidence_links || [])
      .filter(function (l) { return l.note; })
      .map(function (l) { return '<p class="note">' + esc(l.note) + "</p>"; }).join("");

    return '<details class="' + classes.join(" ") + '" data-name="' + esc(memory.name) + '">' +
      "<summary>" +
      '<span class="idx">' + (index < 9 ? "0" : "") + (index + 1) + "</span>" +
      '<span class="who"><span class="nm">' + esc(memory.name) + "</span>" +
      '<span class="meta">' + esc(meta) + "</span></span>" +
      '<span class="tags"><span class="badge" data-tier="' + esc(tier) + '">' + esc(tier) + "</span>" +
      verdictBadge(memory) + '<span class="leg">' + esc(weight) + "</span></span>" +
      "</summary>" +
      '<div class="detail">' +
      '<p class="why">' + esc(memory.verdict.explain) + "</p>" +
      (memory.verdict.fields && memory.verdict.fields.length
        ? '<p class="leg">Deciding fields: ' + esc(memory.verdict.fields.join(" · ")) + "</p>" : "") +
      '<dl>' +
      (memory.digest ? row("digest", memory.digest) : row("digest", "none — the claim cannot be canonicalised")) +
      (memory.valid_from ? row("valid from", stamp(memory.valid_from)) : "") +
      (memory.valid_to ? row("valid to", stamp(memory.valid_to)) : "") +
      (memory.supersedes ? row("supersedes", memory.supersedes) : "") +
      (memory.reason ? row("parse error", memory.reason) : "") +
      detail +
      "</dl>" +
      (links ? '<div class="links">' + links + "</div>" : "") +
      notes +
      "<pre>" + esc(JSON.stringify(memory.claim || memory.raw_body || {}, null, 2)) + "</pre>" +
      '<div class="versions" data-loaded="0"><span class="leg">versions &mdash; loading</span></div>' +
      "</div></details>";
  }

  /* Opening a memory asks the timeline endpoint what else the store holds of it.
     A memory with two versions is the bi-temporal story at its smallest: the
     version we believed then is archived, not deleted, and it is still judged by
     the same gate. `toggle` does not bubble, so this listens in the capture
     phase rather than binding a handler per row. */
  $("trace").addEventListener("toggle", function (event) {
    var row = event.target;
    if (!row.open || !row.dataset || !row.dataset.name) return;
    var host = row.querySelector(".versions");
    if (!host || host.dataset.loaded === "1") return;
    host.dataset.loaded = "1";
    get("/api/timeline/interaction/" + encodeURIComponent(row.dataset.name))
      .then(function (data) {
        var rows = data.versions.map(function (version) {
          return '<div style="display:flex;gap:var(--s2);flex-wrap:wrap;align-items:baseline;' +
            'border-top:1px solid var(--seam);padding:6px 0">' +
            '<span class="leg" style="min-width:58px">' + esc(version.origin) + "</span>" +
            '<span class="mono">' + esc(stamp(version.recorded_at)) + "</span>" +
            '<span style="font-size:12px;color:var(--ink)">' +
            esc(JSON.stringify(version.claim.outcome || version.claim.note || version.digest.slice(0, 12))) +
            "</span>" +
            '<span class="sp" style="flex:1"></span>' +
            '<span class="badge ' + (version.verdict.admits ? "admit" : "soft") + '">' +
            esc(code(version.verdict.code)) + "</span></div>";
        }).join("");
        var lost = (data.unreconstructible || []).length;
        host.innerHTML = '<p class="leg" style="margin:var(--s2) 0 0">' + data.versions.length +
          " version" + (data.versions.length === 1 ? "" : "s") + " recoverable" +
          (lost ? " · " + lost + " proven by the journal, body no longer held" : "") + "</p>" + rows;
      })
      .catch(function () {
        host.innerHTML = '<span class="leg">no version history for this row</span>';
      });
  }, true);

  function renderTrace(memories) {
    state.trace = memories;
    $("trace").innerHTML = memories.map(traceRow).join("");
    countTrace();
  }
  function appendTrace(memory) {
    state.trace.push(memory);
    $("trace").insertAdjacentHTML("beforeend", traceRow(memory, state.trace.length - 1));
    countTrace();
  }
  function countTrace() {
    var admitted = state.trace.filter(function (m) { return m.verdict.admits; }).length;
    $("traceCount").textContent =
      state.trace.length + " recalled · " + admitted + " admissible · " +
      (state.trace.length - admitted) + " refused";
  }

  /* ── the scrubber ─────────────────────────────────────────────────── */
  var scrub = { value: 1000, dragging: false };

  function scrubTime(value) {
    if (!state.span || value >= 1000) return null;
    return new Date(state.span.min + (state.span.max - state.span.min) * (value / 1000)).toISOString();
  }

  function renderScrub() {
    var host = $("scrubTrack");
    var W = 1000, H = 64;
    var x = 24 + (W - 48) * (scrub.value / 1000);
    var ticks = state.ticks.map(function (tick) {
      var tx = 24 + (W - 48) * tick.at;
      var colour = tick.mark === 2 ? "var(--anodize)" : tick.mark === 1 ? "var(--amber-key)" : "var(--safety)";
      return '<rect x="' + (tx - 1) + '" y="14" width="2" height="10" rx="1" style="fill:' + colour + ';opacity:.8"/>';
    }).join("");
    var knurl = "";
    for (var i = 0; i < 5; i++) {
      knurl += '<line x1="' + (x - 6 + i * 3) + '" y1="26" x2="' + (x - 6 + i * 3) +
        '" y2="42" style="stroke:var(--seam);stroke-width:1;opacity:.9"/>';
    }
    host.innerHTML =
      '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" aria-hidden="true">' +
      '<rect x="24" y="30" width="' + (W - 48) + '" height="12" rx="6" style="fill:var(--graphite);opacity:.85"/>' +
      '<rect x="24" y="30" width="' + (W - 48) + '" height="12" rx="6" style="fill:none;stroke:#fff;stroke-opacity:.25;stroke-width:1"/>' +
      '<rect x="24" y="30" width="' + Math.max(0, x - 24) + '" height="12" rx="6" style="fill:var(--anodize);opacity:.55"/>' +
      ticks +
      '<line x1="' + (W - 24) + '" y1="10" x2="' + (W - 24) + '" y2="52" style="stroke:var(--ink-faint);stroke-width:1;stroke-dasharray:2 3"/>' +
      '<text x="' + (W - 28) + '" y="60" text-anchor="end" style="font-family:\'Azeret Mono\',monospace;font-size:9px;fill:var(--ink-faint)">NOW</text>' +
      '<text x="24" y="60" style="font-family:\'Azeret Mono\',monospace;font-size:9px;fill:var(--ink-faint)">OLDEST MEMORY</text>' +
      '<g transform="translate(0,0)">' +
      '<rect x="' + (x - 13) + '" y="18" width="26" height="36" rx="4" style="fill:var(--shell);stroke:var(--seam);stroke-width:1"/>' +
      '<rect x="' + (x - 11) + '" y="20" width="22" height="32" rx="3" style="fill:none;stroke:#fff;stroke-opacity:.6;stroke-width:1"/>' +
      knurl +
      '<rect x="' + (x - 13) + '" y="18" width="26" height="4" rx="2" style="fill:' +
      (scrub.value >= 1000 ? "var(--anodize)" : "var(--amber-key)") + '"/>' +
      "</g></svg>";

    var when = scrubTime(scrub.value);
    host.setAttribute("aria-valuenow", String(Math.round(scrub.value)));
    host.setAttribute("aria-valuetext", when ? "as of " + stamp(when) + ", " + ago(when) : "now");
    $("scrubStamp").textContent = when ? stamp(when) : "now";
    $("scrubMode").textContent = when ? "replaying " + ago(when) : "now";
  }

  function setScrub(value, commit) {
    scrub.value = Math.max(0, Math.min(1000, value));
    renderScrub();
    if (commit) commitScrub();
  }

  var scrubTimer = null;
  function commitScrub() {
    clearTimeout(scrubTimer);
    scrubTimer = setTimeout(function () {
      state.asOf = scrubTime(scrub.value);
      refresh(false);
    }, 140);
  }

  function wireScrub() {
    var track = $("scrubTrack");
    function fromEvent(event) {
      var rect = track.getBoundingClientRect();
      var ratio = (event.clientX - rect.left) / Math.max(1, rect.width);
      /* the rail is inset 24 of 1000 at each end; map the visible rail to 0..1000 */
      var inset = 24 / 1000;
      ratio = (ratio - inset) / (1 - 2 * inset);
      return Math.max(0, Math.min(1, ratio)) * 1000;
    }
    track.addEventListener("pointerdown", function (event) {
      scrub.dragging = true;
      track.setPointerCapture(event.pointerId);
      track.focus();
      setScrub(fromEvent(event), true);
    });
    track.addEventListener("pointermove", function (event) {
      if (!scrub.dragging) return;
      setScrub(fromEvent(event), true);
    });
    track.addEventListener("pointerup", function () { scrub.dragging = false; });
    track.addEventListener("pointercancel", function () { scrub.dragging = false; });
    track.addEventListener("keydown", function (event) {
      if (!state.span) return;
      var span = state.span.max - state.span.min;
      var hour = span ? (3600000 / span) * 1000 : 10;
      var day = hour * 24;
      var next = null;
      if (event.key === "ArrowLeft" || event.key === "ArrowDown") next = scrub.value - hour;
      else if (event.key === "ArrowRight" || event.key === "ArrowUp") next = scrub.value + hour;
      else if (event.key === "PageDown") next = scrub.value - day;
      else if (event.key === "PageUp") next = scrub.value + day;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = 1000;
      if (next === null) return;
      event.preventDefault();
      setScrub(next, true);
    });
    $("scrubNow").addEventListener("click", function () { setScrub(1000, true); });
  }

  /* ── flagged registry ─────────────────────────────────────────────── */
  function renderFlags(data) {
    var flags = data.flags || [];
    $("flagCount").textContent = flags.length + (flags.length === 1 ? " actor" : " actors");
    $("flagNote").textContent = data.note || "";
    $("flags").innerHTML = flags.length ? flags.map(function (flag) {
      var evidence = Object.keys(flag.evidence || {}).map(function (key) {
        var value = flag.evidence[key];
        return '<span class="chip">' + esc(key) + ": " +
          esc(typeof value === "object" ? JSON.stringify(value) : String(value)) + "</span>";
      }).join("");
      var taint = (flag.contaminates || []).map(function (ref) {
        return '<span class="chip taint">' + esc(ref) + "</span>";
      }).join("");
      return '<div class="flagrow">' +
        '<div class="top"><span class="badge" data-tier="FLAGGED">FLAGGED</span>' +
        '<span class="mono" style="color:var(--ink)">' + esc(flag.actor_handle || "") + "</span>" +
        '<span class="mono muted brk">' + esc(flag.actor_address || "") + "</span>" +
        '<span class="sp" style="flex:1"></span>' +
        '<span class="leg">' + esc(stamp(flag.flagged_at)) + "</span></div>" +
        '<p class="reason">' + esc(flag.reason) + "</p>" +
        (evidence ? '<div class="chips">' + evidence + "</div>" : "") +
        (taint ? '<p class="leg" style="margin:var(--s2) 0 0">Reaches ' + (flag.contaminates || []).length +
          " node" + ((flag.contaminates || []).length === 1 ? "" : "s") + "</p><div class=\"chips\">" + taint + "</div>" : "") +
        (flag.revoked_at ? '<p class="leg" style="margin-top:var(--s1)">revoked ' + esc(stamp(flag.revoked_at)) +
          " — " + esc(flag.revoked_reason || "") + "</p>" : "") +
        "</div>";
    }).join("") : '<p class="note">Nothing in the FLAGGED tier.</p>';
  }

  /* ── the vouching graph ───────────────────────────────────────────── */
  /* An authored radial layout rather than a simulation. Actors sit on one ring
     in a fixed order; every memory hangs off the actor that sourced it, on a
     short spoke. It is deterministic -- the same graph draws the same picture
     every time -- and it puts the vouching ring in the middle, which is the
     thing worth looking at. */
  function radialLayout(nodes, edges, W, H) {
    var actors = nodes.filter(function (n) { return n.kind === "actor"; });
    var memories = nodes.filter(function (n) { return n.kind !== "actor"; });
    var cx = W / 2, cy = H / 2;
    var ring = Math.min(W, H) * (memories.length ? 0.27 : 0.34);
    var pos = {};

    actors.forEach(function (node, i) {
      var angle = (i / Math.max(1, actors.length)) * Math.PI * 2 - Math.PI / 2;
      pos[node.id] = {
        x: cx + Math.cos(angle) * ring,
        y: cy + Math.sin(angle) * ring * 0.86,
        angle: angle
      };
    });

    /* group each memory under whichever actor sourced it */
    var owner = {};
    edges.forEach(function (edge) {
      if (edge.type === "sourced" && !owner[edge.target]) owner[edge.target] = edge.source;
    });
    var buckets = {};
    memories.forEach(function (node) {
      var key = owner[node.id] || "unowned";
      (buckets[key] = buckets[key] || []).push(node);
    });

    Object.keys(buckets).forEach(function (key) {
      var anchor = pos[key] || { x: cx, y: cy, angle: -Math.PI / 2 };
      var group = buckets[key];
      var spread = Math.min(Math.PI * 0.72, 0.30 * group.length);
      var reach = Math.min(W, H) * 0.19;
      group.forEach(function (node, i) {
        var offset = group.length === 1 ? 0 : (i / (group.length - 1) - 0.5) * spread;
        var angle = anchor.angle + offset;
        var radius = reach * (0.72 + 0.28 * (i % 2));
        pos[node.id] = {
          x: anchor.x + Math.cos(angle) * radius,
          y: anchor.y + Math.sin(angle) * radius * 0.9
        };
      });
    });

    return nodes.map(function (node) {
      var p = pos[node.id] || { x: cx, y: cy };
      var angle = p.angle;
      return {
        x: Math.max(40, Math.min(W - 40, p.x)),
        y: Math.max(34, Math.min(H - 30, p.y)),
        /* where this node's label goes: straight out from the middle, past the
           fan of memories hanging off it */
        lx: angle === undefined ? p.x : cx + Math.cos(angle) * (ring + Math.min(W, H) * 0.22),
        ly: angle === undefined ? p.y : cy + Math.sin(angle) * (ring * 0.86 + Math.min(W, H) * 0.2)
      };
    });
  }

  function renderGraph(data) {
    state.graph = data;
    var host = $("graph");
    var rect = host.getBoundingClientRect();
    var W = Math.max(320, Math.round(rect.width)) || 900;
    var H = Math.max(240, Math.round(rect.height)) || 560;
    var nodes = data.nodes, edges = data.edges;
    var pos = radialLayout(nodes, edges, W, H);
    var index = {};
    nodes.forEach(function (node, i) { index[node.id] = i; });

    $("graphCount").textContent = nodes.length + " nodes · " + edges.length + " edges";

    var wires = edges.map(function (edge) {
      var a = pos[index[edge.source]], b = pos[index[edge.target]];
      if (!a || !b) return "";
      var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      /* a vouch bows towards the middle of the ring, where the ring is; a
         sourcing is a short, nearly straight spoke */
      var bow = edge.type === "sourced" ? 0.04 : 0.0;
      var nx = -(b.y - a.y) * bow, ny = (b.x - a.x) * bow;
      if (edge.type !== "sourced") {
        nx = (W / 2 - mx) * 0.34;
        ny = (H / 2 - my) * 0.34;
      }
      var stroke = edge.contaminated ? "var(--safety)" : "var(--seam)";
      var dash = edge.type === "sourced" ? ' stroke-dasharray="3 4"' : "";
      return '<path class="wire" data-source="' + esc(edge.source) + '" data-target="' + esc(edge.target) +
        '" d="M' + a.x.toFixed(1) + " " + a.y.toFixed(1) + " Q" + (mx + nx).toFixed(1) + " " +
        (my + ny).toFixed(1) + " " + b.x.toFixed(1) + " " + b.y.toFixed(1) +
        '" fill="none" stroke="' + stroke + '" stroke-width="' + (edge.contaminated ? 1.6 : 1) +
        '" opacity="' + (edge.contaminated ? .85 : .5) + '"' + dash + "/>";
    }).join("");

    var dots = nodes.map(function (node, i) {
      var p = pos[i];
      var actor = node.kind === "actor";
      var r = actor ? 13 : 5.5;
      var fill = node.flagged ? "var(--amber-key)"
        : node.contaminated ? "var(--safety)"
          : actor ? "var(--anodize)" : "var(--ink-faint)";
      var lx = Math.max(52, Math.min(W - 52, p.lx === undefined ? p.x : p.lx));
      var ly = Math.max(18, Math.min(H - 12, p.ly === undefined ? p.y + r + 15 : p.ly));
      var label = actor
        ? '<text x="' + lx.toFixed(1) + '" y="' + ly.toFixed(1) +
          '" text-anchor="middle" style="fill:var(--ink)">' + esc(node.label) + "</text>"
        : '<text class="mem" x="' + p.x.toFixed(1) + '" y="' + (p.y - 9).toFixed(1) +
          '" text-anchor="middle" style="fill:var(--ink-mute);opacity:0">' + esc(node.label) + "</text>";
      var ring = node.flagged
        ? '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + (r + 6) +
          '" fill="none" stroke="var(--safety)" stroke-width="1.5" stroke-dasharray="3 3"/>'
        : "";
      var title = node.kind === "actor"
        ? node.label + " · " + (node.address || "") + (node.flagged ? " · FLAGGED" : "") +
          (node.contaminated ? " · reachable from a flag" : "")
        : node.label + " · " + (node.tier || "") + " · " + code(node.verdict || "");
      return '<g class="node" tabindex="0" role="button" data-id="' + esc(node.id) +
        '" aria-label="' + esc(title) + '"><title>' + esc(title) + "</title>" + ring +
        '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + r +
        '" fill="' + fill + '" stroke="var(--shell)" stroke-width="1.5"/>' + label + "</g>";
    }).join("");

    host.innerHTML = '<svg viewBox="0 0 ' + W + " " + H + '" role="img" ' +
      'aria-label="Vouching graph: who vouched for whom and who sourced which memory">' +
      wires + dots + "</svg>";

    Array.prototype.forEach.call(host.querySelectorAll(".node"), function (group) {
      function highlight(on) {
        var id = group.dataset.id;
        Array.prototype.forEach.call(host.querySelectorAll(".wire"), function (wire) {
          var touching = wire.dataset.source === id || wire.dataset.target === id;
          wire.setAttribute("opacity", on ? (touching ? "1" : ".12") : (wire.getAttribute("stroke-width") === "1.6" ? ".85" : ".5"));
        });
        var text = group.querySelector("text.mem");
        if (text) text.style.opacity = on ? "1" : "0";
      }
      group.addEventListener("mouseenter", function () { highlight(true); });
      group.addEventListener("mouseleave", function () { highlight(false); });
      group.addEventListener("focus", function () { highlight(true); });
      group.addEventListener("blur", function () { highlight(false); });
      group.addEventListener("click", function () { openMemory(group.dataset.id); });
      group.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openMemory(group.dataset.id);
        }
      });
    });
  }

  function openMemory(id) {
    var name = String(id || "").split("/")[1];
    var row = $("trace").querySelector('[data-name="' + name + '"]');
    if (!row) return;
    row.open = true;
    row.scrollIntoView({ behavior: SM.reduced() ? "auto" : "smooth", block: "center" });
  }

  /* ── the anchor ───────────────────────────────────────────────────── */
  function renderAnchor(data) {
    $("anchor").innerHTML = [
      ['<span class="leg">Merkle root</span><b class="mono brk" style="font-size:12px">' +
        esc(data.root) + "</b>"],
      ['<span class="leg">Leaves</span><b>' + data.leaf_count + "</b>"],
      ['<span class="leg">Watermark</span><b style="font-size:13px">' + esc(stamp(data.as_of)) + "</b>"]
    ].map(function (row) { return "<div style=\"max-width:100%\">" + row[0] + "</div>"; }).join("");
    $("anchorPublished").textContent = data.published
      ? "published · " + (data.published.tx_hash || data.published.address || "")
      : "not yet published";
    $("anchorNote").textContent = data.note + (data.published ? "" :
      " No deployment artefact is present in this checkout, so the surface reports the root it " +
      "computes and says plainly that nothing has been published.");
  }

  /* ── running a decision ───────────────────────────────────────────── */
  function select(cp) {
    state.current = cp;
    state.ask = cp.default_ask_usd;
    state.asOf = null;
    scrub.value = 1000;
    $("ask").value = Number(cp.default_ask_usd).toFixed(2);
    Array.prototype.forEach.call($("rack").querySelectorAll(".slotcard"), function (button) {
      button.setAttribute("aria-pressed",
        String(state.counterparties[Number(button.dataset.i)].address === cp.address));
    });
    deck.subject(partyOf(cp));
    renderDossier(cp);
    runStream();
  }

  function closeStream() {
    if (state.source) { state.source.close(); state.source = null; }
  }

  /* The stream exists so the gate can be watched rather than merely reported:
     one frame per memory, in the order the gate reached them. */
  function runStream() {
    if (!state.current) return;
    closeStream();
    state.trace = [];
    $("trace").innerHTML = "";
    deck.reset();
    deck.run(null);

    var url = "/api/stream?counterparty=" + encodeURIComponent(state.current.address) +
      "&requested_usd=" + encodeURIComponent(state.ask) +
      (state.asOf ? "&as_of=" + encodeURIComponent(state.asOf) : "");
    var source = new EventSource(url);
    state.source = source;

    source.addEventListener("armed", function (event) {
      var data = JSON.parse(event.data);
      $("deckStatus").textContent = "SLOT A — READING";
      if (data.chain) setChain(data.chain);
    });
    source.addEventListener("recall", function (event) {
      var data = JSON.parse(event.data);
      $("traceCount").textContent = data.label;
    });
    source.addEventListener("memory", function (event) {
      appendTrace(JSON.parse(event.data).memory);
    });
    source.addEventListener("weigh", function (event) {
      var data = JSON.parse(event.data);
      $("explain").textContent = data.label + " — weighing.";
    });
    source.addEventListener("decision", function (event) {
      var payload = JSON.parse(event.data);
      renderDecision(payload);
      if (!state.asOf) rememberTicks(payload);
      deck.resolve(outcomeOf(payload));
      $("scrubKnown").textContent = payload.trace.length;
      $("scrubAction").textContent = payload.decision.action.toUpperCase();
    });
    source.addEventListener("done", function () { closeStream(); });
    source.onerror = function () { closeStream(); };
  }

  /* A quiet re-run: used by the scrubber and the amount box, where the point is
     the changed answer rather than watching it being reached. */
  function refresh(animate) {
    if (!state.current) return;
    closeStream();
    post("/api/decide", {
      counterparty: state.current.address,
      requested_usd: state.ask,
      as_of: state.asOf
    }).then(function (payload) {
      renderDecision(payload);
      renderTrace(payload.trace);
      if (!state.asOf) rememberTicks(payload);
      var outcome = outcomeOf(payload);
      if (animate) { deck.reset(); deck.run(outcome); } else { deck.reset(); deck.restore(outcome); }
      $("scrubKnown").textContent = payload.trace.length;
      $("scrubAction").textContent = payload.decision.action.toUpperCase();
    });
  }

  function rememberTicks(payload) {
    var times = payload.trace
      .map(function (m) { return ms(m.observed_at); })
      .filter(function (t) { return t !== null; });
    var now = Date.now();
    var min = times.length ? Math.min.apply(null, times) : now - 86400000;
    var span = Math.max(3600000, now - min);
    state.span = { min: min - span * 0.04, max: now };
    var total = state.span.max - state.span.min;
    state.ticks = payload.trace.map(function (m) {
      var t = ms(m.observed_at);
      var mark = m.verdict.admits ? 2 : (m.forgery || m.verdict.code === "malformed" ? 0 : 1);
      return { at: t === null ? 0 : Math.max(0, Math.min(1, (t - state.span.min) / total)), mark: mark };
    });
    renderScrub();
  }

  function setChain(chain) {
    state.chain = chain;
    var chip = $("chainChip");
    chip.setAttribute("data-live", String(!!chain.live));
    $("chainLabel").textContent = chain.chain;
    chip.title = chain.note || "";
    $("footChain").textContent = "chain: " + chain.chain +
      (chain.settlements != null ? " · " + chain.settlements + " recorded settlements" : "");
    deck.chain(chain.live ? "BASE" : "OFFLINE");
  }

  /* ── wiring ───────────────────────────────────────────────────────── */
  var askTimer = null;
  $("ask").addEventListener("input", function (event) {
    var value = parseFloat(event.target.value);
    if (!isFinite(value) || value < 0) return;
    state.ask = value;
    clearTimeout(askTimer);
    askTimer = setTimeout(function () { refresh(false); }, 420);
  });
  Array.prototype.forEach.call(document.querySelectorAll(".preset"), function (button) {
    if (!button.dataset.ask) return;
    button.addEventListener("click", function () {
      state.ask = parseFloat(button.dataset.ask);
      $("ask").value = state.ask.toFixed(2);
      refresh(false);
    });
  });
  $("run").addEventListener("click", function () { runStream(); });
  wireScrub();
  renderScrub();

  var graphTimer = null;
  window.addEventListener("resize", function () {
    clearTimeout(graphTimer);
    graphTimer = setTimeout(function () { if (state.graph) renderGraph(state.graph); }, 200);
  });

  get("/api/counterparties").then(function (data) {
    setChain(data.chain);
    state.counterparties = data.counterparties;
    renderRack();
    var subject = null;
    data.counterparties.forEach(function (cp) { if (!subject && cp.action === "refuse") subject = cp; });
    select(subject || data.counterparties[0]);
  }).catch(function (err) {
    $("explain").textContent =
      "The store could not be read. Run `python web/seed.py` and reload. (" + err.message + ")";
  });

  get("/api/flags").then(renderFlags).catch(function () { });
  get("/api/graph").then(renderGraph).catch(function () { });
  get("/api/anchor").then(renderAnchor).catch(function () { });
})();
