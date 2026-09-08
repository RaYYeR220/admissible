/* The landing. Everything it prints comes from the running server:
   the chain label, the refusal in the hero, the verdict codes beside the
   check list, and the scorecard, which is produced by shelling out to the
   repository's own bench so the number here and the number in a judge's
   terminal cannot drift. Nothing is hardcoded except the copy. */
(function () {
  "use strict";
  var SM = window.SoftMachine;
  var $ = function (id) { return document.getElementById(id); };
  var esc = SM.escape;

  SM.wireTheme($("theme"));

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

  /* ── the tier plate: one moulded object, two orientations ─────────── */
  var TIERS = [
    {
      name: "ATTESTED", colour: "var(--anodize)",
      lines: [
        "Bound to a settled payment on",
        "Base, or to an ERC-8004 record",
        "whose committed hash is the",
        "keccak256 of this exact claim."
      ],
      strip: "MOVES WHAT SETTLED — NO MORE"
    },
    {
      name: "WITNESSED", colour: "var(--amber-key)",
      lines: [
        "Our own agent saw it first-hand.",
        "No chain call, and no other actor",
        "may claim this tier on our behalf,",
        "however it labels itself."
      ],
      strip: "MOVES MONEY — DISCOUNTED, CAPPED"
    },
    {
      name: "HEARSAY", colour: "var(--ink-faint)",
      lines: [
        "Somebody asserted it. Nothing",
        "corroborates it. It may inform a",
        "conversation; it may not move",
        "money on its own, at any amount."
      ],
      strip: "NEVER MOVES MONEY ALONE"
    }
  ];

  function well(x, y, w, h, tier, rp) {
    var pad = 22;
    var lines = tier.lines.map(function (line, i) {
      return '<text x="' + (x + pad) + '" y="' + (y + 96 + i * 18) + '" style="font-family:\'Azeret Mono\',monospace;font-size:11px;letter-spacing:.02em;fill:#f5f2e9;fill-opacity:.55">' + esc(line) + "</text>";
    }).join("");
    return (
      '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="' + rp + '" style="fill:var(--graphite)"/>' +
      '<rect x="' + (x + 1.5) + '" y="' + (y + 1.5) + '" width="' + (w - 3) + '" height="' + (h - 3) + '" rx="' + rp + '" style="fill:none;stroke:#fff;stroke-opacity:.07;stroke-width:1"/>' +
      '<circle cx="' + (x + w - pad) + '" cy="' + (y + pad + 6) + '" r="7" style="fill:' + tier.colour + '"/>' +
      '<circle cx="' + (x + w - pad) + '" cy="' + (y + pad + 6) + '" r="14" style="fill:' + tier.colour + ';opacity:.16"/>' +
      '<text x="' + (x + pad) + '" y="' + (y + 50) + '" style="font-family:\'Panchang\',sans-serif;font-weight:600;font-size:26px;letter-spacing:.01em;fill:' + tier.colour + '">' + esc(tier.name) + "</text>" +
      '<text x="' + (x + pad) + '" y="' + (y + 70) + '" style="font-family:\'Azeret Mono\',monospace;font-size:9px;letter-spacing:.14em;fill:#f5f2e9;fill-opacity:.3">TIER ' + (TIERS.indexOf(tier) + 1) + " OF 3</text>" +
      lines +
      '<line x1="' + (x + pad) + '" y1="' + (y + h - 44) + '" x2="' + (x + w - pad) + '" y2="' + (y + h - 44) + '" style="stroke:#f5f2e9;stroke-opacity:.12;stroke-width:1"/>' +
      '<text x="' + (x + pad) + '" y="' + (y + h - 22) + '" style="font-family:\'Azeret Mono\',monospace;font-size:10px;letter-spacing:.09em;fill:' + tier.colour + '">' + esc(tier.strip) + "</text>"
    );
  }

  function hazard(x, y, w, h) {
    return (
      '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="4" style="fill:none;stroke:var(--safety);stroke-width:2;stroke-opacity:.7"/>' +
      '<text x="' + (x + 18) + '" y="' + (y + 24) + '" style="font-family:\'Azeret Mono\',monospace;font-weight:600;font-size:11px;letter-spacing:.14em;fill:var(--safety)">FLAGGED</text>' +
      '<text x="' + (x + 18) + '" y="' + (y + 44) + '" style="font-family:\'Azeret Mono\',monospace;font-size:10px;letter-spacing:.03em;fill:var(--safety);fill-opacity:.8">An actor caught laundering forged evidence. Written into Sibyl&rsquo;s own</text>' +
      '<text x="' + (x + 18) + '" y="' + (y + 60) + '" style="font-family:\'Azeret Mono\',monospace;font-size:10px;letter-spacing:.03em;fill:var(--safety);fill-opacity:.8">flagged_actors table, and it survives into the next session.</text>'
    );
  }

  function renderPlate() {
    var host = $("plate");
    if (!host) return;
    var tall = window.matchMedia("(max-width: 620px)").matches;
    var W, H, body;
    if (tall) {
      W = 620; H = 930;
      body = TIERS.map(function (t, i) { return well(40, 90 + i * 232, 540, 208, t, 8); }).join("") +
        hazard(40, 90 + 3 * 232 + 14, 540, 74);
    } else {
      W = 1180; H = 486;
      body = TIERS.map(function (t, i) { return well(40 + i * 380, 84, 340, 296, t, 8); }).join("") +
        hazard(40, 396, 1100, 74);
    }
    host.style.aspectRatio = W + " / " + H;
    host.innerHTML =
      '<svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Tier plate: attested, witnessed and hearsay, with the flagged tier beneath">' +
      '<defs><linearGradient id="plateG" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" style="stop-color:var(--shell)"/><stop offset="1" style="stop-color:var(--shell-shade)"/></linearGradient></defs>' +
      '<rect x="0" y="0" width="' + W + '" height="' + H + '" rx="18" fill="url(#plateG)"/>' +
      '<rect x="0.5" y="0.5" width="' + (W - 1) + '" height="' + (H - 1) + '" rx="18" style="fill:none;stroke:var(--seam);stroke-width:1"/>' +
      '<rect x="10" y="10" width="' + (W - 20) + '" height="' + (H - 20) + '" rx="14" style="fill:none;stroke:#fff;stroke-opacity:.5;stroke-width:1"/>' +
      '<text x="40" y="48" style="font-family:\'Azeret Mono\',monospace;font-weight:500;font-size:11px;letter-spacing:.14em;fill:var(--ink-faint)">TIER PLATE &middot; AD&middot;1 &middot; RIVETED</text>' +
      '<text x="' + (W - 40) + '" y="48" text-anchor="end" style="font-family:\'Azeret Mono\',monospace;font-weight:500;font-size:11px;letter-spacing:.14em;fill:var(--ink-faint)">WEIGHT IS THE SETTLED AMOUNT</text>' +
      body +
      "</svg>";
  }
  renderPlate();
  var plateTimer;
  window.addEventListener("resize", function () {
    clearTimeout(plateTimer);
    plateTimer = setTimeout(renderPlate, 180);
  });

  /* ── the ordered checks, with the codes that actually fired ───────── */
  var CHECKS = [
    ["Is this even an envelope?", ["malformed"]],
    ["Does it parse, field by field?", ["malformed"]],
    ["Did an actor we already caught assert it?", ["flagged_source"]],
    ["Has a later record invalidated it?", ["superseded"]],
    ["Has its validity window closed?", ["expired"]],
    ["Do its two clocks agree with ours?", ["backdated"]],
    ["Does it even claim to have evidence?", ["inadmissible_hearsay"]],
    ["Does the chain agree, and who paid?",
      ["evidence_not_found", "counterparty_mismatch", "amount_mismatch", "digest_mismatch"]]
  ];

  function renderChecks(fired) {
    var host = $("checks");
    if (!host) return;
    host.innerHTML = CHECKS.map(function (row, i) {
      var codes = row[1].map(function (code) {
        var hit = fired && fired[code];
        return '<span class="badge ' + (hit ? "hard" : "soft") + '">' + esc(code.replace(/_/g, " ")) +
          (hit ? " &times;" + hit : "") + "</span>";
      }).join(" ");
      return '<li style="display:grid;grid-template-columns:26px 1fr;gap:var(--s2);padding:9px 0;border-top:' +
        (i ? "1px solid var(--seam)" : "0") + '">' +
        '<span class="leg" style="padding-top:2px">' + (i + 1 < 10 ? "0" : "") + (i + 1) + "</span>" +
        '<span><span style="color:var(--ink);font-size:13.5px">' + esc(row[0]) + "</span>" +
        '<span style="display:flex;gap:5px;flex-wrap:wrap;margin-top:6px">' + codes + "</span></span></li>";
    }).join("");
  }
  renderChecks(null);

  /* ── the decks ────────────────────────────────────────────────────── */
  var heroDeck = SM.makeDeck($("heroStage"), {
    party: { id: "loading", tier: "—", sessions: 0, ok: false, marks: [] },
    onStatus: function (text) {
      var hint = $("heroHint");
      if (hint && /REFUSED/.test(text)) hint.textContent = "hearsay · the deck will not close on it";
      else if (hint && /ADMITTED|HELD/.test(text)) hint.textContent = "memory re-derived · terms written";
    }
  });
  var gateDeck = SM.makeDeck($("gateStage"), {
    party: { id: "loading", tier: "—", sessions: 0, ok: false, marks: [] }
  });

  function terms(decision) {
    var d = decision;
    if (d.action === "pay") return "PAY " + d.unsecured_usd.toFixed(2) + " USDC";
    if (d.action === "escrow") return "ESCROW " + d.collateral_usd.toFixed(2) + " USDC";
    return "NO TRANSFER";
  }

  function outcomeOf(payload) {
    var d = payload.decision;
    var lead = null;
    (payload.trace || []).forEach(function (m) {
      if (!lead && m.forgery) lead = m;
    });
    if (!lead) {
      (payload.trace || []).forEach(function (m) {
        if (!lead && !m.verdict.admits) lead = m;
      });
    }
    var code = (d.blocked_by && d.blocked_by.verdict) || (lead && lead.verdict.code) || "";
    var field = (lead && lead.verdict.fields && lead.verdict.fields[0]) || "";
    return {
      ok: d.action !== "refuse",
      action: d.action,
      terms: terms(d),
      clause: code.replace(/_/g, " "),
      clauseDetail: field || (lead ? lead.name : "")
    };
  }

  function partyOf(cp) {
    return {
      id: cp.address.slice(0, 6) + "…" + cp.address.slice(-4),
      label: cp.handle || cp.address,
      tier: cp.standing,
      sessions: cp.sessions,
      marks: cp.marks,
      ok: cp.action !== "refuse"
    };
  }

  /* ── wire it to the server ────────────────────────────────────────── */
  get("/api/site").then(function (site) {
    var chip = $("chainChip"), label = $("chainLabel");
    chip.setAttribute("data-live", String(!!site.chain.live));
    label.textContent = site.chain.chain;
    chip.title = site.chain.note || "";
    $("footChain").textContent = "chain: " + site.chain.chain;
    heroDeck.chain(site.chain.live ? "BASE" : "OFFLINE");
    gateDeck.chain(site.chain.live ? "BASE" : "OFFLINE");

    var missing = [];
    [["repoLink", site.repo_url, "Repository"], ["videoLink", site.video_url, "Demo video"]]
      .forEach(function (row) {
        var el = $(row[0]);
        if (row[1]) { el.href = row[1]; el.textContent = row[2]; el.rel = "noreferrer"; }
        else {
          el.removeAttribute("href");
          el.setAttribute("aria-disabled", "true");
          el.style.opacity = ".45";
          el.style.cursor = "not-allowed";
          el.textContent = row[2] + " — not published";
          missing.push(row[2].toLowerCase());
        }
      });
    $("linkNote").textContent = missing.length
      ? "The " + missing.join(" and ") + " link" + (missing.length > 1 ? "s are" : " is") +
        " not published yet, so this page serves it as unavailable rather than inventing a URL. " +
        "Set ADMISSIBLE_REPO_URL and ADMISSIBLE_VIDEO_URL and it appears."
      : "";
  }).catch(function () {
    $("chainLabel").textContent = "server unreachable";
  });

  get("/api/counterparties").then(function (data) {
    var refused = null, admitted = null;
    data.counterparties.forEach(function (cp) {
      if (!refused && cp.action === "refuse") refused = cp;
      if (!admitted && cp.action !== "refuse") admitted = cp;
    });
    var subject = refused || admitted;
    if (!subject) return;

    heroDeck.subject(partyOf(subject));
    gateDeck.subject(partyOf(subject));
    $("gateSubject").textContent =
      "subject: " + (subject.handle || subject.address) + " · " + subject.sessions + " memories";

    return post("/api/decide", {
      counterparty: subject.address,
      requested_usd: subject.default_ask_usd
    }).then(function (payload) {
      var fired = {};
      (payload.trace || []).forEach(function (m) {
        if (!m.verdict.admits) fired[m.verdict.code] = (fired[m.verdict.code] || 0) + 1;
      });
      renderChecks(fired);

      var outcome = outcomeOf(payload);
      var ready = document.fonts ? document.fonts.ready : Promise.resolve();
      ready.then(function () {
        setTimeout(function () {
          heroDeck.mount(); heroDeck.reset(); heroDeck.run(outcome);
        }, 320);
      });

      /* the gate deck plays the same refusal when it comes into view */
      var played = false;
      var fire = function () {
        if (played) return;
        played = true;
        gateDeck.mount(); gateDeck.reset(); gateDeck.run(outcome);
      };
      if ("IntersectionObserver" in window) {
        var io = new IntersectionObserver(function (entries) {
          entries.forEach(function (e) { if (e.isIntersecting) { fire(); io.disconnect(); } });
        }, { threshold: 0.35 });
        io.observe($("gateStage"));
      }
      setTimeout(fire, 2600);
    });
  }).catch(function (err) {
    $("gateSubject").textContent = "store unavailable — run python web/seed.py";
    if (window.console) console.warn(err);
  });

  /* ── the scorecard, run on demand ─────────────────────────────────── */
  var cardLoaded = false;
  function loadCard() {
    if (cardLoaded) return;
    cardLoaded = true;
    get("/api/scorecard").then(function (card) {
      var host = $("cardNumbers");
      if (!card.available) {
        host.innerHTML = '<div><span class="leg">scorecard unavailable</span><b class="dim">' +
          esc(card.error || "bench did not run") + "</b></div>";
        return;
      }
      var c = card.corpus || {};
      host.innerHTML = [
        ['<span class="leg">Attacks caught, exact verdict</span><b class="ok">' +
          card.attacks_caught_exact + " / " + card.attacks_total + "</b>"],
        ['<span class="leg">Sound memories admitted</span><b class="ok">' +
          card.controls_admitted + " / " + card.controls_total + "</b>"],
        ['<span class="leg">False refusals</span><b class="' + (card.false_refusals ? "no" : "ok") + '">' +
          card.false_refusals + "</b>"],
        ['<span class="leg">Corpus</span><b>' + c.total + '</b><b class="dim">' +
          c.families + " families</b>"],
        ['<span class="leg">Refused before any RPC call</span><b>' + c.offline_decidable + "</b>"]
      ].map(function (row) { return "<div>" + row[0] + "</div>"; }).join("");
      $("cardCmd").textContent = card.command;
      $("redteamNote").textContent = card.honest_note || "";
      if (card.redteam && card.redteam.residue) $("residueNote").textContent = card.redteam.residue;
    }).catch(function () {
      $("cardNumbers").innerHTML =
        '<div><span class="leg">scorecard unavailable</span><b class="dim">run python bench/run.py</b></div>';
    });
  }
  if ("IntersectionObserver" in window) {
    var io2 = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { loadCard(); io2.disconnect(); } });
    }, { threshold: 0.2 });
    io2.observe($("numbers"));
  }
  /* and unconditionally shortly after load, so the numbers are there whether or
     not anybody scrolled -- the bench takes a couple of seconds to run */
  setTimeout(loadCard, 900);
})();
