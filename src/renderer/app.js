// Meshwatch renderer — multi-view dashboard wired to preload IPC.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const PREFS_KEY = "meshwatch.prefs";

const state = {
  view: "overview",
  devices: [],
  topology: [],
  audit: null,
  drift: [],
  subnet: null,
  selectedMac: null,
  query: "",
  chip: "All",
  lastScanAt: null,
  scanning: false,
  scanProgress: 0,
  auditFilter: "all", // all | critical | high | medium | low | dismissed
  prefs: loadPrefs()
};

const statusEl = $("#status");
const logEl = $("#log");
const ctxEl = $("#ctx");
let toastTimer = null;

function loadPrefs() {
  try {
    return Object.assign(
      { showOffline: true, autoScan: false },
      JSON.parse(localStorage.getItem(PREFS_KEY) || "{}")
    );
  } catch (e) {
    return { showOffline: true, autoScan: false };
  }
}

function savePrefs() {
  state.prefs.showOffline = $("#pref-offline").checked;
  state.prefs.autoScan = $("#pref-autoscan").checked;
  localStorage.setItem(PREFS_KEY, JSON.stringify(state.prefs));

  const sshPort = $("#pref-ssh-port").value;
  const sshUser = $("#pref-ssh-user").value;
  window.meshwatch.pihole.setPrefs({ sshPort, sshUser }).then((r) => {
    if (r && !r.ok) {
      toast(r.reason || "Could not save SSH settings");
      return;
    }
    if (r && r.state) state.pihole = r.state;
    toast("Preferences saved");
    loadPreferences();
  }).catch((e) => {
    toast("Could not save preferences: " + (e && e.message || e));
  });
  renderInventory();
}

function setStatus(text) {
  statusEl.textContent = text;
}

function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

// Electron does not implement window.prompt — use an in-app modal.
let modalResolver = null;

function askText({ title, hint, value, multiline }) {
  return new Promise((resolve) => {
    if (modalResolver) modalResolver(null);
    modalResolver = resolve;
    $("#modal-title").textContent = title || "Edit";
    const hintEl = $("#modal-hint");
    hintEl.textContent = hint || "";
    hintEl.hidden = !hint;
    const input = $("#modal-input");
    input.value = value == null ? "" : String(value);
    input.rows = multiline === false ? 1 : 4;
    $("#modal").hidden = false;
    requestAnimationFrame(() => {
      input.focus();
      input.select();
    });
  });
}

function closeModal(result) {
  $("#modal").hidden = true;
  const resolve = modalResolver;
  modalResolver = null;
  if (resolve) resolve(result);
}

$("#modal-cancel").addEventListener("click", () => closeModal(null));
$("#modal-ok").addEventListener("click", () => closeModal($("#modal-input").value));
$("#modal-input").addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    closeModal(null);
  }
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey || $("#modal-input").rows === 1)) {
    e.preventDefault();
    closeModal($("#modal-input").value);
  }
});
$("#modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") closeModal(null);
});

function line(text, color) {
  const div = document.createElement("div");
  div.textContent = text;
  if (color) div.style.color = color;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function ipSort(a, b) {
  const pa = String(a.ip || "").split(".").map(Number);
  const pb = String(b.ip || "").split(".").map(Number);
  for (let i = 0; i < 4; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

function roleLabel(type) {
  if (!type) return "—";
  const map = {
    gateway: "Gateway",
    "dns-dhcp": "DNS / DHCP · Pi-hole",
    switch: "Switch",
    "access-point": "Access point",
    extender: "Extender",
    "legacy-router": "Legacy router"
  };
  return map[type] || type;
}

function isOnline(d) {
  if (!d.last_seen && !state.lastScanAt) return true;
  const ref = state.lastScanAt || Date.now();
  const seen = d.last_seen || ref;
  return ref - seen < 15 * 60 * 1000;
}

function deviceRisk(d) {
  if (state.audit && state.audit.findings) {
    const hits = state.audit.findings.filter((f) => f.mac === d.mac);
    if (hits.some((f) => f.severity === "critical")) return "critical";
    if (hits.some((f) => f.severity === "high")) return "high";
    if (hits.some((f) => f.severity === "medium")) return "medium";
    if (hits.some((f) => f.severity === "low")) return "low";
  }
  if (d.end_of_support || d.endOfSupport) return "critical";
  if (d.estimated) return "medium";
  return "ok";
}

function firmwareOf(d) {
  return d.firmware_manual || d.firmware || "—";
}

function parentName(d) {
  const mac = d.parent_mac || d.parentMac;
  if (!mac) return d.type === "gateway" ? "Internet" : "—";
  const p = state.devices.find((x) => x.mac === mac);
  return p ? p.name : mac;
}

function childCount(mac) {
  return state.devices.filter((d) => (d.parent_mac || d.parentMac) === mac).length;
}

function go(view) {
  if (view === "pihole" && $("#nav-pihole").hidden) {
    view = "overview";
  }
  state.view = view;
  $$(".nav").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + view));
  if (view === "topology") renderTopology();
  if (view === "audit" && !state.audit) runAudit();
  if (view === "pihole") loadPihole();
  if (view === "preferences") loadPreferences();
  if (view === "discovery") updateScanChrome();
  hideCtx();
  // Device panel stays open while switching rows in Inventory or Topology;
  // close it when leaving for any other left-nav view.
  if (view !== "inventory" && view !== "topology") closeDetail();
}

async function updatePiholeNav() {
  let st = { discovered: false };
  try {
    st = await window.meshwatch.pihole.state();
  } catch (e) { /* ignore */ }
  state.pihole = st;
  const nav = $("#nav-pihole");
  nav.hidden = !st.discovered;
  if (!st.discovered && state.view === "pihole") go("overview");
  return st;
}

$$(".nav").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.view)));
$$("[data-goto]").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.goto)));

const CHIPS = ["All", "Online", "Gateway", "Switch", "Access point", "Client", "Estimated"];

function renderChips() {
  const row = $("#inventory-chips");
  row.textContent = "";
  for (const c of CHIPS) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chip" + (state.chip === c ? " on" : "");
    b.textContent = c;
    b.addEventListener("click", () => {
      state.chip = c;
      renderChips();
      renderInventory();
    });
    row.appendChild(b);
  }
}

function filteredDevices() {
  const q = state.query.trim().toLowerCase();
  let list = state.devices.slice().sort(ipSort);

  if (!state.prefs.showOffline) list = list.filter(isOnline);

  if (state.chip === "Online") list = list.filter(isOnline);
  else if (state.chip === "Gateway") list = list.filter((d) => d.type === "gateway");
  else if (state.chip === "Switch") list = list.filter((d) => d.type === "switch");
  else if (state.chip === "Access point") {
    list = list.filter((d) => d.type === "access-point" || d.type === "extender");
  } else if (state.chip === "Estimated") list = list.filter((d) => d.estimated);
  else if (state.chip === "Client") {
    list = list.filter((d) => !d.type || !["gateway", "switch", "access-point", "extender", "dns-dhcp", "legacy-router"].includes(d.type));
  }

  if (!q) return list;
  return list.filter((d) => {
    const hay = [d.name, d.ip, d.mac, d.vendor, d.model, d.type, firmwareOf(d), (d.methods || []).join(" ")].join(" ").toLowerCase();
    return hay.indexOf(q) !== -1;
  });
}

function renderInventory() {
  const tbody = $("#devices tbody");
  tbody.textContent = "";
  const rows = filteredDevices();
  $("#inventory-lede").textContent = rows.length + " of " + state.devices.length + " devices";
  $("#badge-inventory").textContent = state.devices.length || "";

  for (const d of rows) {
    const tr = document.createElement("tr");
    tr.dataset.mac = d.mac;
    if (d.mac === state.selectedMac) tr.classList.add("selected");

    const nameCell = document.createElement("td");
    nameCell.textContent = d.name || "Unidentified host";
    if (d.estimated) {
      const est = document.createElement("span");
      est.className = "est";
      est.textContent = "estimate";
      nameCell.appendChild(est);
    }
    if (d.nameOverride || d.name_override) {
      const custom = document.createElement("span");
      custom.className = "est";
      custom.textContent = "renamed";
      nameCell.appendChild(custom);
    }
    tr.appendChild(nameCell);

    const risk = deviceRisk(d);
    const online = isOnline(d);
    const cells = [
      d.ip,
      d.mac,
      d.vendor || "—",
      roleLabel(d.type),
      firmwareOf(d),
      null,
      null
    ];
    for (let i = 0; i < 5; i++) {
      const td = document.createElement("td");
      td.textContent = cells[i] == null || cells[i] === "" ? "—" : cells[i];
      tr.appendChild(td);
    }
    const riskTd = document.createElement("td");
    riskTd.innerHTML = '<span class="risk ' + risk + '">' + risk + "</span>";
    tr.appendChild(riskTd);

    const stTd = document.createElement("td");
    stTd.innerHTML = '<span class="status-dot' + (online ? "" : " off") + '"></span>' + (online ? "Online" : "Not seen");
    tr.appendChild(stTd);

    tr.addEventListener("click", () => openDetail(d));
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      openCtx(e.clientX, e.clientY, d);
    });
    tbody.appendChild(tr);
  }

  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.className = "empty";
    td.textContent = state.devices.length ? "No devices match this filter." : "No devices yet — run a scan.";
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

function renderOverview() {
  const online = state.devices.filter(isOnline).length;
  const estimated = state.devices.filter((d) => d.estimated).length;
  const withWeb = state.devices.filter((d) => d.web_reachable || (d.web && d.web.reachable)).length;
  const gw = state.devices.find((d) => d.type === "gateway");

  $("#overview-stats").innerHTML = [
    ["Online", online],
    ["Devices", state.devices.length],
    ["Estimated IDs", estimated],
    ["Web admin", withWeb],
    ["Gateway", gw ? gw.name : "—"]
  ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");

  const attn = $("#overview-attention");
  attn.textContent = "";
  const findings = (state.audit && state.audit.findings) || [];
  const top = findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  const drift = state.drift || [];

  if (!top.length && !drift.length) {
    attn.innerHTML = '<p class="empty">Nothing urgent. Run Security audit after a scan.</p>';
  } else {
    for (const f of top) {
      const div = document.createElement("div");
      div.className = "finding";
      div.innerHTML =
        '<span class="sev ' + f.severity + '">' + escapeHtml(f.severity) + "</span>" +
        "<div><h3>" + escapeHtml(f.title) + "</h3>" +
        '<span class="meta">' + escapeHtml((f.device || "") + " · " + (f.ip || "")) + "</span></div>";
      attn.appendChild(div);
    }
    for (const w of drift) {
      const div = document.createElement("div");
      div.className = "finding";
      div.innerHTML =
        '<span class="sev high">drift</span>' +
        "<div><h3>" + escapeHtml(w.knownName + " missing") + "</h3>" +
        "<p>" + escapeHtml(w.detail) + "</p></div>";
      attn.appendChild(div);
    }
  }

  if (state.audit) {
    $("#overview-score").textContent = String(state.audit.score);
    const c = state.audit.counts || {};
    const dismissedN = state.audit.dismissedCount || 0;
    $("#overview-score-note").textContent =
      (c.critical || 0) + " critical · " + (c.high || 0) + " high · " + (c.medium || 0) + " medium" +
      (dismissedN ? " · " + dismissedN + " dismissed" : "");
  }
}

function renderTopology() {
  const root = $("#topology-tree");
  root.textContent = "";
  const tree = state.topology || [];
  if (!tree.length) {
    root.innerHTML = '<p class="empty">No topology yet — run a scan.</p>';
    return;
  }

  const rows = [];
  function walk(nodes, depth, isLastSiblings) {
    nodes.forEach((n, i) => {
      const isLast = i === nodes.length - 1;
      const kids = (n.children && n.children.length) || 0;
      const device = state.devices.find((x) => x.mac === n.mac) || n;
      const online = isOnline(device);
      const risk = deviceRisk(device);
      rows.push({
        n,
        device,
        depth,
        isLast,
        spine: isLastSiblings.slice(),
        kids,
        online,
        risk,
        estimated: !!n.estimated
      });
      if (n.children && n.children.length) {
        walk(n.children, depth + 1, isLastSiblings.concat(isLast));
      }
    });
  }
  walk(tree, 0, []);

  const list = document.createElement("div");
  list.className = "topo-list";

  for (const row of rows) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "topo-row" +
      (row.n.mac === state.selectedMac ? " on" : "") +
      (row.depth === 0 ? " root" : "") +
      (row.estimated ? " estimated" : "");
    btn.setAttribute("role", "treeitem");
    btn.style.setProperty("--depth", String(row.depth));

    const rail = document.createElement("span");
    rail.className = "topo-rail";
    rail.setAttribute("aria-hidden", "true");
    for (let d = 0; d < row.depth; d++) {
      const col = document.createElement("span");
      col.className = "topo-rail-col" + (row.spine[d] ? " quiet" : "");
      rail.appendChild(col);
    }
    if (row.depth > 0) {
      const elbow = document.createElement("span");
      elbow.className = "topo-elbow" + (row.isLast ? " last" : "") + (row.estimated ? " est" : "");
      rail.appendChild(elbow);
    }

    const dot = document.createElement("span");
    dot.className = "topo-dot" +
      (row.online ? "" : " off") +
      (row.risk === "critical" || row.risk === "high" ? " risk" : "");

    const main = document.createElement("span");
    main.className = "topo-main";
    const title = document.createElement("span");
    title.className = "topo-name";
    title.textContent = row.n.name || "Device";
    const sub = document.createElement("span");
    sub.className = "topo-sub";
    sub.textContent = [
      roleLabel(row.n.type),
      row.n.ip || null
    ].filter(Boolean).join(" · ");
    main.appendChild(title);
    main.appendChild(sub);

    const right = document.createElement("span");
    right.className = "topo-right";
    if (row.kids > 0) {
      const branch = document.createElement("span");
      branch.className = "topo-branch";
      branch.textContent = row.kids === 1 ? "1 downstream" : row.kids + " downstream";
      right.appendChild(branch);
    }
    if (row.estimated) {
      const est = document.createElement("span");
      est.className = "topo-est";
      est.textContent = "Estimated";
      right.appendChild(est);
    }
    if (row.risk && row.risk !== "ok") {
      const badge = document.createElement("span");
      badge.className = "topo-risk " + row.risk;
      badge.textContent = row.risk;
      right.appendChild(badge);
    }

    btn.appendChild(rail);
    btn.appendChild(dot);
    btn.appendChild(main);
    btn.appendChild(right);

    btn.addEventListener("click", () => {
      const d = state.devices.find((x) => x.mac === row.n.mac);
      if (d) openDetail(d);
    });
    btn.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const d = state.devices.find((x) => x.mac === row.n.mac);
      if (d) openCtx(e.clientX, e.clientY, d);
    });

    list.appendChild(btn);
  }

  root.appendChild(list);
}

function renderAudit() {
  const box = $("#audit-list");
  const stats = $("#audit-stats");
  box.textContent = "";
  if (!state.audit) {
    stats.innerHTML = "";
    box.innerHTML = '<p class="empty">Press Run audit.</p>';
    return;
  }

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const c = state.audit.counts || {};
  const filter = state.auditFilter || "all";
  const active = state.audit.findings || [];
  const dismissed = state.audit.dismissedFindings || [];

  const chips = [
    { key: "all", label: "Open", n: active.length },
    { key: "critical", label: "Critical", n: c.critical || 0 },
    { key: "high", label: "High", n: c.high || 0 },
    { key: "medium", label: "Medium", n: c.medium || 0 },
    { key: "low", label: "Low", n: c.low || 0 },
    { key: "dismissed", label: "Dismissed", n: dismissed.length }
  ];

  stats.innerHTML =
    '<div class="stat score-stat"><div class="n">' + escapeHtml(String(state.audit.score)) + '</div><div class="l">Score</div></div>' +
    chips.map((chip) =>
      '<button type="button" class="stat filter-stat sev-stat-' + chip.key +
      (filter === chip.key ? " on" : "") +
      '" data-filter="' + chip.key + '" aria-pressed="' + (filter === chip.key ? "true" : "false") + '">' +
      '<div class="n">' + escapeHtml(String(chip.n)) + '</div>' +
      '<div class="l">' + escapeHtml(chip.label) + "</div></button>"
    ).join("");

  $$(".filter-stat", stats).forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.filter;
      state.auditFilter = state.auditFilter === key ? "all" : key;
      renderAudit();
    });
  });

  $("#badge-audit").textContent = (c.critical || 0) || "";

  const showingDismissed = filter === "dismissed";
  let findings = showingDismissed ? dismissed.slice() : active.slice();
  findings.sort((a, b) => {
    const sa = SEV_ORDER[a.severity] != null ? SEV_ORDER[a.severity] : 9;
    const sb = SEV_ORDER[b.severity] != null ? SEV_ORDER[b.severity] : 9;
    if (sa !== sb) return sa - sb;
    return String(a.title || "").localeCompare(String(b.title || ""));
  });

  if (!showingDismissed && filter !== "all") {
    findings = findings.filter((f) => f.severity === filter);
  }

  if (!findings.length) {
    box.innerHTML = '<p class="empty">' +
      (showingDismissed
        ? "No dismissed findings."
        : ("No " + (filter === "all" ? "open " : filter + " ") + "findings.")) +
      "</p>";
  }

  for (const f of findings) {
    const div = document.createElement("div");
    div.className = "finding" + (showingDismissed ? " dismissed" : "");
    const actionBtn = !showingDismissed && f.action && /block internet/i.test(f.action)
      ? '<button type="button" class="secondary finding-block" data-mac="' + escapeHtml(f.mac || "") + '">Block internet</button>'
      : "";
    const dismissBtn = showingDismissed
      ? '<button type="button" class="secondary finding-restore" data-key="' + escapeHtml(f.key || "") + '">Restore</button>'
      : '<button type="button" class="secondary finding-dismiss" data-key="' + escapeHtml(f.key || "") + '">Dismiss</button>';
    div.innerHTML =
      '<span class="sev ' + escapeHtml(f.severity) + '">' + escapeHtml(f.severity) + "</span>" +
      "<div><h3>" + escapeHtml(f.title) + "</h3>" +
      "<p>" + escapeHtml(f.detail || "") + "</p>" +
      '<span class="meta">' + escapeHtml([f.device, f.ip, f.reference].filter(Boolean).join(" · ")) + "</span>" +
      (f.action ? "<p><strong>Action:</strong> " + escapeHtml(f.action) + "</p>" : "") +
      (f.estimated ? '<span class="est">estimate</span>' : "") +
      (showingDismissed ? '<span class="meta">Dismissed — not counted in score</span>' : "") +
      "</div>" +
      '<div class="finding-actions">' + dismissBtn + actionBtn + "</div>";
    box.appendChild(div);
  }
  $$(".finding-block", box).forEach((b) => {
    b.addEventListener("click", () => {
      toast("Internet blocking is not available yet — it needs a live Pi-hole API connection.");
    });
  });
  $$(".finding-dismiss", box).forEach((b) => {
    b.addEventListener("click", async () => {
      const key = b.dataset.key;
      if (!key) return;
      const r = await window.meshwatch.dismissFinding(key);
      if (r && r.ok && r.audit) {
        state.audit = r.audit;
        toast("Finding dismissed — score " + r.audit.score);
        renderAudit();
      } else {
        toast((r && r.reason) || "Could not dismiss finding");
      }
    });
  });
  $$(".finding-restore", box).forEach((b) => {
    b.addEventListener("click", async () => {
      const key = b.dataset.key;
      if (!key) return;
      const r = await window.meshwatch.restoreFinding(key);
      if (r && r.ok && r.audit) {
        state.audit = r.audit;
        toast("Finding restored — score " + r.audit.score);
        renderAudit();
      } else {
        toast((r && r.reason) || "Could not restore finding");
      }
    });
  });
  renderInventory();
  renderOverview();
}

async function runAudit() {
  setStatus("Running audit…");
  try {
    state.audit = await window.meshwatch.getAudit();
    state.auditFilter = "all";
    renderAudit();
    setStatus("Audit complete — score " + state.audit.score);
    toast("Audit score " + state.audit.score);
  } catch (e) {
    setStatus("Audit failed: " + e.message);
  }
}

async function loadPihole() {
  const stats = $("#pihole-stats");
  const blocked = $("#pihole-blocked");
  const host = $("#pihole-host");
  try {
    const target = await window.meshwatch.pihole.target();
    const s = await window.meshwatch.pihole.stats();
    if (!s || s.available === false) {
      stats.innerHTML = [
        ["Queries today", "—"],
        ["Blocked", "—"],
        ["Blocked %", "—"],
        ["SSH port", (target && target.port) || "—"]
      ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");
      blocked.innerHTML = '<p class="empty">' + escapeHtml((s && s.reason) || "Pi-hole API is not connected yet. Save the API token in Preferences when ready.") + "</p>";
      const where = target && target.host
        ? (target.user + "@" + target.host + " -p " + target.port)
        : "host not set";
      host.innerHTML = '<p class="empty">SSH target: <code>' + escapeHtml(where) + "</code>. Set the port in Preferences if you moved off 22.</p>";
      return;
    }
    stats.innerHTML = [
      ["Queries today", s.queriesToday],
      ["Blocked", s.blockedToday],
      ["Blocked %", s.blockedPercent],
      ["Blocklist", s.blocklistSize]
    ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n == null ? "—" : n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");

    const tops = s.topBlocked || [];
    blocked.innerHTML = tops.length
      ? tops.map((t) => '<div class="blocked-row"><span>' + escapeHtml(t.domain || t) + "</span><span>" + escapeHtml(String(t.hits || "")) + "</span></div>").join("")
      : '<p class="empty">No blocked domains reported.</p>';
    host.innerHTML = s.hostNote
      ? "<p>" + escapeHtml(s.hostNote) + "</p>"
      : '<p class="empty">Host metrics via SSH when connected.</p>';
  } catch (e) {
    stats.innerHTML = '<p class="empty">' + escapeHtml(e.message) + "</p>";
  }
}

async function runPiholeCmd(command) {
  const out = $("#pihole-out");
  out.textContent = "$ " + command + "\n…";
  try {
    const r = await window.meshwatch.pihole.exec(command);
    if (r.cancelled) {
      out.textContent = "Cancelled.";
      toast("Command cancelled");
      return;
    }
    out.textContent = "$ " + command + "\n" + (r.output || []).join("\n");
  } catch (e) {
    out.textContent = "Error: " + e.message;
  }
}

function updateScanChrome() {
  const sub = state.subnet;
  $("#scan-subnet-label").textContent = (sub && sub.cidr) || "Local /24";
  if (state.scanning) {
    $("#scan-found").textContent = "Scanning…";
    $("#badge-discovery").textContent = "···";
  } else if (state.devices.length) {
    $("#scan-found").textContent = state.devices.length + " devices on file";
    $("#badge-discovery").textContent = "";
  } else {
    $("#scan-found").textContent = "Idle";
    $("#badge-discovery").textContent = "";
  }
  $("#scan-bar-fill").style.width = Math.min(100, state.scanProgress) + "%";
}

async function openDetail(d) {
  state.selectedMac = d.mac;
  renderInventory();
  if (state.view === "topology") renderTopology();
  const el = $("#detail");
  el.hidden = false;
  const online = isOnline(d);
  $("#detail-status").textContent = online ? "Online" : "Not seen";
  $("#detail-name").textContent = d.name || "Device";

  const webReach = d.web_reachable || (d.web && d.web.reachable);
  const webTitle = d.web_title || (d.web && d.web.title);
  const fw = firmwareOf(d);
  const fwLatest = d.firmware_latest || d.firmwareLatest;
  const fwSource = d.firmware_source || d.firmwareSource || (d.firmware_manual ? "manual" : null);
  const behind = fwLatest && fw && fw !== "—" && fw !== fwLatest;

  const rows = [
    ["Type", roleLabel(d.type)],
    ["IPv4", d.ip],
    ["MAC", d.mac],
    ["Vendor", d.vendor],
    ["Model", d.model],
    ["Display name", d.name],
    ["Discovered as", d.discoveredName || d.name],
    ["Uplink", parentName(d)],
    ["Connection", d.link || "—"],
    ["Signal", d.signal || "—"],
    ["Firmware", fw],
    ["Latest available", fwLatest || "—"],
    ["Source", fwSource || "—"],
    ["Control", d.control],
    ["Matched by", d.matched_by || d.matchedBy],
    ["Web title", webTitle],
    ["Found via", Array.isArray(d.methods) ? d.methods.join(", ") : d.method],
    ["Note", d.note],
    ["First seen", d.first_seen ? new Date(d.first_seen).toLocaleString() : null],
    ["Last seen", d.last_seen ? new Date(d.last_seen).toLocaleString() : null]
  ];
  $("#detail-body").innerHTML =
    "<dl>" +
    rows
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => "<dt>" + escapeHtml(k) + "</dt><dd>" + escapeHtml(String(v)) + "</dd>")
      .join("") +
    "</dl>" +
    (d.estimated ? '<p class="est">Identity not confirmed — label is an estimate.</p>' : "");

  const actions = $("#detail-actions");
  actions.textContent = "";

  const primary = document.createElement("button");
  primary.type = "button";
  primary.className = "primary-inline";
  if (behind) {
    primary.textContent = "Update firmware to " + fwLatest;
    primary.addEventListener("click", () => toast("Firmware update from Meshwatch is not available yet. Use the device admin page for now."));
  } else if (d.estimated || fw === "—") {
    primary.textContent = "Record firmware manually";
    primary.addEventListener("click", async () => {
      const v = await askText({
        title: "Record firmware",
        hint: "Type the version from the device label or admin page.",
        value: d.firmware_manual || "",
        multiline: false
      });
      if (v == null) return;
      await window.meshwatch.setFirmwareManual(d.mac, v.trim());
      d.firmware_manual = v.trim();
      d.firmware = v.trim();
      d.firmware_source = "manual";
      toast("Recorded firmware " + v.trim());
      openDetail(d);
      renderInventory();
    });
  } else {
    primary.textContent = "Re-probe this device";
    primary.addEventListener("click", () => {
      go("discovery");
      startScan();
    });
  }
  actions.appendChild(primary);
  const note = document.createElement("div");
  note.className = "action-note";
  note.textContent = behind
    ? "Vendor catalogue updates are not wired yet. Open the device admin page to check for firmware."
    : (d.estimated || fw === "—" ? "No API to query. Type the version from the device label or admin page." : "Runs another full subnet sweep.");
  actions.appendChild(note);

  const renameBtn = document.createElement("button");
  renameBtn.type = "button";
  renameBtn.textContent = "Rename device";
  renameBtn.addEventListener("click", () => renameDevicePrompt(d));
  actions.appendChild(renameBtn);

  if (d.nameOverride || d.name_override) {
    const clear = document.createElement("button");
    clear.type = "button";
    clear.textContent = "Clear custom name";
    clear.addEventListener("click", async () => {
      await window.meshwatch.renameDevice(d.mac, "");
      d.nameOverride = null;
      d.name_override = null;
      d.name = d.discoveredName || d.name;
      toast("Using discovered name again");
      await refreshDevice(d.mac);
    });
    actions.appendChild(clear);
  }

  if (webReach && d.ip) {
    const open = document.createElement("button");
    open.type = "button";
    open.textContent = "Open admin page";
    open.addEventListener("click", () => openInAppBrowser("http://" + d.ip + "/"));
    actions.appendChild(open);
  }

  const block = document.createElement("button");
  block.type = "button";
  block.textContent = "Block internet access";
  block.addEventListener("click", () => toast("Internet blocking is not available yet — it needs a live Pi-hole API connection."));
  actions.appendChild(block);

  const noteBtn = document.createElement("button");
  noteBtn.type = "button";
  noteBtn.textContent = "Add note";
  noteBtn.addEventListener("click", async () => {
    const n = await askText({
      title: "Note for " + (d.name || d.ip || "device"),
      hint: "Saved on this PC only. Leave empty to clear.",
      value: d.note || "",
      multiline: true
    });
    if (n == null) return;
    await window.meshwatch.setNote(d.mac, n);
    d.note = n;
    toast(n.trim() ? "Note saved" : "Note cleared");
    await refreshDevice(d.mac);
  });
  actions.appendChild(noteBtn);

  if (d.control === "tplink") {
    const sec = document.createElement("div");
    sec.className = "detail-section";
    sec.textContent = "TP-Link controls";
    actions.appendChild(sec);
    const tpActions = [
      ["Reboot", "reboot"],
      ["Firmware update", "firmwareUpdate"],
      ["SSID + password", "ssid"],
      ["Band steering", "bandSteering"],
      ["Client list", "clientList"],
      ["Port forwarding", "portForwarding"],
      ["WAN speed test", "speedTest"],
      ["LED schedule", "led"],
      ["Backhaul health", "backhaul"]
    ];
    for (const [label, action] of tpActions) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", async () => {
        const r = await window.meshwatch.tplink.action(d.ip, action, {});
        if (r && r.cancelled) return toast("Cancelled");
        if (r && r.adminPage && (!r.ok)) {
          toast((r.reason || "Not available") + " — opening admin in Meshwatch");
          openInAppBrowser(r.adminPage);
        } else if (r && r.ok) toast(label + " ok");
        else toast((r && r.reason) || "This control action is not available yet");
      });
      actions.appendChild(b);
    }
  }

  if (d.type === "dns-dhcp" || d.control === "ssh") {
    const sec = document.createElement("div");
    sec.className = "detail-section";
    sec.textContent = "Pi-hole / SSH";
    actions.appendChild(sec);
    for (const [label, cmd] of [
      ["Open Pi-hole panel", null],
      ["pihole status", "pihole status"],
      ["Update gravity", "pihole -g"]
    ]) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", () => {
        go("pihole");
        if (cmd) runPiholeCmd(cmd);
      });
      actions.appendChild(b);
    }
  }
}

function closeDetail() {
  $("#detail").hidden = true;
  state.selectedMac = null;
  renderInventory();
  if (state.view === "topology") renderTopology();
}

function openCtx(x, y, d) {
  ctxEl.hidden = false;
  ctxEl.textContent = "";
  const items = [
    ["Open details", () => openDetail(d)],
    ["Rename…", () => renameDevicePrompt(d)],
    d.ip && (d.web_reachable || (d.web && d.web.reachable))
      ? ["Open admin page", () => openInAppBrowser("http://" + d.ip + "/")]
      : null,
    ["Copy IP", async () => { await navigator.clipboard.writeText(d.ip || ""); toast("IP copied"); }],
    ["Copy MAC", async () => { await navigator.clipboard.writeText(d.mac || ""); toast("MAC copied"); }],
    ["Record firmware…", async () => {
      const v = await askText({
        title: "Record firmware",
        hint: "Version from the device itself.",
        value: d.firmware_manual || d.firmware || "",
        multiline: false
      });
      if (v == null) return;
      await window.meshwatch.setFirmwareManual(d.mac, v.trim());
      d.firmware_manual = v.trim();
      toast("Firmware recorded");
      renderInventory();
    }],
    ["Block internet…", () => toast("Internet blocking is not available yet — it needs a live Pi-hole API connection.")],
    ["Add note…", async () => {
      const note = await askText({
        title: "Note for " + (d.name || d.ip || "device"),
        hint: "Saved on this PC only. Leave empty to clear.",
        value: d.note || "",
        multiline: true
      });
      if (note == null) return;
      await window.meshwatch.setNote(d.mac, note);
      d.note = note;
      toast(note.trim() ? "Note saved" : "Note cleared");
      await refreshDevice(d.mac);
    }]
  ].filter(Boolean);

  for (const [label, fn] of items) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    if (/Block/.test(label)) b.className = "danger";
    b.addEventListener("click", () => {
      hideCtx();
      fn();
    });
    ctxEl.appendChild(b);
  }
  ctxEl.style.left = Math.min(x, window.innerWidth - 240) + "px";
  ctxEl.style.top = Math.min(y, window.innerHeight - 220) + "px";
}

function hideCtx() {
  ctxEl.hidden = true;
}

async function renameDevicePrompt(d) {
  const current = d.nameOverride || d.name_override || d.name || "";
  const next = await askText({
    title: "Rename device",
    hint: "Leave empty and Save to clear a custom name and use discovery again.",
    value: current,
    multiline: false
  });
  if (next == null) return;
  const r = await window.meshwatch.renameDevice(d.mac, next);
  if (r && !r.ok) {
    toast(r.reason || "Rename failed");
    return;
  }
  toast(next.trim() ? "Renamed to " + next.trim() : "Custom name cleared");
  await refreshDevice(d.mac);
}

async function refreshDevice(mac) {
  await loadDevices();
  const updated = state.devices.find((x) => x.mac === mac);
  if (updated && state.selectedMac === mac) openDetail(updated);
  renderTopology();
}

function exportCsv() {
  const rows = [["Name", "IP", "MAC", "Vendor", "Type", "Firmware", "Risk", "Status", "Methods"]];
  for (const d of state.devices.slice().sort(ipSort)) {
    rows.push([
      d.name, d.ip, d.mac, d.vendor, d.type, firmwareOf(d), deviceRisk(d),
      isOnline(d) ? "online" : "not seen",
      (d.methods || []).join("+")
    ]);
  }
  const csv = rows.map((r) => r.map((c) => {
    const s = String(c == null ? "" : c);
    return /["',\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "meshwatch-inventory.csv";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Exported " + state.devices.length + " devices");
}

async function loadPreferences() {
  $("#pref-offline").checked = !!state.prefs.showOffline;
  $("#pref-autoscan").checked = !!state.prefs.autoScan;
  const avail = await window.meshwatch.credentials.available();
  $("#cred-status").textContent = avail
    ? "OS-backed encryption available. Passwords never leave this machine."
    : "OS encryption unavailable — credential vault disabled.";
  $("#cred-form").style.display = avail ? "" : "none";

  const pi = await updatePiholeNav();
  const panel = $("#pihole-prefs-panel");
  // Always show SSH prefs — port/user are needed before or without a live
  // discovery (this LAN uses a non-default SSH port).
  panel.hidden = false;
  $("#pref-ssh-port").value = (pi && pi.sshPort) || 22;
  $("#pref-ssh-user").value = (pi && pi.sshUser) || "admin";
  $("#pihole-host-value").textContent = pi && pi.ip
    ? ((pi.online ? "Online · " : "Last seen · ") + pi.ip + (pi.mac ? " · " + pi.mac : ""))
    : "Not remembered yet — run a scan";
  $("#pihole-host-note").textContent = pi && pi.remembered
    ? "Kept after the first discovery so the Pi-hole panel stays available offline."
    : (pi && pi.discovered ? "Detected on this network." : "Run a scan to remember the Pi-hole host.");

  const sel = $("#cred-mac");
  sel.textContent = "";
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = "Select device…";
  sel.appendChild(opt0);
  for (const d of state.devices.slice().sort(ipSort)) {
    const o = document.createElement("option");
    o.value = d.mac;
    o.textContent = (d.name || d.ip) + " — " + d.mac;
    sel.appendChild(o);
  }

  const list = await window.meshwatch.credentials.list();
  const box = $("#cred-list");
  box.textContent = "";
  if (!list.length) {
    box.innerHTML = '<p class="empty">No saved device logins yet.</p>';
    return;
  }
  for (const c of list) {
    const d = state.devices.find((x) => x.mac === c.mac);
    const row = document.createElement("div");
    row.className = "cred-item";
    row.innerHTML =
      "<div><strong>" + escapeHtml(c.label || (d && d.name) || c.mac) + "</strong>" +
      "<div class=\"muted\">" + escapeHtml((c.username || "(no user)") + " · " + c.mac) + "</div></div>";
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "Remove";
    rm.addEventListener("click", async () => {
      await window.meshwatch.credentials.remove(c.mac);
      toast("Credential removed");
      loadPreferences();
    });
    row.appendChild(rm);
    box.appendChild(row);
  }
}

async function refreshHeader() {
  try {
    const sub = await window.meshwatch.getSubnet();
    state.subnet = sub;
    const parts = [sub.cidr || "local network"];
    if (sub.localIp) parts.push("this PC " + sub.localIp);
    if (sub.iface) parts.push(sub.iface);
    $("#header-sub").textContent = parts.join(" · ");
    updateScanChrome();
  } catch (e) {
    $("#header-sub").textContent = "Local network";
  }
  try {
    $("#version").textContent = "v" + (await window.meshwatch.version());
  } catch (e) { /* ignore */ }
}

async function loadDevices() {
  state.devices = (await window.meshwatch.getDevices()) || [];
  for (const d of state.devices) {
    if (!d.methods && d.method) d.methods = String(d.method).split("+");
  }
  try { state.topology = (await window.meshwatch.getTopology()) || []; } catch (e) { state.topology = []; }
  try { state.drift = (await window.meshwatch.getDrift()) || []; } catch (e) { state.drift = []; }
  renderChips();
  renderInventory();
  renderOverview();
  renderTopology();
  updateScanChrome();
  await updatePiholeNav();
  if (state.devices.length) {
    setStatus(state.devices.length + " devices from last scan");
    $("#last-scan").textContent = state.devices[0].last_seen
      ? "Last seen " + new Date(state.devices[0].last_seen).toLocaleString()
      : "Devices on file";
  }
}

async function startScan() {
  const button = $("#scan");
  button.disabled = true;
  $("#rescan").disabled = true;
  logEl.textContent = "";
  closeDetail();
  state.scanning = true;
  state.scanProgress = 0;
  updateScanChrome();
  go("discovery");
  setStatus("Scanning…");
  $("#scan").textContent = "Scanning…";

  try {
    const devices = await window.meshwatch.scan();
    state.devices = devices || [];
    state.lastScanAt = Date.now();
    state.topology = (await window.meshwatch.getTopology()) || [];
    state.drift = (await window.meshwatch.getDrift()) || [];
    state.audit = null;
    state.scanProgress = 100;
    renderChips();
    renderInventory();
    renderOverview();
    renderTopology();
    $("#last-scan").textContent = "Last sweep just now";
    setStatus(state.devices.length + " devices found");
    line("Done — " + state.devices.length + " devices", "#d7d3d3");
    $("#scan-meta").innerHTML =
      "<span>" + state.devices.length + " responded</span>" +
      "<span>leases cross-checked against Pi-hole</span>" +
      "<span>" + escapeHtml((state.subnet && state.subnet.cidr) || "") + "</span>";
    toast(state.devices.length + " devices found");
    await updatePiholeNav();
  } catch (e) {
    line("Scan failed: " + e.message, "#ff563c");
    setStatus("Scan failed");
    toast("Scan failed");
  } finally {
    state.scanning = false;
    updateScanChrome();
    button.disabled = false;
    $("#rescan").disabled = false;
    $("#scan").textContent = "Scan network now";
  }
}

window.meshwatch.onScanProgress(({ stage, detail }) => {
  if (stage === "ping") {
    state.scanProgress = Math.round((detail.probed / detail.total) * 85);
    updateScanChrome();
    setStatus(
      "Probing " + detail.probed + " of " + detail.total +
      " on " + (detail.subnet || "LAN") + " — " + detail.found + " responded"
    );
    $("#scan-found").textContent = detail.found + " responded";
    $("#scan-meta").innerHTML =
      "<span>" + detail.probed + " / " + detail.total + " probed</span>" +
      "<span>" + detail.found + " responded</span>";
    return;
  }
  if (stage === "start") {
    line("Scanning " + (detail.subnet || "") + (detail.localIp ? " from " + detail.localIp : ""), "#d7d3d3");
    if (detail.subnet) {
      state.subnet = Object.assign({}, state.subnet || {}, { cidr: detail.subnet, localIp: detail.localIp, iface: detail.iface });
      $("#header-sub").textContent = detail.subnet + (detail.localIp ? " · this PC " + detail.localIp : "");
    }
    return;
  }
  if (stage === "done") state.scanProgress = 100;
  else if (stage === "webprobe") state.scanProgress = 90;
  else if (stage === "snmp") state.scanProgress = 95;
  else state.scanProgress = Math.min(88, state.scanProgress + 2);
  updateScanChrome();
  line("[" + stage + "] " + (detail.note || JSON.stringify(detail)));
});

$("#scan").addEventListener("click", () => startScan());
$("#rescan").addEventListener("click", () => startScan());
$("#inventory-filter").addEventListener("input", (e) => {
  state.query = e.target.value;
  renderInventory();
});
$("#run-audit").addEventListener("click", () => runAudit());
$("#detail-close").addEventListener("click", () => closeDetail());
$("#save-prefs").addEventListener("click", () => savePrefs());
$("#export-csv").addEventListener("click", () => exportCsv());
$("#pref-update").addEventListener("click", async () => {
  const r = await window.meshwatch.checkForUpdate();
  toast((r && r.message) || (r && r.state) || "Update check started");
});
$("#cred-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const mac = $("#cred-mac").value;
  const password = $("#cred-pass").value;
  if (!mac || !password) return;
  const r = await window.meshwatch.credentials.save(
    mac,
    $("#cred-label").value,
    $("#cred-user").value,
    password
  );
  if (r && r.ok) {
    toast("Credential saved");
    $("#cred-pass").value = "";
    loadPreferences();
  } else toast((r && r.reason) || "Save failed");
});

document.addEventListener("click", (e) => {
  if (!ctxEl.hidden && !ctxEl.contains(e.target)) hideCtx();
});

$$("#pihole-actions button").forEach((b) => {
  b.addEventListener("click", () => runPiholeCmd(b.dataset.cmd));
});
$("#pihole-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const cmd = $("#pihole-cmd").value.trim();
  if (cmd) runPiholeCmd(cmd);
});

if (window.meshwatch.onUpdateStatus) {
  window.meshwatch.onUpdateStatus((s) => {
    const el = $("#update-status");
    if (s.state === "available") el.textContent = "Update " + s.version + " available…";
    else if (s.state === "downloading") el.textContent = "Downloading update " + s.percent + "%";
    else if (s.state === "ready") el.textContent = "Update ready — restart to install";
    else if (s.state === "error") el.textContent = "Update check failed";
    else if (s.state === "current") el.textContent = "";
  });
}

function reportBrowserBounds() {
  const frame = $("#browser-frame");
  if (!frame || $("#browser").hidden) return;
  const r = frame.getBoundingClientRect();
  window.meshwatch.browser.setBounds({
    x: r.left,
    y: r.top,
    width: r.width,
    height: r.height
  });
}

async function openInAppBrowser(url) {
  const r = await window.meshwatch.browser.open(url);
  if (!r || !r.ok) {
    toast((r && r.reason) || "Could not open page");
    return;
  }
  $("#browser").hidden = false;
  $("#browser-url").value = url;
  $("#browser-title").textContent = "";
  hideCtx();
  closeDetail();
  requestAnimationFrame(() => reportBrowserBounds());
}

function closeInAppBrowser() {
  window.meshwatch.browser.close();
  $("#browser").hidden = true;
}

$("#browser-back").addEventListener("click", () => window.meshwatch.browser.back());
$("#browser-forward").addEventListener("click", () => window.meshwatch.browser.forward());
$("#browser-reload").addEventListener("click", () => window.meshwatch.browser.reload());
$("#browser-close").addEventListener("click", () => closeInAppBrowser());
window.addEventListener("resize", () => reportBrowserBounds());

window.meshwatch.browser.on("opened", ({ url }) => {
  $("#browser").hidden = false;
  $("#browser-url").value = url || "";
  reportBrowserBounds();
});
window.meshwatch.browser.on("closed", () => {
  $("#browser").hidden = true;
});
window.meshwatch.browser.on("navigated", ({ url }) => {
  $("#browser-url").value = url || "";
});
window.meshwatch.browser.on("title", ({ title }) => {
  $("#browser-title").textContent = title || "";
});
window.meshwatch.browser.on("loading", ({ loading }) => {
  $("#browser-reload").textContent = loading ? "…" : "↻";
});
window.meshwatch.browser.on("error", ({ desc }) => {
  toast("Page failed: " + (desc || "load error"));
});
window.meshwatch.browser.on("needBounds", () => reportBrowserBounds());

$("#pref-offline").checked = !!state.prefs.showOffline;
$("#pref-autoscan").checked = !!state.prefs.autoScan;

refreshHeader();
loadDevices().then(() => {
  if (state.prefs.autoScan) startScan();
});
window.meshwatch.versions().then((v) => {
  if (v && v.chrome) {
    const note = $("#cred-status");
    // Preferences shows vault status; Chromium version goes in header sub on demand via version badge title
    $("#version").title = "Chromium " + v.chrome + " · Electron " + v.electron + " · Node " + v.node;
  }
}).catch(() => {});
