// Meshwatch renderer — multi-view dashboard wired to preload IPC.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  view: "overview",
  devices: [],
  topology: [],
  audit: null,
  drift: [],
  subnet: null,
  selectedMac: null,
  filter: "",
  lastScanAt: null
};

const statusEl = $("#status");
const logEl = $("#log");
const ctxEl = $("#ctx");

function setStatus(text) {
  statusEl.textContent = text;
}

function line(text, color) {
  const div = document.createElement("div");
  div.textContent = text;
  if (color) div.style.color = color;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
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

function go(view) {
  state.view = view;
  $$(".nav").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + view));
  if (view === "topology") renderTopology();
  if (view === "audit" && !state.audit) runAudit();
  if (view === "pihole") loadPihole();
  hideCtx();
}

$$(".nav").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.view)));
$$("[data-goto]").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.goto)));

function filteredDevices() {
  const q = state.filter.trim().toLowerCase();
  const list = state.devices.slice().sort(ipSort);
  if (!q) return list;
  return list.filter((d) => {
    const hay = [d.name, d.ip, d.mac, d.vendor, d.model, d.type, (d.methods || []).join(" ")].join(" ").toLowerCase();
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
    tr.appendChild(nameCell);
    for (const v of [d.ip, d.mac, d.vendor || "—", roleLabel(d.type), (d.methods || d.method || "—")]) {
      const td = document.createElement("td");
      td.textContent = Array.isArray(v) ? v.join(", ") : (v == null || v === "" ? "—" : v);
      tr.appendChild(td);
    }
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
    td.colSpan = 6;
    td.className = "empty";
    td.textContent = state.devices.length ? "No devices match this filter." : "No devices yet — run a scan.";
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

function renderOverview() {
  const online = state.devices.length;
  const estimated = state.devices.filter((d) => d.estimated).length;
  const withWeb = state.devices.filter((d) => d.web_reachable || (d.web && d.web.reachable)).length;
  const gw = state.devices.find((d) => d.type === "gateway");

  $("#overview-stats").innerHTML = [
    ["Devices", online],
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
    $("#overview-score-note").textContent =
      (c.critical || 0) + " critical · " + (c.high || 0) + " high · " + (c.medium || 0) + " medium";
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

  function paint(nodes, isRoot) {
    const wrap = document.createElement("div");
    for (const n of nodes) {
      const node = document.createElement("div");
      node.className = "topo-node" + (isRoot ? " root" : "");
      const card = document.createElement("div");
      card.className = "topo-card";
      card.innerHTML =
        "<strong>" + escapeHtml(n.name || "Device") + "</strong>" +
        "<span>" + escapeHtml((n.ip || "") + (n.type ? " · " + roleLabel(n.type) : "")) + "</span>" +
        (n.estimated ? '<span class="est">link estimated</span>' : "");
      card.addEventListener("click", () => {
        const d = state.devices.find((x) => x.mac === n.mac);
        if (d) openDetail(d);
      });
      card.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        const d = state.devices.find((x) => x.mac === n.mac);
        if (d) openCtx(e.clientX, e.clientY, d);
      });
      node.appendChild(card);
      if (n.children && n.children.length) node.appendChild(paint(n.children, false));
      wrap.appendChild(node);
    }
    return wrap;
  }
  root.appendChild(paint(tree, true));
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
  const c = state.audit.counts || {};
  stats.innerHTML = [
    ["Score", state.audit.score],
    ["Critical", c.critical || 0],
    ["High", c.high || 0],
    ["Medium", c.medium || 0],
    ["Low", c.low || 0]
  ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");

  $("#badge-audit").textContent = (c.critical || 0) || "";

  for (const f of state.audit.findings || []) {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML =
      '<span class="sev ' + escapeHtml(f.severity) + '">' + escapeHtml(f.severity) + "</span>" +
      "<div><h3>" + escapeHtml(f.title) + "</h3>" +
      "<p>" + escapeHtml(f.detail || "") + "</p>" +
      '<span class="meta">' + escapeHtml([f.device, f.ip, f.reference].filter(Boolean).join(" · ")) + "</span>" +
      (f.action ? "<p><strong>Action:</strong> " + escapeHtml(f.action) + "</p>" : "") +
      (f.estimated ? '<span class="est">estimate</span>' : "") +
      "</div>";
    box.appendChild(div);
  }
}

async function runAudit() {
  setStatus("Running audit…");
  try {
    state.audit = await window.meshwatch.getAudit();
    renderAudit();
    renderOverview();
    setStatus("Audit complete — score " + state.audit.score);
  } catch (e) {
    setStatus("Audit failed: " + e.message);
  }
}

async function loadPihole() {
  const stats = $("#pihole-stats");
  try {
    const s = await window.meshwatch.pihole.stats();
    if (!s || s.available === false) {
      stats.innerHTML = '<div class="stat"><div class="n">—</div><div class="l">API not connected yet</div></div>';
      $("#pihole-out").textContent = (s && s.reason) || "Phase 2 will wire the Pi-hole API token and SSH key.";
      return;
    }
    stats.innerHTML = [
      ["Queries today", s.queriesToday],
      ["Blocked", s.blockedToday],
      ["Blocked %", s.blockedPercent],
      ["Blocklist", s.blocklistSize]
    ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n == null ? "—" : n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");
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
      return;
    }
    out.textContent = "$ " + command + "\n" + (r.output || []).join("\n");
  } catch (e) {
    out.textContent = "Error: " + e.message;
  }
}

function openDetail(d) {
  state.selectedMac = d.mac;
  renderInventory();
  const el = $("#detail");
  el.hidden = false;
  $("#detail-name").textContent = d.name || "Device";
  const webReach = d.web_reachable || (d.web && d.web.reachable);
  const webTitle = d.web_title || (d.web && d.web.title);
  const rows = [
    ["IP", d.ip],
    ["MAC", d.mac],
    ["Vendor", d.vendor],
    ["Model", d.model],
    ["Type", roleLabel(d.type)],
    ["Control", d.control],
    ["Matched by", d.matched_by || d.matchedBy],
    ["Web title", webTitle],
    ["Login page", webReach ? (d.web_login_form || (d.web && d.web.hasLoginForm) ? "yes" : "open") : "no"],
    ["Found via", Array.isArray(d.methods) ? d.methods.join(", ") : d.method],
    ["Note", d.note],
    ["First seen", d.first_seen ? new Date(d.first_seen).toLocaleString() : null],
    ["Last seen", d.last_seen ? new Date(d.last_seen).toLocaleString() : null]
  ];
  $("#detail-body").innerHTML =
    "<dl>" +
    rows
      .filter(([, v]) => v != null && v !== "" && v !== "—")
      .map(([k, v]) => "<dt>" + escapeHtml(k) + "</dt><dd>" + escapeHtml(String(v)) + "</dd>")
      .join("") +
    "</dl>" +
    (d.estimated ? '<p class="est">Identity not confirmed — label is an estimate.</p>' : "");

  const actions = $("#detail-actions");
  actions.textContent = "";
  if (webReach && d.ip) {
    const open = document.createElement("button");
    open.type = "button";
    open.textContent = "Open admin page";
    open.addEventListener("click", () => window.meshwatch.openExternal("http://" + d.ip + "/"));
    actions.appendChild(open);
  }
  const noteBtn = document.createElement("button");
  noteBtn.type = "button";
  noteBtn.textContent = "Add note";
  noteBtn.addEventListener("click", async () => {
    const note = window.prompt("Note for " + (d.name || d.ip), d.note || "");
    if (note == null) return;
    await window.meshwatch.setNote(d.mac, note);
    d.note = note;
    openDetail(d);
  });
  actions.appendChild(noteBtn);
}

function closeDetail() {
  $("#detail").hidden = true;
  state.selectedMac = null;
  renderInventory();
}

function openCtx(x, y, d) {
  ctxEl.hidden = false;
  ctxEl.textContent = "";
  const items = [
    ["Open details", () => openDetail(d)],
    d.ip && (d.web_reachable || (d.web && d.web.reachable))
      ? ["Open admin page", () => window.meshwatch.openExternal("http://" + d.ip + "/")]
      : null,
    ["Copy IP", () => navigator.clipboard.writeText(d.ip || "")],
    ["Copy MAC", () => navigator.clipboard.writeText(d.mac || "")],
    ["Add note…", async () => {
      const note = window.prompt("Note for " + (d.name || d.ip), d.note || "");
      if (note == null) return;
      await window.meshwatch.setNote(d.mac, note);
      d.note = note;
    }]
  ].filter(Boolean);

  for (const [label, fn] of items) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", () => {
      hideCtx();
      fn();
    });
    ctxEl.appendChild(b);
  }
  const pad = 8;
  ctxEl.style.left = Math.min(x, window.innerWidth - 220) + "px";
  ctxEl.style.top = Math.min(y, window.innerHeight - 160) + "px";
  void pad;
}

function hideCtx() {
  ctxEl.hidden = true;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function refreshHeader() {
  try {
    const sub = await window.meshwatch.getSubnet();
    state.subnet = sub;
    const parts = [sub.cidr || "local network"];
    if (sub.localIp) parts.push("this PC " + sub.localIp);
    if (sub.iface) parts.push(sub.iface);
    $("#header-sub").textContent = parts.join(" · ");
  } catch (e) {
    $("#header-sub").textContent = "Local network";
  }
  try {
    const v = await window.meshwatch.version();
    $("#version").textContent = "v" + v;
  } catch (e) { /* ignore */ }
}

async function loadDevices() {
  state.devices = (await window.meshwatch.getDevices()) || [];
  // Normalize methods from last sighting if missing on row
  for (const d of state.devices) {
    if (!d.methods && d.method) d.methods = String(d.method).split("+");
  }
  try {
    state.topology = (await window.meshwatch.getTopology()) || [];
  } catch (e) {
    state.topology = [];
  }
  try {
    state.drift = (await window.meshwatch.getDrift()) || [];
  } catch (e) {
    state.drift = [];
  }
  renderInventory();
  renderOverview();
  renderTopology();
  if (state.devices.length) {
    setStatus(state.devices.length + " devices from last scan");
    $("#last-scan").textContent = state.devices[0].last_seen
      ? "Last seen " + new Date(state.devices[0].last_seen).toLocaleString()
      : "Devices on file";
  }
}

window.meshwatch.onScanProgress(({ stage, detail }) => {
  if (stage === "ping") {
    setStatus(
      "Probing " + detail.probed + " of " + detail.total +
      " on " + (detail.subnet || "LAN") + " — " + detail.found + " responded"
    );
    return;
  }
  if (stage === "start") {
    line("Scanning " + (detail.subnet || "") + (detail.localIp ? " from " + detail.localIp : ""), "#d7d3d3");
    if (detail.subnet) $("#header-sub").textContent = detail.subnet + (detail.localIp ? " · this PC " + detail.localIp : "");
    return;
  }
  line("[" + stage + "] " + (detail.note || JSON.stringify(detail)));
});

$("#scan").addEventListener("click", async () => {
  const button = $("#scan");
  button.disabled = true;
  logEl.textContent = "";
  closeDetail();
  go("overview");
  setStatus("Scanning…");
  try {
    const devices = await window.meshwatch.scan();
    state.devices = devices || [];
    state.lastScanAt = Date.now();
    state.topology = (await window.meshwatch.getTopology()) || [];
    state.drift = (await window.meshwatch.getDrift()) || [];
    state.audit = null;
    renderInventory();
    renderOverview();
    renderTopology();
    $("#last-scan").textContent = "Last sweep just now";
    setStatus(state.devices.length + " devices found");
    line("Done — " + state.devices.length + " devices", "#d7d3d3");
  } catch (e) {
    line("Scan failed: " + e.message, "#ff563c");
    setStatus("Scan failed");
  } finally {
    button.disabled = false;
  }
});

$("#inventory-filter").addEventListener("input", (e) => {
  state.filter = e.target.value;
  renderInventory();
});

$("#run-audit").addEventListener("click", () => runAudit());
$("#detail-close").addEventListener("click", () => closeDetail());
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

refreshHeader();
loadDevices();
