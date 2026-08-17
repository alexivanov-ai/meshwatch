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
  tagChip: null,
  lastScanAt: null,
  scanning: false,
  scanProgress: 0,
  auditFilter: "all",
  piStats: null,
  prefs: loadPrefs()
};

const statusEl = $("#status");
const logEl = $("#log");
const ctxEl = $("#ctx");
let toastTimer = null;

function loadPrefs() {
  try {
    return Object.assign(
      { showOffline: true, autoScan: false, theme: "system" },
      JSON.parse(localStorage.getItem(PREFS_KEY) || "{}")
    );
  } catch (e) {
    return { showOffline: true, autoScan: false, theme: "system" };
  }
}

function resolveTheme(pref) {
  const mode = pref || "system";
  if (mode === "light" || mode === "dark") return mode;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(pref) {
  const choice = pref || (state.prefs && state.prefs.theme) || "system";
  const resolved = resolveTheme(choice);
  document.documentElement.dataset.theme = resolved;
  if (window.meshwatch && window.meshwatch.setTheme) {
    window.meshwatch.setTheme(choice).catch(() => {});
  }
  return resolved;
}

let sshSaveToastAt = 0;

async function saveSshPrefs(opts) {
  const quiet = !!(opts && opts.quiet);
  const portEl = $("#pref-ssh-port");
  const userEl = $("#pref-ssh-user");
  if (!portEl || !userEl) return { ok: false, reason: "SSH fields missing" };
  const sshPort = portEl.value;
  const sshUser = userEl.value;
  try {
    const r = await window.meshwatch.pi.setPrefs({ sshPort, sshUser });
    if (r && !r.ok) {
      if (!quiet) toast(r.reason || "Could not save SSH settings");
      return r;
    }
    if (r && r.state) state.pi = r.state;
    if (!quiet) {
      const now = Date.now();
      if (now - sshSaveToastAt > 800) {
        sshSaveToastAt = now;
        toast("SSH port and username saved");
      }
    }
    return r || { ok: true };
  } catch (e) {
    if (!quiet) toast("Could not save SSH settings: " + ((e && e.message) || e));
    return { ok: false, reason: (e && e.message) || String(e) };
  }
}

async function savePrefs() {
  state.prefs.showOffline = $("#pref-offline").checked;
  state.prefs.autoScan = $("#pref-autoscan").checked;
  state.prefs.theme = $("#pref-theme").value || "system";
  state.prefs.scanIntervalMin = Number($("#pref-interval").value || 15);
  state.prefs.notifyNewDevice = $("#pref-notify").checked;
  state.prefs.startWithSystem = $("#pref-startup").checked;
  state.prefs.deepPortScan = $("#pref-ports").value || "weekly";
  state.prefs.firmwareSync = $("#pref-firmware").checked;
  localStorage.setItem(PREFS_KEY, JSON.stringify(state.prefs));
  applyTheme(state.prefs.theme);
  window.meshwatch.prefs.set(state.prefs).catch(() => {});
  const ssh = await saveSshPrefs({ quiet: true });
  if (ssh && ssh.ok === false) {
    toast(ssh.reason || "Could not save SSH settings");
    return;
  }
  toast("Preferences saved");
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

// Yes/No confirmation reusing the same modal chrome as askText, since this
// app has no separate confirm dialog and native window.confirm() would look
// out of place next to it. The textarea is hidden for the duration (and
// given a non-empty sentinel value) so clicking the existing OK button
// resolves truthy; Cancel/backdrop/click-away still resolve via the normal
// closeModal(null) paths. Restores the input and button label afterward so
// the next askText() call is unaffected.
function askConfirm({ title, hint, okLabel }) {
  return new Promise((resolve) => {
    if (modalResolver) modalResolver(null);
    $("#modal-title").textContent = title || "Are you sure?";
    const hintEl = $("#modal-hint");
    hintEl.textContent = hint || "";
    hintEl.hidden = !hint;
    const input = $("#modal-input");
    input.hidden = true;
    input.value = "confirm";
    const okBtn = $("#modal-ok");
    okBtn.textContent = okLabel || "Continue";
    modalResolver = (result) => {
      input.hidden = false;
      input.value = "";
      okBtn.textContent = "Save";
      resolve(result != null);
    };
    $("#modal").hidden = false;
    requestAnimationFrame(() => okBtn.focus());
  });
}

$("#modal-cancel").addEventListener("click", () => closeModal(null));
$("#modal-ok").addEventListener("click", () => closeModal($("#modal-input").value));
// Escape is bound to the modal container, not the textarea: askConfirm()
// hides the textarea, so a handler on it never sees the key and Escape did
// nothing while a confirmation (including the credential-overwrite one) was
// up. The container is focusable-through — keydown bubbles from whatever
// inside it has focus (the textarea, or the OK button in confirm mode).
$("#modal").addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    e.preventDefault();
    closeModal(null);
  }
});
$("#modal-input").addEventListener("keydown", (e) => {
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

const TAG_COLOR_COUNT = 4; // keep in sync with .topo-dot.tag-0..3 in styles.css

function hashString(s) {
  let h = 0;
  const str = String(s || "");
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
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
    "dns-dhcp": "DNS / DHCP",
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
  if (state.view === "pi" && view !== "pi") stopTerminal();
  state.view = view;
  $$(".nav").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + view));
  if (view === "topology") renderTopology();
  if (view === "audit" && !state.audit) runAudit();
  if (view === "pi") loadPi();
  if (view === "preferences") loadPreferences();
  if (view === "discovery") updateScanChrome();
  hideCtx();
  // Device panel stays open while switching rows in Inventory or Topology;
  // close it when leaving for any other left-nav view.
  if (view !== "inventory" && view !== "topology") closeDetail();
}

function updatePiTabVisibility() {
  const nav = $("#nav-pi");
  const discovered = !!(state.pi && state.pi.discovered);
  if (nav) nav.hidden = !discovered;
  if (!discovered && state.view === "pi") go("overview");
}

async function updatePiNav() {
  let st = { discovered: false };
  try {
    st = await window.meshwatch.pi.state();
  } catch (e) { /* ignore */ }
  state.pi = st;
  updatePiTabVisibility();
  return st;
}

$$(".nav").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.view)));
$$("[data-goto]").forEach((btn) => btn.addEventListener("click", () => go(btn.dataset.goto)));

const CHIPS = ["All", "TP-Link", "Infrastructure", "Needs update", "No API", "Clients"];

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

function renderTagChips() {
  const row = $("#inventory-tag-chips");
  if (!row) return;
  row.textContent = "";
  const tags = Array.from(new Set(
    state.devices.flatMap((d) => (d.tags || []))
  )).sort((a, b) => a.localeCompare(b));
  row.hidden = !tags.length;
  if (state.tagChip && tags.indexOf(state.tagChip) === -1) state.tagChip = null;
  for (const t of tags) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chip" + (state.tagChip === t ? " on" : "");
    b.textContent = t;
    b.addEventListener("click", () => {
      state.tagChip = state.tagChip === t ? null : t;
      renderTagChips();
      renderInventory();
    });
    row.appendChild(b);
  }
}

function isInfra(d) {
  return ["gateway", "switch", "access-point", "extender", "dns-dhcp", "legacy-router"].indexOf(d.type) !== -1;
}

function filteredDevices() {
  const q = state.query.trim().toLowerCase();
  let list = state.devices.slice().sort(ipSort);

  if (!state.prefs.showOffline) list = list.filter(isOnline);

  if (state.chip === "TP-Link") list = list.filter((d) => d.control === "tplink" || /tp-?link/i.test(d.vendor || ""));
  else if (state.chip === "Infrastructure") list = list.filter(isInfra);
  else if (state.chip === "Needs update") {
    list = list.filter((d) => {
      const r = deviceRisk(d);
      return r === "critical" || r === "high";
    });
  } else if (state.chip === "No API") list = list.filter((d) => d.estimated || d.control === "none");
  else if (state.chip === "Clients") list = list.filter((d) => !isInfra(d));

  if (state.tagChip) list = list.filter((d) => d.tags && d.tags.includes(state.tagChip));

  if (!q) return list;
  return list.filter((d) => {
    const hay = [d.name, d.ip, d.mac, d.vendor, d.model, d.type, firmwareOf(d), (d.methods || []).join(" ")].join(" ").toLowerCase();
    return hay.indexOf(q) !== -1;
  });
}

function stackedTd(main, sub) {
  const td = document.createElement("td");
  td.innerHTML = '<span class="cell-main">' + escapeHtml(main || "—") + '</span><span class="cell-sub">' + escapeHtml(sub || "—") + "</span>";
  return td;
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

    const online = isOnline(d);
    const nameTd = document.createElement("td");
    nameTd.innerHTML =
      '<span class="device-cell"><span class="status-dot' + (online ? "" : " off") + '"></span><span>' +
      '<span class="cell-main">' + escapeHtml(d.name || "Unidentified host") + "</span>" +
      '<span class="cell-sub">' + escapeHtml(d.vendor || "—") +
      (d.estimated ? " · estimate" : "") +
      ((d.nameOverride || d.name_override) ? " · renamed" : "") +
      "</span></span></span>";
    tr.appendChild(nameTd);

    const risk = deviceRisk(d);
    const control = d.control === "tplink" ? "Local API" : (d.control === "ssh" ? "SSH" : (d.control === "readonly" ? "Read only" : (d.estimated ? "No API" : "View")));
    tr.appendChild(stackedTd(roleLabel(d.type), control));
    tr.appendChild(stackedTd(d.ip, d.mac));
    tr.appendChild(stackedTd(parentName(d) || "—", d.link || (online ? "—" : "off")));
    tr.appendChild(stackedTd(firmwareOf(d), d.firmware_source || d.firmwareSource || "—"));

    const riskTd = document.createElement("td");
    riskTd.innerHTML = '<span class="risk ' + risk + '">' + risk + "</span>";
    tr.appendChild(riskTd);

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
  const online = state.devices.filter(isOnline).length;
  const offline = Math.max(0, state.devices.length - online);
  const navOn = $("#nav-online");
  const navOff = $("#nav-offline");
  if (navOn) navOn.textContent = online + " online";
  if (navOff) navOff.textContent = offline + " off";

  const findings = (state.audit && state.audit.findings) || [];
  const behind = state.devices.filter((d) => {
    const fw = firmwareOf(d);
    const latest = d.firmware_latest || d.firmwareLatest;
    return (latest && fw && fw !== "—" && fw !== latest) || d.estimated;
  }).length;
  const crit = findings.filter((f) => f.severity === "critical").length;
  const dns = state.piStats && state.piStats.blockedPercent != null
    ? Math.round(state.piStats.blockedPercent) + "%"
    : "—";

  $("#overview-stats").innerHTML = [
    ["Devices seen", state.devices.length, online + " responding now"],
    ["Behind or unverifiable", behind, "no firmware API or behind"],
    ["Critical findings", crit, "need action"],
    ["DNS queries blocked", dns, state.piStats && state.piStats.blockedToday != null ? state.piStats.blockedToday + " today" : "when a DNS service is connected"]
  ].map(([l, n, note]) => '<div class="stat"><div class="l">' + escapeHtml(l) + '</div><div class="n">' + escapeHtml(String(n)) + '</div><div class="cell-sub">' + escapeHtml(note) + "</div></div>").join("");

  const attn = $("#overview-attention");
  attn.textContent = "";
  const top = findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  const drift = state.drift || [];

  if (!top.length && !drift.length) {
    attn.innerHTML = '<p class="empty">Nothing urgent. Run Security audit after a scan.</p>';
  } else {
    for (const f of top) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "attention-btn";
      btn.innerHTML =
        '<span class="attention-mark"></span><span><span class="cell-main">' + escapeHtml(f.device || "Device") + "</span>" +
        '<span class="cell-sub">' + escapeHtml(f.title) + "</span></span>" +
        '<span class="risk ' + escapeHtml(f.severity) + '">' + escapeHtml(f.severity) + "</span>";
      btn.addEventListener("click", () => {
        const d = state.devices.find((x) => x.mac === f.mac);
        go("inventory");
        if (d) openDetail(d);
      });
      attn.appendChild(btn);
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

  const talkersEl = $("#overview-talkers");
  const talkerTrendEl = $("#overview-talker-trend");
  const talkers = (state.piStats && state.piStats.talkers) || [];
  if (talkersEl) {
    if (!talkers.length) {
      talkersEl.innerHTML = '<p class="empty">Connect your DNS service in Preferences to see who is querying DNS.</p>';
      if (talkerTrendEl) talkerTrendEl.innerHTML = "";
    } else {
      const max = Math.max.apply(null, talkers.map((t) => Number(t.queries) || 0)) || 1;
      talkersEl.innerHTML = talkers.slice(0, 5).map((t) => {
        const w = Math.round((Number(t.queries) || 0) / max * 100);
        // Only offer the trend click on rows we can actually key history by.
        // Pi-hole v5 (legacy) talkers have no `ip` field - leave those as
        // plain, non-interactive rows rather than imply a feature that
        // can't work for them (clicking would silently do nothing).
        const clickable = t.ip ? " talker-clickable" : "";
        const ipAttr = t.ip ? ' data-ip="' + escapeHtml(t.ip) + '" data-name="' + escapeHtml(t.name || t.ip || "host") + '"' : "";
        return '<div class="talker' + clickable + '"' + ipAttr +
          '><div class="talker-top"><span class="talker-name">' + escapeHtml(t.name || t.ip || "host") +
          '</span><span class="talker-amt">' + escapeHtml(String(t.queries)) + ' queries</span></div>' +
          '<div class="talker-track"><div class="talker-fill" style="width:' + w + '%"></div></div></div>';
      }).join("");
      if (talkerTrendEl) talkerTrendEl.innerHTML = "";
      $$(".talker-clickable", talkersEl).forEach((row) => row.addEventListener("click", () => showTalkerTrend(row.dataset.ip, row.dataset.name)));
    }
  }

  const nodesEl = $("#overview-nodes");
  const nodes = state.devices.filter(isInfra).map((d) => ({
    name: d.name,
    n: childCount(d.mac),
    est: d.estimated
  })).filter((n) => n.n > 0).sort((a, b) => b.n - a.n);
  if (nodesEl) {
    if (!nodes.length) {
      nodesEl.innerHTML = '<p class="empty">Run a scan. Counts come from who hangs off whom.</p>';
    } else {
      nodesEl.innerHTML = nodes.slice(0, 6).map((n) =>
        '<div class="node-row"><span>' + escapeHtml(n.name) + "</span><span>" + n.n + " client" + (n.n === 1 ? "" : "s") +
        (n.est ? " · est." : "") + "</span></div>"
      ).join("");
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

  renderLatencySparklines().catch(() => {});
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

    const firstTag = row.device.tags && row.device.tags[0];
    const dot = document.createElement("span");
    dot.className = "topo-dot" +
      (row.online ? "" : " off") +
      (row.risk === "critical" || row.risk === "high" ? " risk" : "") +
      (firstTag ? " tag-" + (hashString(firstTag) % TAG_COLOR_COUNT) : "");
    if (firstTag) dot.title = "Tag: " + firstTag;

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

async function blockDevice(d, blocked) {
  const r = await window.meshwatch.pi.block(d.mac, blocked);
  if (r && r.ok) {
    d.blocked = blocked;
    // Name the mechanism the backend actually reported (`ftl-group`,
    // `adguard-access-list`, …) rather than asserting a product.
    toast(blocked
      ? (d.name + " blocked at the DNS service" + (r.via ? " (" + r.via + ")" : ""))
      : (d.name + " unblocked"));
    return true;
  }
  toast((r && r.reason) || "Could not change blocking");
  return false;
}

async function runFindingAction(mac, action) {
  const d = state.devices.find((x) => x.mac === mac);
  const act = String(action || "");
  if (/block internet/i.test(act) && d) return blockDevice(d, true);
  if (/update firmware/i.test(act) && d && d.ip) {
    const r = await window.meshwatch.tplink.action(d.ip, "firmwareUpdate", {});
    if (r && r.adminPage && !r.ok) {
      toast((r.reason || "Not available") + " — opening admin");
      return openInAppBrowser(r.adminPage);
    }
    toast((r && r.reason) || (r && r.ok ? "Update requested" : "Could not update"));
    return;
  }
  if (/open device|record the version/i.test(act) && d) {
    go("inventory");
    return openDetail(d);
  }
  if (/fallback dns/i.test(act)) {
    toast("Set a secondary DNS on the gateway admin page — Meshwatch will not change WAN DNS without you looking.");
    if (d && d.ip) openInAppBrowser("http://" + d.ip + "/");
    return;
  }
  if (/retire/i.test(act) && d) {
    go("inventory");
    return openDetail(d);
  }
  toast(act);
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
    const actionBtn = !showingDismissed && f.action
      ? '<button type="button" class="primary-inline finding-act" data-mac="' + escapeHtml(f.mac || "") + '" data-action="' + escapeHtml(f.action) + '">' + escapeHtml(f.action) + "</button>"
      : "";
    const openBtn = f.mac
      ? '<button type="button" class="secondary finding-open" data-mac="' + escapeHtml(f.mac || "") + '">Open device</button>'
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
      '<div class="finding-actions">' + actionBtn + openBtn + dismissBtn + "</div>";
    box.appendChild(div);
  }
  $$(".finding-act", box).forEach((b) => {
    b.addEventListener("click", () => runFindingAction(b.dataset.mac, b.dataset.action));
  });
  $$(".finding-open", box).forEach((b) => {
    b.addEventListener("click", () => {
      const d = state.devices.find((x) => x.mac === b.dataset.mac);
      go("inventory");
      if (d) openDetail(d);
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
    renderAuditTrend();
    setStatus("Audit complete — score " + state.audit.score);
    toast("Audit score " + state.audit.score);
  } catch (e) {
    setStatus("Audit failed: " + e.message);
  }
}

async function loadPi() {
  try {
    const backendInfo = await window.meshwatch.pi.backend();
    $("#pi-backend-name").textContent = backendInfo
      ? backendInfo.name + (backendInfo.version ? " " + backendInfo.version : "")
      : "No DNS service detected";
    const target = await window.meshwatch.pi.target();
    const hostLine = target && target.host
      ? target.host + " · SSH " + target.user + "@" + target.host + ":" + target.port
      : "No host remembered yet";
    $("#pi-host-line").textContent = hostLine;
    $("#pi-ssh-target").textContent = hostLine;

    $("#pi-open-admin").onclick = () => target.host && openInAppBrowser("http://" + target.host + "/");
    const logBtn = $("#pi-open-log");
    logBtn.hidden = !(backendInfo && backendInfo.name === "AdGuard Home");
    logBtn.onclick = () => target.host && openInAppBrowser("http://" + target.host + "/#logs?response_status=all");

    const s = await window.meshwatch.pi.stats();
    state.piStats = s && s.available ? s : null;
    // pi.backend() reports the version the LAST stats() call saw rather than
    // running a second login + fetch of its own, so fill it in from this one.
    if (backendInfo && s && s.available && s.firmware) {
      $("#pi-backend-name").textContent = backendInfo.name + " " + s.firmware;
    }
    renderOverview();

    const statsEl = $("#pi-stats");
    if (s && s.available) {
      statsEl.innerHTML = [
        ["Queries today", s.queriesToday],
        ["Blocked today", s.blockedToday],
        ["Blocked %", s.blockedPercent != null ? s.blockedPercent + "%" : "—"],
        ["Blocklist size", s.blocklist || "—"]
      ].map(([l, n]) => '<div class="stat"><div class="n">' + escapeHtml(String(n == null ? "—" : n)) + '</div><div class="l">' + escapeHtml(l) + "</div></div>").join("");
    } else {
      statsEl.innerHTML = '<div class="empty">' + escapeHtml((s && s.reason) || "DNS stats unavailable") + "</div>";
    }

    const blockedEl = $("#pi-dns-blocked");
    const hasBlocked = !!(s && s.blocked && s.blocked.length);
    blockedEl.classList.toggle("empty", !hasBlocked);
    blockedEl.innerHTML = hasBlocked
      ? s.blocked.map((b) => '<div class="blocked-row"><span>' + escapeHtml(b.domain) + "</span><span>" + escapeHtml(String(b.hits)) + "</span></div>").join("")
      : "No blocked-domain data yet.";

    const leases = await window.meshwatch.pi.leases();
    const leasesEl = $("#pi-leases");
    const hasLeases = !!(leases && leases.length);
    leasesEl.classList.toggle("empty", !hasLeases);
    leasesEl.innerHTML = hasLeases
      ? leases.map((l) =>
        '<div class="lease-row"><span>' + escapeHtml(l.hostname || l.ip) +
        ' <span class="cell-sub">' + escapeHtml(l.ip || "") + "</span></span><span>" +
        escapeHtml(l.expires || "—") + "</span></div>"
      ).join("")
      : "No DHCP leases available from this backend.";

    const host = await window.meshwatch.pi.hostStats();
    const hostEl = $("#pi-host");
    hostEl.classList.toggle("empty", !host.uptime);
    hostEl.textContent = host.uptime
      ? "Up " + host.uptime + " · disk " + (host.diskUsedPercent != null ? host.diskUsedPercent + "%" : "—") +
        " (" + (host.diskUsed || "?") + " / " + (host.diskTotal || "?") + ") · " +
        (host.cpuCores || "?") + " cores · load " + (host.loadAvg || "—")
      : "Could not read host stats over SSH yet.";
    const reboot = await window.meshwatch.pi.rebootRequired();
    $("#pi-reboot-banner").hidden = !reboot;

    const apps = await window.meshwatch.pi.installedApps();
    const appsEl = $("#pi-apps");
    const hasApps = !!(apps.ok && apps.apps.length);
    appsEl.classList.toggle("empty", !hasApps);
    appsEl.innerHTML = hasApps
      ? apps.apps.map((a) => '<div class="node-row"><span>' + escapeHtml(a.name) + "</span></div>").join("")
      : escapeHtml(apps.ok ? "No manually-installed apps found." : (apps.reason || "Could not read installed apps."));

    // Only ever open an SSH shell while the Pi tab is the visible view. This
    // function is also reached from Preferences (after saving an API
    // password), and used to be reached from every scan completion — both of
    // which would silently hold an interactive shell open to the Pi for the
    // rest of the process lifetime, since stopTerminal() only fires when
    // navigating AWAY from a Pi tab the user may never have opened.
    if (state.view === "pi") loadPiTerminalTarget();
    loadPiServices();
  } catch (e) {
    $("#pi-stats").innerHTML = '<div class="empty">' + escapeHtml(e.message) + "</div>";
  }
}

let term = null;
let fitAddon = null;
let termSessionId = null;
// Unsubscribe functions for the three pi:term:* listeners, so the renderer
// can drop them when it goes away instead of leaving them registered.
let termUnsubscribers = [];

function startTerminal() {
  if (term) return;
  term = new window.Terminal({ convertEol: true, cursorBlink: true, fontSize: 13 });
  fitAddon = new window.FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($("#pi-term"));
  fitAddon.fit();

  termUnsubscribers = [
    window.meshwatch.terminal.onStarted(({ sessionId }) => { termSessionId = sessionId; }),
    window.meshwatch.terminal.onData(({ sessionId, chunk }) => { if (sessionId === termSessionId) term.write(chunk); }),
    window.meshwatch.terminal.onClosed(({ sessionId, error }) => {
      if (sessionId !== termSessionId) return;
      term.write("\r\n[connection closed" + (error ? ": " + error : "") + "]\r\n");
      termSessionId = null;
    })
  ].filter((fn) => typeof fn === "function");
  term.onData((data) => { if (termSessionId) window.meshwatch.terminal.input(termSessionId, data); });
  term.onResize(({ rows, cols }) => { if (termSessionId) window.meshwatch.terminal.resize(termSessionId, rows, cols); });

  window.meshwatch.terminal.start(term.rows, term.cols);
  window.addEventListener("resize", () => fitAddon && fitAddon.fit());
}

// Ends the backend SSH session but keeps the xterm.js instance and its
// listeners — loadPiTerminalTarget() starts a fresh session in the same
// instance when the Pi tab is opened again.
function stopTerminal() {
  if (termSessionId) window.meshwatch.terminal.stop(termSessionId);
  termSessionId = null;
}

// Full teardown, for when this renderer itself is going away (window closed,
// reload): stop the session AND drop the IPC listeners.
function teardownTerminal() {
  stopTerminal();
  for (const off of termUnsubscribers) {
    try { off(); } catch (e) { /* ignore */ }
  }
  termUnsubscribers = [];
}

window.addEventListener("pagehide", () => teardownTerminal());

function loadPiTerminalTarget() {
  // Called from loadPi() each time the Pi tab is opened.
  if (!term) { startTerminal(); return; }
  // The xterm.js UI instance survives tab switches (so we never spawn a
  // second visible terminal), but go() stops the backend SSH session when
  // navigating away. If there's no live session, start a fresh one in the
  // same terminal instance rather than leaving a dead prompt on return —
  // the onStarted/onData/onClosed listeners are already wired from the
  // first startTerminal() call and just pick up the new session id.
  if (!termSessionId) {
    term.reset();
    window.meshwatch.terminal.start(term.rows, term.cols);
  }
}

async function loadPiServices() {
  const list = await window.meshwatch.pi.servicesList();
  renderPiServices(list);
}

function renderPiServices(list) {
  const el = $("#pi-services");
  el.classList.toggle("empty", !list.length);
  el.innerHTML = list.length
    ? "<ul>" + list.map((s) =>
        "<li>" + escapeHtml(s.name) + (s.name === "Unknown service" ? ' <span class="est">estimate</span>' : "") +
        " · port " + escapeHtml(String(s.port)) + (s.title ? " · " + escapeHtml(s.title) : "") +
        ' <button type="button" class="pi-svc-open" data-url="' + escapeHtml(s.url) + '">Open</button></li>'
      ).join("") + "</ul>"
    : "No extra services detected yet.";
  $$(".pi-svc-open", el).forEach((b) => b.addEventListener("click", () => openInAppBrowser(b.dataset.url)));
}

$("#pi-rescan-services").addEventListener("click", async () => {
  toast("Rescanning services…");
  const list = await window.meshwatch.pi.servicesRescan();
  renderPiServices(list);
  toast(list.length + " service(s) found");
});

const piServicesToggle = $("#pi-services-toggle");
if (piServicesToggle) {
  piServicesToggle.addEventListener("click", () => {
    const body = $("#pi-services-body");
    const collapsed = body.hidden;
    body.hidden = !collapsed;
    piServicesToggle.textContent = collapsed ? "Collapse" : "Expand";
    piServicesToggle.setAttribute("aria-expanded", String(collapsed));
  });
}

$("#pi-apt-check").addEventListener("click", async () => {
  const resultEl = $("#pi-apt-result");
  resultEl.classList.remove("empty");
  resultEl.textContent = "Checking…";
  const r = await window.meshwatch.pi.aptCheck();
  resultEl.innerHTML = r.ok
    ? (r.count ? r.count + " package(s) upgradable: " + r.packages.map((p) => escapeHtml(p.name)).join(", ") : "Everything is up to date.")
    : escapeHtml(r.reason || "Check failed");
});

$("#pi-apt-upgrade").addEventListener("click", async () => {
  const r = await window.meshwatch.pi.aptUpgrade();
  if (r && r.cancelled) return toast("Cancelled");
  $("#pi-out").textContent = (r.output || []).join("\n");
  toast(r.code ? "Upgrade finished with errors — see output below" : "Upgrade complete");
  loadPi();
});

async function runPiCmd(command) {
  const out = $("#pi-out");
  out.textContent = "$ " + command + "\n…";
  try {
    const r = await window.meshwatch.pi.exec(command);
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

// Inline SVG line sparkline, no charting library. `points` is an array of
// objects with an `onlineRatio` property in 0..1 — that exact property name,
// nothing else is read. Callers plotting something else (audit score, ping
// latency, per-client query counts) normalize to 0..1 and map into
// `onlineRatio` before calling; keep this contract stable, all four do it.
function sparklineSvg(points) {
  const w = 140, h = 24, step = w / Math.max(1, points.length - 1);
  const path = points.map((p, i) => (i === 0 ? "M" : "L") + (i * step).toFixed(1) + "," + (h - p.onlineRatio * h).toFixed(1)).join(" ");
  return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + " " + h + '"><path d="' + path + '" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>';
}

// Posture-score trend line in the Security view. sparklineSvg() reads each
// point's `onlineRatio` (0..1), so a score out of 100 is mapped down to that
// range — a raw `score` property would render a blank line.
async function renderAuditTrend() {
  const el = $("#audit-trend");
  if (!el) return;
  const history = await window.meshwatch.auditHistory(30);
  const points = (history || []).map((h) => ({ onlineRatio: h.score / 100 }));
  el.innerHTML = points.length > 1 ? "Score trend " + sparklineSvg(points) : "";
}

// Overview sparkline for gateway ping latency — rough "closer to 0ms = closer
// to 1.0" normalization (capped at 0 for anything >=100ms) so it can reuse
// sparklineSvg()'s onlineRatio-shaped points, same as the audit-score trend.
async function renderLatencySparklines() {
  const gw = await window.meshwatch.latencyHistory("gateway", 50);
  const points = (gw || []).filter((s) => s.ms != null).map((s) => ({ onlineRatio: Math.max(0, 1 - s.ms / 100) }));
  const el = $("#overview-latency");
  if (el) el.innerHTML = points.length > 1 ? "Gateway latency " + sparklineSvg(points) : "";
}

// Per-client DNS query trend, shown on demand when a Top DNS clients row is
// clicked (rather than for every client at once, which would be noisy).
// Points are normalized against the max queries seen in the fetched window,
// same onlineRatio-shaped-point contract as sparklineSvg()'s other callers.
// This is a query-count trend, not a bandwidth/traffic measure — the label
// below makes that explicit so it can't be mistaken for actual throughput.
async function showTalkerTrend(clientIp, clientName) {
  const el = $("#overview-talker-trend");
  if (!el || !clientIp) return;
  el.innerHTML = '<p class="muted">Loading trend…</p>';
  const history = await window.meshwatch.talkerHistory(clientIp, 20);
  if (!history || history.length < 2) {
    el.innerHTML = '<p class="muted">Not enough history yet for ' + escapeHtml(clientName || clientIp) + '.</p>';
    return;
  }
  const max = Math.max(1, ...history.map((h) => Number(h.queries) || 0));
  const points = history.map((h) => ({ onlineRatio: Math.min(1, (Number(h.queries) || 0) / max) }));
  el.innerHTML = '<div class="talker-trend-head">' + escapeHtml(clientName || clientIp) + " trend " + sparklineSvg(points) + "</div>" +
    '<p class="muted talker-trend-note">DNS queries, not bandwidth.</p>';
}

async function renderUptimeSparkline(d) {
  const history = await window.meshwatch.uptimeHistory(d.mac, 14);
  const holder = document.createElement("div");
  holder.className = "detail-section";
  holder.innerHTML = "Online history (14d) " + sparklineSvg(history);
  $("#detail-body").appendChild(holder);
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

  if (d.services && d.services.length) {
    const svcSec = document.createElement("div");
    svcSec.className = "detail-section";
    svcSec.innerHTML = "Advertises: " + d.services.map((s) => '<span class="chip">' + escapeHtml(s.type) + "</span>").join(" ");
    $("#detail-body").appendChild(svcSec);
  }

  const actions = $("#detail-actions");
  actions.textContent = "";

  const primary = document.createElement("button");
  primary.type = "button";
  primary.className = "primary-inline";
  if (behind) {
    primary.textContent = "Update firmware to " + fwLatest;
    primary.addEventListener("click", async () => {
      const r = await window.meshwatch.tplink.action(d.ip, "firmwareUpdate", {});
      if (r && r.cancelled) return toast("Cancelled");
      if (r && r.ok) return toast("Firmware update requested");
      if (r && r.adminPage) {
        toast((r.reason || "Not available") + " — opening admin in Meshwatch");
        openInAppBrowser(r.adminPage);
      } else toast((r && r.reason) || "Firmware update is not available from Meshwatch");
    });
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
  block.textContent = d.blocked ? "Allow internet access" : "Block internet access";
  block.addEventListener("click", () => blockDevice(d, !d.blocked));
  actions.appendChild(block);

  const watchBtn = document.createElement("button");
  watchBtn.type = "button";
  watchBtn.textContent = d.watched ? "Stop watching join/leave" : "Alert when it joins or leaves";
  watchBtn.addEventListener("click", async () => {
    const next = !d.watched;
    await window.meshwatch.watchDevice(d.mac, next);
    d.watched = next;
    toast(next ? "Watching " + (d.name || d.ip) : "Stopped watching");
    openDetail(d);
  });
  actions.appendChild(watchBtn);

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

  const tagSec = document.createElement("div");
  tagSec.className = "detail-section";
  tagSec.innerHTML = "Tags: " + ((d.tags || []).length
    ? (d.tags || []).map((t) => '<span class="chip">' + escapeHtml(t) + "</span>").join(" ")
    : '<span class="chip">None</span>');
  actions.appendChild(tagSec);
  const tagBtn = document.createElement("button");
  tagBtn.type = "button";
  tagBtn.textContent = "Edit tags";
  tagBtn.addEventListener("click", async () => {
    const v = await askText({
      title: "Tags for " + (d.name || d.ip),
      hint: "Comma-separated, your own words",
      value: (d.tags || []).join(", "),
      multiline: false
    });
    if (v == null) return;
    const tags = v.split(",").map((t) => t.trim()).filter(Boolean);
    await window.meshwatch.setDeviceTags(d.mac, tags);
    d.tags = tags;
    toast("Tags saved");
    renderTagChips();
    openDetail(d);
  });
  actions.appendChild(tagBtn);

  if (d.mac) {
    const wakeBtn = document.createElement("button");
    wakeBtn.type = "button";
    wakeBtn.textContent = "Wake device (WoL)";
    wakeBtn.title = "Only works if Wake-on-LAN is enabled in this device's own BIOS/OS — Meshwatch can't verify that remotely.";
    wakeBtn.addEventListener("click", async () => {
      const r = await window.meshwatch.wakeDevice(d.mac);
      toast(r.ok ? "Magic packet sent" : "Could not send: " + (r.reason || "unknown error"));
    });
    actions.appendChild(wakeBtn);
  }

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
        } else if (r && r.ok) toast(r.note ? (label + " — " + r.note) : (label + " ok"));
        else toast((r && r.reason) || "This control action is not available yet");
      });
      actions.appendChild(b);
    }
  }

  if (d.type === "dns-dhcp" || d.control === "ssh") {
    const sec = document.createElement("div");
    sec.className = "detail-section";
    sec.textContent = "Pi · SSH";
    actions.appendChild(sec);
    const openPi = document.createElement("button");
    openPi.type = "button";
    openPi.textContent = "Open Pi panel";
    openPi.addEventListener("click", () => go("pi"));
    actions.appendChild(openPi);
  }

  renderUptimeSparkline(d);
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
    ["Block internet…", () => blockDevice(d, true)],
    [d.watched ? "Stop watching…" : "Alert when it joins or leaves", async () => {
      const next = !d.watched;
      await window.meshwatch.watchDevice(d.mac, next);
      d.watched = next;
      toast(next ? "Watching " + (d.name || d.ip) : "Stopped watching");
    }],
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
  try {
    const remote = await window.meshwatch.prefs.get();
    if (remote) state.prefs = Object.assign(state.prefs, remote);
  } catch (e) { /* local copy is fine */ }
  $("#pref-offline").checked = !!state.prefs.showOffline;
  $("#pref-autoscan").checked = !!state.prefs.autoScan;
  $("#pref-theme").value = state.prefs.theme || "system";
  if ($("#pref-interval")) $("#pref-interval").value = String(state.prefs.scanIntervalMin == null ? 15 : state.prefs.scanIntervalMin);
  if ($("#pref-notify")) $("#pref-notify").checked = state.prefs.notifyNewDevice !== false;
  if ($("#pref-startup")) $("#pref-startup").checked = !!state.prefs.startWithSystem;
  if ($("#pref-ports")) $("#pref-ports").value = state.prefs.deepPortScan || "weekly";
  if ($("#pref-firmware")) $("#pref-firmware").checked = state.prefs.firmwareSync !== false;
  const avail = await window.meshwatch.credentials.available();
  $("#cred-status").textContent = avail
    ? "OS-backed encryption available. Passwords never leave this machine."
    : "OS encryption unavailable — credential vault disabled.";
  $("#cred-form").style.display = avail ? "" : "none";

  const pi = await updatePiNav();
  const panel = $("#pi-prefs-panel");
  // Always show SSH prefs — port/user are needed before or without a live
  // discovery (this LAN uses a non-default SSH port).
  panel.hidden = false;
  if (pi && pi.sshPort != null && pi.sshPort !== "") $("#pref-ssh-port").value = String(pi.sshPort);
  if (pi && pi.sshUser) $("#pref-ssh-user").value = pi.sshUser;
  $("#pi-host-value").textContent = pi && pi.ip
    ? ((pi.online ? "Online · " : "Last seen · ") + pi.ip + (pi.mac ? " · " + pi.mac : ""))
    : "Not remembered yet — run a scan";
  $("#pi-host-note").textContent = pi && pi.remembered
    ? "Kept after the first discovery so the Pi panel stays available offline."
    : (pi && pi.discovered ? "Detected on this network." : "Run a scan to remember the Pi host.");
  try {
    const has = await window.meshwatch.pi.hasPassword();
    $("#pi-api-note").textContent = has
      ? "API password is saved on this PC."
      : "DNS service API password — a Pi-hole 5 auth token, a Pi-hole 6 app password, or the AdGuard Home admin password. Stored with OS encryption.";
  } catch (e) { /* ignore */ }
  if (pi && pi.keyPath) {
    $("#pi-key-note").textContent = "Using " + pi.keyPath;
  }

  const list = await window.meshwatch.credentials.list();
  state.credentials = list || [];
  const piMac = pi && pi.mac;

  const sel = $("#cred-mac");
  sel.textContent = "";
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = "Select device…";
  sel.appendChild(opt0);
  for (const d of state.devices.slice().sort(ipSort)) {
    const o = document.createElement("option");
    o.value = d.mac;
    if (piMac && d.mac === piMac) {
      // The Pi's login slot in this vault is the live SSH credential used by
      // the embedded terminal and pi:exec — never an ordinary-looking option
      // a user could mistake for "save my AdGuard/Pi-hole password here".
      const hasCred = state.credentials.some((c) => c.mac === piMac);
      o.textContent = (d.name || d.ip) + " — Raspberry Pi: SSH login" +
        (hasCred ? " (already saved — see Pi tab)" : " (used by the Pi tab, not a general login)");
    } else {
      o.textContent = (d.name || d.ip) + " — " + d.mac;
    }
    sel.appendChild(o);
  }

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
  renderTagChips();
  renderInventory();
  renderOverview();
  renderTopology();
  updateScanChrome();
  await updatePiNav();
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
      "<span>DHCP leases cross-checked</span>" +
      "<span>" + escapeHtml((state.subnet && state.subnet.cidr) || "") + "</span>";
    toast(state.devices.length + " devices found");
    await updatePiNav();
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
$("#pref-backup").addEventListener("click", async () => {
  try {
    const r = await window.meshwatch.db.backup($("#pref-backup-creds").checked);
    if (r && r.ok) toast("Backup saved to " + r.path);
    else if (!r || !r.cancelled) toast("Backup failed");
  } catch (e) {
    toast("Backup failed: " + (e.message || e));
  }
});
$("#pref-restore").addEventListener("click", async () => {
  try {
    const r = await window.meshwatch.db.restore();
    // On success the app relaunches before this ever resolves. Only a
    // cancel/failure comes back here.
    if (r && !r.ok && !r.cancelled) toast(r.reason || "Restore failed");
  } catch (e) {
    toast("Restore failed — your data was not changed: " + (e.message || e));
  }
});
$("#pref-update").addEventListener("click", async () => {
  const r = await window.meshwatch.checkForUpdate();
  toast((r && r.message) || (r && r.state) || "Update check started");
});
$("#cred-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const mac = $("#cred-mac").value;
  const password = $("#cred-pass").value;
  if (!mac || !password) return;

  // The vault stores exactly one credential per MAC — saving here silently
  // overwrites whatever is already there (see the Pi's SSH-login mix-up).
  // Warn before destroying an existing saved login.
  const existing = (state.credentials || []).find((c) => c.mac === mac);
  if (existing) {
    const device = state.devices.find((d) => d.mac === mac);
    const existingLabel = existing.label || (device && device.name) || mac;
    const proceed = await askConfirm({
      title: "Replace saved login?",
      hint: "This device already has a saved login (\"" + existingLabel + "\"). " +
        "Saving a new one will replace it — anything relying on the old credential " +
        "(like SSH) will stop working. Continue?",
      okLabel: "Replace it"
    });
    if (!proceed) return;
  }

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

$("#pi-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const cmd = $("#pi-cmd").value.trim();
  if (cmd) runPiCmd(cmd);
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
$("#pref-theme").value = state.prefs.theme || "system";
applyTheme(state.prefs.theme);

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if ((state.prefs.theme || "system") === "system") applyTheme("system");
});

$("#pref-theme").addEventListener("change", () => {
  state.prefs.theme = $("#pref-theme").value || "system";
  localStorage.setItem(PREFS_KEY, JSON.stringify(state.prefs));
  applyTheme(state.prefs.theme);
});

const sshForm = $("#pi-ssh-form");
if (sshForm) {
  sshForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    await saveSshPrefs();
  });
}
["pref-ssh-port", "pref-ssh-user"].forEach((id) => {
  const el = $("#" + id);
  if (el) el.addEventListener("change", () => { saveSshPrefs(); });
});

const apiForm = $("#pi-api-form");
if (apiForm) {
  apiForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    await saveSshPrefs({ quiet: true });
    const password = $("#pref-pi-api").value;
    const r = await window.meshwatch.pi.setPassword(password);
    if (r && r.ok) {
      $("#pref-pi-api").value = "";
      toast("DNS service API password saved");
      loadPreferences();
      loadPi();
    } else toast((r && r.reason) || "Could not save API password");
  });
}
const keyBtn = $("#pref-ssh-key");
if (keyBtn) {
  keyBtn.addEventListener("click", async () => {
    const r = await window.meshwatch.pi.pickKey();
    if (r && r.ok) {
      toast("Using SSH key " + r.path);
      loadPreferences();
    } else if (!r || !r.cancelled) toast("No key selected");
  });
}

refreshHeader();
loadDevices().then(async () => {
  try {
    const remote = await window.meshwatch.prefs.get();
    if (remote) state.prefs = Object.assign(state.prefs, remote);
  } catch (e) { /* ignore */ }
  try {
    state.piStats = await window.meshwatch.pi.stats();
    if (state.piStats && state.piStats.available === false) state.piStats = null;
  } catch (e) { state.piStats = null; }
  renderOverview();
  if (state.prefs.autoScan) startScan();
});
if (window.meshwatch.onScanFinished) {
  window.meshwatch.onScanFinished(() => {
    loadDevices();
    // Only refresh the Pi tab when it's the view actually on screen. A full
    // loadPi() is expensive (backend probes, an API login, DHCP leases and
    // five separate SSH connections) and used to run on EVERY scan
    // completion — including the startup scan and every interval-timer
    // sweep — even when the Pi tab had never been opened. go("pi") already
    // calls loadPi(), so the tab refreshes when the user actually goes there.
    if (state.view === "pi") loadPi();
  });
}
window.meshwatch.versions().then((v) => {
  if (v && v.chrome) {
    $("#version").title = "Chromium " + v.chrome + " · Electron " + v.electron + " · Node " + v.node;
  }
}).catch(() => {});
