// Phase 0 renderer. Deliberately minimal - phase 5 rebuilds this to match
// prototype.html. It exists so that npm start shows something real and proves
// the IPC bridge works end to end.

const $ = (sel) => document.querySelector(sel);
const status = $("#status");
const log = $("#log");
const tbody = $("#devices tbody");

function line(text) {
  const div = document.createElement("div");
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

window.meshwatch.onScanProgress(({ stage, detail }) => {
  if (stage === "ping") {
    status.textContent = "Probing " + detail.probed + " of " + detail.total + " - " + detail.found + " responded";
    return;
  }
  line("[" + stage + "] " + (detail.note || JSON.stringify(detail)));
});

$("#scan").addEventListener("click", async () => {
  const button = $("#scan");
  button.disabled = true;
  log.textContent = "";
  tbody.textContent = "";
  status.textContent = "Scanning...";

  try {
    const devices = await window.meshwatch.scan();
    render(devices);
    status.textContent = devices.length + " devices found";
  } catch (e) {
    line("Scan failed: " + e.message);
    status.textContent = "Scan failed";
  } finally {
    button.disabled = false;
  }
});

function render(devices) {
  const sorted = devices.slice().sort((a, b) => {
    const na = Number(String(a.ip).split(".")[3] || 0);
    const nb = Number(String(b.ip).split(".")[3] || 0);
    return na - nb;
  });
  for (const d of sorted) {
    const tr = document.createElement("tr");
    for (const v of [d.ip, d.mac, d.name, d.vendor || "-", (d.methods || []).join(", ")]) {
      const td = document.createElement("td");
      td.textContent = v == null ? "-" : v;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

// Show anything already in the database from a previous run.
window.meshwatch.getDevices().then(devices => {
  if (devices && devices.length) {
    render(devices);
    status.textContent = devices.length + " devices from the last scan";
  }
});
