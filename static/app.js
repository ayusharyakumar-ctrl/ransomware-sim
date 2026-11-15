// ===== Ransomware Simulation & Detection System - dashboard logic =====
// Every number shown on this page comes from the Flask backend (no fake data).

const $ = (id) => document.getElementById(id);

// ---- per-browser session (each visitor gets their own sandbox folder) ----
function newId() {
  const a = new Uint8Array(12); crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
let SID;
try { SID = localStorage.getItem("rsds_sid") || newId(); localStorage.setItem("rsds_sid", SID); }
catch { SID = newId(); }

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Session-Id": SID, ...(opts.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
const postJSON = (path, body = {}) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtSize = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const levelColor = (lvl) => ({ SAFE: "#22c55e", WARNING: "#f59e0b", CRITICAL: "#ef4444" }[lvl] || "#22c55e");
const statusColor = (s) => ({ Normal: "#22c55e", Elevated: "#f59e0b", Critical: "#ef4444", High: "#ef4444" }[s] || "#22c55e");

function setStatus(msg) { $("status").textContent = msg; }

// ---------------- workflow steps ----------------
const STEP_ORDER = ["load", "simulate", "monitor", "detect", "alert", "display"];
function setSteps(activeUpTo, running) {
  const idx = STEP_ORDER.indexOf(activeUpTo);
  document.querySelectorAll(".step").forEach((el) => {
    const i = STEP_ORDER.indexOf(el.dataset.step);
    el.classList.toggle("active", i <= idx);
    el.classList.toggle("running", el.dataset.step === running);
  });
}

// ---------------- files ----------------
function renderFiles(files) {
  $("fileCount").textContent = `${files.length} file${files.length === 1 ? "" : "s"} in sandbox`;
  $("fileList").innerHTML = files.length
    ? files.map((f) => { const note = /readme|restore|decrypt|ransom/i.test(f.name) && f.name.endsWith(".txt");
        return `<li class="${f.name.endsWith(".locked") || note ? "locked" : ""}">
        <span class="fname">${f.name.endsWith(".locked") ? "🔒 " : note ? "💀 " : "📄 "}${esc(f.name)}</span>
        <span class="fmeta">${fmtSize(f.size)} · H=${f.entropy.toFixed(2)}</span></li>`; }).join("")
    : '<li class="muted">No files loaded yet</li>';
  if (files.length) setSteps("load");
}

async function refresh() {
  try { renderFiles((await api("/api/state")).files); } catch (e) { setStatus(e.message); }
  loadHistory();
}

async function uploadFiles(fileList) {
  if (!fileList.length) return;
  const fd = new FormData();
  [...fileList].forEach((f) => fd.append("files", f));
  setStatus(`Uploading ${fileList.length} file(s) to sandbox…`);
  try {
    const r = await api("/api/upload", { method: "POST", body: fd });
    renderFiles(r.files);
    setStatus(`✔ ${r.saved.length} file(s) copied into the sandbox. Choose a scenario and press Start Analysis.`);
  } catch (e) { setStatus("✖ " + e.message); }
}

const dz = $("dropzone");
$("fileInput").addEventListener("change", (e) => { uploadFiles(e.target.files); e.target.value = ""; });
["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("drop", (e) => uploadFiles(e.dataTransfer.files));

$("sampleBtn").addEventListener("click", async () => {
  try {
    const r = await api("/api/samples", { method: "POST" });
    renderFiles(r.files);
    setStatus(`✔ Loaded ${r.saved.length} sample files (text, CSV, JSON, Markdown, PNG).`);
  } catch (e) { setStatus("✖ " + e.message); }
});

// ---------------- simulation ----------------
let busy = false;
$("startBtn").addEventListener("click", async () => {
  if (busy) return;
  const mode = document.querySelector('input[name="mode"]:checked').value;
  busy = true; toggleButtons(true);
  resetResults();
  try {
    setSteps("load", "simulate"); setStatus("Running simulation inside the sandbox…");
    const req = postJSON("/api/simulate", { mode });
    await sleep(350); setSteps("simulate", "monitor"); setStatus("Monitoring file-system events with watchdog…");
    const r = await req;
    setSteps("monitor", "detect"); setStatus("Detection engine evaluating behaviour…");
    await sleep(300); renderMetrics(r.detection.metrics); drawCharts(r);
    setSteps("detect", "alert"); renderDetection(r);
    await sleep(250); renderAlerts(r.alerts);
    setSteps("alert", "display"); renderLogs(r.logs); renderResults(r.records); renderFiles(r.files);
    await sleep(200); setSteps("display");
    setStatus(`✔ Done in ${r.detection.metrics.duration_s}s · ${r.mode_label} → ${r.final_level}`);
    loadHistory();
  } catch (e) {
    setStatus("✖ " + e.message); setSteps("load");
  } finally { busy = false; toggleButtons(false); }
});

function toggleButtons(dis) { ["startBtn", "restoreBtn", "resetBtn", "sampleBtn"].forEach((id) => ($(id).disabled = dis)); }

$("restoreBtn").addEventListener("click", async () => {
  try {
    const r = await api("/api/restore", { method: "POST" });
    renderFiles(r.files);
    setStatus(r.restored ? `↺ Restored ${r.restored} file(s): decrypted and renamed back.` : "Nothing to restore.");
  } catch (e) { setStatus("✖ " + e.message); }
});

$("resetBtn").addEventListener("click", async () => {
  try {
    await api("/api/reset", { method: "POST" });
    renderFiles([]); resetResults(); setSteps(null);
    setStatus("Sandbox cleared.");
  } catch (e) { setStatus("✖ " + e.message); }
});

$("exportBtn").addEventListener("click", () => { window.location = `/api/logs/export?sid=${SID}`; });
$("pdfBtn").addEventListener("click", async () => {
  const res = await fetch(`/api/report.pdf?sid=${SID}`);
  if (!res.ok) { setStatus("✖ " + ((await res.json().catch(() => ({}))).error || "Run a simulation first")); return; }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a"); a.href = url; a.download = "incident_report.pdf"; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});

// ---------------- rendering ----------------
function setBar(id, pct, color) { const b = $(id); b.style.width = Math.max(0, Math.min(100, pct)) + "%"; b.style.background = color; }
function setBadge(id, text) { const b = $(id); b.textContent = text; b.className = "badge " + text; }

function renderMetrics(m) {
  $("monSource").textContent = `· ${m.events_captured} events via ${m.metrics_source}`;
  $("renameVal").textContent = `${m.rename_rate}%`;
  $("renameSub").textContent = `${m.files_renamed} of ${m.total_files} files renamed`;
  setBar("renameBar", m.rename_rate, statusColor(m.rename_status)); setBadge("renameBadge", m.rename_status);

  $("entropyVal").textContent = `${m.entropy_after.toFixed(2)} / 8`;
  $("entropySub").textContent = `avg before ${m.entropy_before.toFixed(2)} → after ${m.entropy_after.toFixed(2)}`;
  setBar("entropyBar", (m.entropy_after / 8) * 100, statusColor(m.entropy_status)); setBadge("entropyBadge", m.entropy_status);

  $("speedVal").textContent = `${m.speed} files/min`;
  $("speedSub").textContent = `${m.files_touched} file(s) changed in ${m.duration_s}s`;
  setBar("speedBar", Math.min(100, (m.speed / 600) * 100), statusColor(m.speed_status)); setBadge("speedBadge", m.speed_status);
}

function renderDetection(r) {
  const d = r.detection, lvl = r.final_level;
  $("scoreVal").textContent = d.threat_score;
  setBar("scoreBar", d.threat_score, levelColor(lvl));
  setBadge("levelBadge", lvl);
  $("threatBox").className = "threat " + lvl;
  $("verdict").textContent = d.verdict + (lvl !== d.threat_level ? " (escalated by ML model)" : "");
  $("patterns").innerHTML = d.patterns.length
    ? d.patterns.map((p) => `<li class="${p.severity}"><div>${esc(p.name)}<small>${esc(p.detail)}</small></div><span class="pts">+${p.points}</span></li>`).join("")
    : '<li class="muted">No suspicious patterns</li>';

  const p = Math.round(r.ml.probability * 100);
  const ring = $("mlRing");
  ring.style.setProperty("--p", p);
  ring.style.setProperty("--c", p >= 80 ? "#ef4444" : p >= 50 ? "#f59e0b" : "#22c55e");
  $("mlProb").textContent = p + "%";
  $("mlLabel").textContent = r.ml.label === "ransomware" ? "Classified as RANSOMWARE" : "Classified as BENIGN";
}

function renderAlerts(alerts) {
  $("alertCount").textContent = alerts.length ? `(${alerts.length})` : "";
  $("alerts").innerHTML = alerts.length
    ? alerts.map((a) => `<li class="${a.severity}"><b>${a.severity === "critical" ? "🚨" : "⚠️"} ${esc(a.title)}</b><small>${a.time} · ${esc(a.detail)}</small></li>`).join("")
    : '<li class="muted">✅ No alerts. Activity looks normal.</li>';
}

function renderLogs(logs) {
  $("logs").innerHTML = logs.map((l) => `<div class="l lv-${l.level}">[${l.time}] ${l.level.padEnd(8)} ${esc(l.message)}</div>`).join("");
  $("logs").scrollTop = $("logs").scrollHeight;
}

function renderResults(records) {
  $("resultTable").querySelector("tbody").innerHTML = records.length
    ? records.map((r) => `<tr><td>${esc(r.original)}</td><td>${esc(r.final)}</td><td>${esc(r.action)}</td>
        <td>${r.entropy_before.toFixed(2)} → <b style="color:${r.entropy_after >= 7.5 && r.content_changed ? "#f87171" : "inherit"}">${r.entropy_after.toFixed(2)}</b></td></tr>`).join("")
    : '<tr><td colspan="4" class="muted">No files were touched</td></tr>';
}

async function loadHistory() {
  try {
    const rows = await api("/api/history");
    $("historyTable").querySelector("tbody").innerHTML = rows.length
      ? rows.map((h) => `<tr><td>${h.time.slice(11)}</td><td>${h.mode}</td><td>${h.files}</td><td>${h.score}</td>
          <td>${Math.round(h.ml_probability * 100)}%</td><td><em class="badge ${h.level}">${h.level}</em></td></tr>`).join("")
      : '<tr><td colspan="6" class="muted">No runs yet</td></tr>';
  } catch { /* ignore */ }
}

function resetResults() {
  ["renameBar", "entropyBar", "speedBar", "scoreBar"].forEach((id) => setBar(id, 0, "#22c55e"));
  $("scoreVal").textContent = "0"; setBadge("levelBadge", "IDLE"); $("threatBox").className = "threat";
  $("verdict").textContent = "Analysing…";
}

// ---------------- charts ----------------
Chart.defaults.color = "#8193b2"; Chart.defaults.borderColor = "#1f2a44";
Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, Inter, sans-serif";
let entropyChart, timelineChart, fiChart;

function drawCharts(r) {
  const labels = r.records.map((x) => x.original.length > 14 ? x.original.slice(0, 13) + "…" : x.original);
  entropyChart?.destroy();
  entropyChart = new Chart($("entropyChart"), {
    type: "bar",
    data: { labels, datasets: [
      { label: "Before", data: r.records.map((x) => x.entropy_before), backgroundColor: "#3b82f6" },
      { label: "After", data: r.records.map((x) => x.entropy_after), backgroundColor: r.records.map((x) => (x.entropy_after >= 7.5 && x.content_changed ? "#ef4444" : "#22c55e")) },
    ] },
    options: { responsive: true, scales: { y: { min: 0, max: 8, title: { display: true, text: "bits / byte" } } },
      plugins: { legend: { labels: { boxWidth: 10 } } } },
  });

  const kinds = { modified: "#a855f7", renamed: "#f97316", created: "#06b6d4", deleted: "#ef4444" };
  timelineChart?.destroy();
  timelineChart = new Chart($("timelineChart"), {
    type: "scatter",
    data: { datasets: Object.entries(kinds).map(([k, c]) => ({
      label: k, backgroundColor: c, pointRadius: 5,
      data: r.timeline.filter((e) => e.event === k).map((e) => ({ x: e.t, y: Object.keys(kinds).indexOf(k) + 1, f: e.file })),
    })) },
    options: { responsive: true,
      scales: { x: { title: { display: true, text: "seconds since start" }, min: 0 },
                y: { min: 0, max: 5, ticks: { stepSize: 1, callback: (v) => Object.keys(kinds)[v - 1] || "" } } },
      plugins: { legend: { labels: { boxWidth: 10 } },
        tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${c.raw.f} @ ${c.raw.x}s` } } } },
  });
}

async function loadModelInfo() {
  try {
    const m = await api("/api/ml");
    $("mlAcc").textContent = `Model accuracy: ${(m.accuracy * 100).toFixed(1)}% on ${m.test_samples} test samples`;
    $("mlRules").textContent = m.rules;
    $("cmpTable").querySelector("tbody").innerHTML = (m.comparison || []).map((c) =>
      `<tr${c.model === "Decision Tree" ? ' style="color:#c4b5fd;font-weight:600"' : ""}><td>${c.model}${c.model === "Decision Tree" ? " ✓" : ""}</td>
       <td>${(c.accuracy * 100).toFixed(1)}%</td><td>${(c.precision * 100).toFixed(1)}%</td>
       <td>${(c.recall * 100).toFixed(1)}%</td><td>${(c.f1 * 100).toFixed(1)}%</td></tr>`).join("");
    const fi = Object.entries(m.feature_importance).sort((a, b) => b[1] - a[1]);
    fiChart?.destroy();
    fiChart = new Chart($("fiChart"), {
      type: "bar",
      data: { labels: fi.map((x) => x[0]), datasets: [{ label: "Feature importance", data: fi.map((x) => x[1]), backgroundColor: "#a855f7" }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { min: 0, max: 1 } } },
    });
  } catch { $("mlAcc").textContent = "Model info unavailable"; }
}

// ---------------- URL checker ----------------
$("urlForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = $("urlInput").value.trim();
  if (!url) return;
  try {
    const r = await postJSON("/api/check-url", { url });
    const card = `<div class="url-card" style="border-left-color:${levelColor(r.level)}">
      <div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(r.verdict)}</b><em class="badge ${r.level}">${r.level} · ${r.score}</em></div>
      <div class="u">${esc(r.url)}</div>
      ${r.findings.length ? `<ul>${r.findings.map((f) => `<li><b>${esc(f.name)}</b> (+${f.points}): ${esc(f.detail)}</li>`).join("")}</ul>` : ""}
    </div>`;
    $("urlResults").insertAdjacentHTML("afterbegin", card);
    $("urlInput").value = "";
  } catch (err) { setStatus("✖ " + err.message); }
});

refresh();
loadModelInfo();
