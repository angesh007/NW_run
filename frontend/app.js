const API = (path) => `http://localhost:8000${path}`;

function setCard(id, value, suffix = "") {
  document.getElementById(id).textContent = value + (suffix || "");
}

function pct(v) {
  return (v !== null && v !== undefined) ? `${v.toFixed(2)}%` : "—";
}

async function loadSummary() {
  const res = await fetch(API("/api/summary"));
  const j = await res.json();
  setCard("activeThreats", j.active_threats);
  setCard("activeThreatsChange", `${j.active_threats_change_pct >= 0 ? "↑" : "↓"} ${pct(Math.abs(j.active_threats_change_pct))}`);
  setCard("modelAccuracy", pct(j.model_accuracy));
  setCard("accuracyTrend", `${j.model_accuracy_trend_pct >= 0 ? "↑" : "↓"} ${pct(Math.abs(j.model_accuracy_trend_pct))} this week`);
  setCard("dataCoverage", pct(j.data_coverage_pct));
  setCard("dataVolume", `${j.data_volume_tb_today.toFixed(3)} TB processed today`);
  setCard("responseTime", `${j.avg_response_time_sec.toFixed(2)}s`);
  setCard("autoRem", j.auto_remediation_enabled ? "Auto-remediation: ON" : "Auto-remediation: OFF");
}

async function loadHeatmap() {
  const res = await fetch(API("/api/heatmap"));
  const j = await res.json();
  const map = j.tactics || {};
  const container = document.getElementById("heatmap");
  container.innerHTML = "";
  const entries = Object.entries(map).sort((a, b) => a[0].localeCompare(b[0]));
  const max = Math.max(1, ...entries.map(([_, v]) => Number(v) || 0));
  entries.forEach(([name, raw]) => {
    const val = Number(raw) || 0;
    const cell = document.createElement("div");
    const intensity = val / max;
    cell.className = "cell";
    cell.style.backgroundColor = `rgba(255,0,0,${0.1 + 0.7 * intensity})`;
    cell.title = `${name}: ${val}`;
    cell.innerHTML = `<div class="cell-name">${name}</div><div class="cell-count">${val}</div>`;
    container.appendChild(cell);
  });
}

let perfChart;
async function loadModelPerf() {
  const res = await fetch(API("/api/model-performance"));
  const j = await res.json();
  const ctx = document.getElementById("modelPerf").getContext("2d");
  const data = {
    labels: ["Precision", "Recall", "Accuracy"],
    datasets: [{
      label: "Last 7 days",
      data: [j.precision, j.recall, j.accuracy]
    }]
  };
  if (perfChart) perfChart.destroy();
  perfChart = new Chart(ctx, {
    type: "bar",
    data,
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true, max: 100 }
      }
    }
  });
}

async function loadAssets() {
  const res = await fetch(API("/api/assets"));
  const j = await res.json();
  const tbody = document.querySelector("#assetsTable tbody");
  tbody.innerHTML = "";
  j.assets.forEach(a => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.asset_id || ""}</td>
      <td>${a.hostname || ""}</td>
      <td>${a.ip_address || ""}</td>
      <td>${a.timestamp || ""}</td>`;
    tbody.appendChild(tr);
  });
}

async function loadSessions() {
  const res = await fetch(API("/api/sessions"));
  const j = await res.json();
  const tbody = document.querySelector("#sessionsTable tbody");
  tbody.innerHTML = "";
  j.sessions.forEach(s => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${s.timestamp || ""}</td>
      <td>${s.owner || ""}</td>
      <td>${s.hostname || ""}</td>
      <td>${s.ip_address || ""}</td>
      <td>${s.trust_score || ""}</td>
      <td>${s.risk_score || ""}</td>
      <td>${s.access_decision || ""}</td>
      <td>${s.anomaly_detected || ""}</td>`;
    tbody.appendChild(tr);
  });
}

async function loadCorrelation() {
  const res = await fetch(API("/api/correlation"));
  const j = await res.json();
  const tbody = document.querySelector("#corrTable tbody");
  tbody.innerHTML = "";
  j.correlations.forEach(c => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${c.timestamp || ""}</td>
      <td>${c.record_id || ""}</td>
      <td>${c.correlation_id || ""}</td>
      <td>${c.explanation_top_feature || ""}</td>
      <td>${c.explanation_score ?? ""}</td>
      <td>${c.learning_note || ""}</td>`;
    tbody.appendChild(tr);
  });
}

/* ---------- Chat log helper (HTML rendering for bot) ---------- */
function chatLogAdd(logElement, role, text) {
    const div = document.createElement("div");
    div.className = role === "user" ? "msg user" : "msg bot";
    if (role === "bot") {
      div.innerHTML = text || "";   // render HTML
    } else {
      div.textContent = text || "";
    }
    logElement.appendChild(div);
    logElement.scrollTop = logElement.scrollHeight;
  }
  
/* ===== Weekly Security Metrics (last 7 days, daily buckets) ===== */
let threatsGraph;
async function loadThreatsGraph() {
  const canvas = document.getElementById("mitreGraph");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  // Fetch weekly points
  const res = await fetch(API("/api/mitre-trend"));
  const j = await res.json();
  const points = Array.isArray(j?.points) ? j.points : [];

  if (threatsGraph) threatsGraph.destroy();

  const labels = points.map(p => new Date(p.date)); // 00:00 each day
  const total   = points.map(p => Number(p.total) || 0);
  const ia      = points.map(p => Number(p.ia) || 0);
  const c2      = points.map(p => Number(p.c2) || 0);
  const active  = points.map(p => Number(p.active_threats) || 0);

  threatsGraph = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Total MITRE Events (daily)", data: total,  borderColor: "#00c4e8", tension: 0.35, fill: false, pointRadius: 3 },
        { label: "Initial Access (daily)",     data: ia,     borderColor: "#21c55d", tension: 0.35, fill: false, pointRadius: 3 },
        { label: "Command & Control (daily)",  data: c2,     borderColor: "#ef4444", tension: 0.35, fill: false, pointRadius: 3 },
        { label: "Active Threats (daily)",     data: active, borderColor: "#a78bfa", tension: 0.35, fill: false, pointRadius: 3 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      scales: {
        x: {
          type: "time",
          time: { unit: "day", displayFormats: { day: "MMM d" } },
          grid:  { color: "rgba(255,255,255,0.1)" },
          ticks: { color: "#c0c0c0" }
        },
        y: {
          beginAtZero: true,
          grid:  { color: "rgba(255,255,255,0.1)" },
          ticks: { color: "#c0c0c0", precision: 0 }
        }
      },
      plugins: {
        legend: { labels: { color: "#c0c0c0" } },
        tooltip: {
          mode: "index",
          intersect: false,
          callbacks: {
            title: (items) => {
              const x = items?.[0]?.parsed?.x;
              return x ? new Date(x).toLocaleDateString() : "";
            },
            label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y ?? 0}`
          }
        },
        title: { display: true, text: "Weekly Security Metrics (last 7 days)" }
      }
    }
  });
}

/* ------------------------------ init ------------------------------ */
async function init() {
  await Promise.all([
    loadSummary(),
    loadHeatmap(),
    loadModelPerf(),
    loadAssets(),
    loadSessions(),
    loadCorrelation(),
    loadThreatsGraph()
  ]);

  // Floating chat
  const chatButton = document.getElementById('chat-button');
  const chatContainer = document.getElementById('chat-container');
  const closeChatBtn = document.getElementById('close-chat-btn');
  const popupChatLog = document.getElementById('popup-chat-log');
  const popupChatText = document.getElementById('popup-chat-text');
  const popupSendBtn = document.getElementById('popup-send-btn');

  if (chatButton && chatContainer && closeChatBtn) {
    chatButton.addEventListener('click', () => chatContainer.classList.toggle('open'));
    closeChatBtn.addEventListener('click', () => chatContainer.classList.remove('open'));
  }

  if (popupChatText && popupSendBtn) {
    async function sendPopupMessage() {
      const msg = popupChatText.value.trim();
      if (!msg) return;
      chatLogAdd(popupChatLog, "user", msg);
      popupChatText.value = "";
      try {
        const res = await fetch(API("/api/chat"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: msg })
        });
        const j = await res.json();
        if (j.reply) chatLogAdd(popupChatLog, "bot", j.reply);
        else chatLogAdd(popupChatLog, "bot", j.error || "Error");
      } catch {
        chatLogAdd(popupChatLog, "bot", "Request failed");
      }
    }
    popupSendBtn.addEventListener("click", sendPopupMessage);
    popupChatText.addEventListener("keydown", (e) => { if (e.key === "Enter") sendPopupMessage(); });
  }

  // Light auto-refresh
  setInterval(loadSummary, 10000);
  setInterval(loadAssets, 15000);
  setInterval(loadCorrelation, 20000);
}

init();
