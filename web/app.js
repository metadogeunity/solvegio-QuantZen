const metricSpec = [
  ["Protected Requests", "protected_requests", "Live API audit"],
  ["Verified", "verified", "Signature checks passed"],
  ["Blocked", "blocked", "Security decisions"],
  ["Replay Attacks", "replay_attacks", "Detected replays"],
  ["Invalid Signatures", "invalid_signatures", "Rejected signatures"],
  ["Unknown Keys", "unknown_keys", "Untrusted key IDs"],
  ["Webhook Events", "webhook_events", "SolveGio webhook ingress"]
];

const scenarios = [
  ["valid", "Valid Request", "Signed request"],
  ["invalid_signature", "Invalid Signature", "Bad PQ signature"],
  ["tampered_payload", "Tampered Payload", "Modify body after signing"],
  ["expired_timestamp", "Expired Timestamp", "Old timestamp"],
  ["reused_nonce", "Reused Nonce", "Reuse nonce"],
  ["revoked_key", "Revoked Key", "Use revoked key"],
  ["unknown_key", "Unknown Key", "Unknown kid"],
  ["duplicate_webhook", "Duplicate Webhook", "Replay event"]
];

const icons = ["⌁", "✓", "×", "↻", "!", "⌕", "↗"];

async function getJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error("HTTP " + response.status + " from " + url);
  }
  return response.json();
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function metrics(data) {
  document.querySelector("#metrics").innerHTML = metricSpec.map(function (m, i) {
    return '<div class="metric">' +
      '<div class="metric-top"><span class="metric-icon">' + icons[i] + "</span>" + escapeHTML(m[0]) + "</div>" +
      "<b>" + Number(data[m[1]] || 0).toLocaleString() + "</b>" +
      "<small>" + escapeHTML(m[2]) + "</small>" +
      "</div>";
  }).join("");
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString();
}

function trafficRows(events) {
  return events.filter(function (event) {
    return event.endpoint && event.endpoint.indexOf("/v1/") === 0;
  }).slice(0, 8);
}

function securityRows(events) {
  return events.filter(function (event) {
    return event.decision === "BLOCK" && event.type;
  }).slice(0, 8);
}

function severity(type) {
  if (type === "EXPIRED_TIMESTAMP" || type === "KEY_OUTSIDE_VALIDITY") return "Medium";
  return "High";
}

function tables(events) {
  const traffic = trafficRows(events);
  document.querySelector("#traffic tbody").innerHTML = traffic.length
    ? traffic.map(function (event) {
        const decision = event.decision || "";
        const valid = decision === "ALLOW";
        return "<tr>" +
          "<td>" + escapeHTML(formatTime(event.time)) + "</td>" +
          "<td>" + escapeHTML(event.method || "—") + "</td>" +
          "<td>" + escapeHTML(event.endpoint || "—") + "</td>" +
          "<td>" + escapeHTML(event.tenant || "—") + "</td>" +
          "<td>" + escapeHTML(event.key_id || "—") + "</td>" +
          '<td><span class="' + (valid ? "active" : "revoked") + '">' + (valid ? "✓ Valid" : "× Invalid") + "</span></td>" +
          "<td>" + Number(event.latency_ms || 0) + " ms</td>" +
          '<td><span class="' + (valid ? "allow" : "block") + '">' + (valid ? "ALLOWED" : "BLOCKED") + "</span></td>" +
          "</tr>";
      }).join("")
    : '<tr><td colspan="8" class="empty">No live API traffic recorded yet.</td></tr>';

  const security = securityRows(events);
  document.querySelector("#events tbody").innerHTML = security.length
    ? security.map(function (event) {
        return "<tr>" +
          "<td>" + escapeHTML(formatTime(event.time)) + "</td>" +
          '<td class="event-name">' + escapeHTML(event.type) + "</td>" +
          "<td>" + escapeHTML(event.details || "Gateway security control") + "</td>" +
          '<td><span class="' + (severity(event.type) === "Medium" ? "warn" : "block") + '">' + severity(event.type) + "</span></td>" +
          "</tr>";
      }).join("")
    : '<tr><td colspan="4" class="empty">No blocked security events.</td></tr>';
}

function trust(keys) {
  document.querySelector("#trust").innerHTML = keys.length
    ? keys.map(function (key) {
        const status = key.Status || "";
        return "<tr>" +
          "<td>" + escapeHTML(key.Issuer) + "</td>" +
          "<td>" + escapeHTML(key.KID) + "</td>" +
          "<td>" + escapeHTML(key.Algorithm) + "</td>" +
          '<td><span class="' + (status === "ACTIVE" ? "active" : "revoked") + '">' + escapeHTML(status) + "</span></td>" +
          "<td>" + escapeHTML(key.Fingerprint) + "</td>" +
          "<td>" + escapeHTML(new Date(key.ValidFrom).toISOString().slice(0, 10)) + " → " + escapeHTML(new Date(key.ValidUntil).toISOString().slice(0, 10)) + "</td>" +
          '<td><span class="readonly">Read-only</span></td>' +
          "</tr>";
      }).join("")
    : '<tr><td colspan="7" class="empty">No trusted keys registered.</td></tr>';
}

function renderEndpointDistribution(items, total) {
  const list = document.querySelector("#endpoint-list");
  if (!items.length || total === 0) {
    document.querySelector("#donut-value").textContent = "0";
    document.querySelector("#donut-label").textContent = "Live requests";
    list.innerHTML = '<div class="empty-panel">No endpoint traffic yet.</div>';
    return;
  }

  let cursor = 0;
  const palette = ["#0b72ff", "#32b1ef", "#20bd74", "#f5a400", "#8d5cff", "#94a3b8"];
  const stops = [];
  items.slice(0, 6).forEach(function (item, index) {
    const pct = item.count / total * 100;
    stops.push(palette[index % palette.length] + " " + cursor + "% " + (cursor + pct) + "%");
    cursor += pct;
  });
  if (cursor < 100) {
    stops.push("#d8dfeb " + cursor + "% 100%");
  }

  document.querySelector("#donut").style.background = "conic-gradient(" + stops.join(",") + ")";
  document.querySelector("#donut-value").textContent = total.toLocaleString();
  document.querySelector("#donut-label").textContent = "Live requests";

  list.innerHTML = items.slice(0, 6).map(function (item, index) {
    const pct = Math.round(item.count / total * 100);
    return '<div><i style="background:' + palette[index % palette.length] + '"></i>' +
      escapeHTML(item.endpoint) + "<b>" + pct + "%</b></div>";
  }).join("");
}

function drawChart(activity) {
  const canvas = document.querySelector("#chart");
  const ctx = canvas.getContext("2d");
  const width = Math.max(canvas.clientWidth, 300);
  const height = 190;
  const ratio = window.devicePixelRatio || 1;

  canvas.width = width * ratio;
  canvas.height = height * ratio;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = "#dce6f5";
  ctx.lineWidth = 1;
  for (let y = 25; y <= 165; y += 35) {
    ctx.beginPath();
    ctx.moveTo(20, y);
    ctx.lineTo(width - 16, y);
    ctx.stroke();
  }

  const max = Math.max.apply(null, activity.concat([1]));
  const barWidth = Math.max(4, (width - 44) / activity.length - 3);

  activity.forEach(function (value, index) {
    const x = 22 + index * ((width - 44) / activity.length);
    const barHeight = value === 0 ? 2 : (value / max) * 125;
    ctx.fillStyle = "#0b72ff";
    ctx.fillRect(x, 165 - barHeight, barWidth, barHeight);
  });

  ctx.fillStyle = "#64748b";
  ctx.font = "10px system-ui";
  ctx.fillText("24h", width - 35, 183);

  const hasActivity = activity.some(function (value) { return value > 0; });
  document.querySelector("#chart-empty").style.display = hasActivity ? "none" : "block";
}

function renderStatus(status) {
  const configured = Boolean(status.api_connection);
  const webhookReady = Boolean(status.webhook_status);

  document.querySelector("#env").textContent = status.environment || "UNKNOWN";
  document.querySelector("#statusEvent").textContent = status.last_event || "Never";
  document.querySelector("#lastEvent").textContent = status.last_event || "Never";

  document.querySelector("#conn").textContent = configured ? "SolveGio configured" : "SolveGio not configured";
  document.querySelector("#api-status").textContent = configured ? "Configured" : "Not configured";
  document.querySelector("#webhook-status").textContent = webhookReady ? "Configured" : "Not configured";
  document.querySelector("#api-key-status").textContent = status.api_key_configured ? "Configured" : "Not configured";

  const connectionText = document.querySelector("#connection-subtitle");
  connectionText.textContent = configured ? "Backend credentials are present" : "Waiting for sandbox credentials";
}

async function load() {
  try {
    const results = await Promise.all([
      getJSON("/api/dashboard"),
      getJSON("/api/trust-registry"),
      getJSON("/api/solvegio")
    ]);

    const dashboard = results[0];
    metrics(dashboard);
    tables(dashboard.events || []);
    trust(results[1]);
    renderEndpointDistribution(
      dashboard.endpoint_distribution || [],
      Number(dashboard.protected_requests || 0)
    );
    drawChart(dashboard.activity || []);
    renderStatus(results[2]);
  } catch (error) {
    document.querySelector("#conn").textContent = "Gateway unavailable";
    document.querySelector("#connection-subtitle").textContent = error.message;
    console.error(error);
  }
}

function simulator() {
  document.querySelector("#sim").innerHTML = '<div class="scenario-grid">' +
    scenarios.map(function (scenario) {
      return '<button class="scenario" data-s="' + scenario[0] + '">' +
        "<strong>" + escapeHTML(scenario[1]) + "</strong>" +
        "<span>" + escapeHTML(scenario[2]) + "</span>" +
        "</button>";
    }).join("") +
    "</div>";

  document.querySelectorAll(".scenario").forEach(function (button) {
    button.addEventListener("click", async function () {
      button.disabled = true;
      button.querySelector("span").textContent = "Running…";
      try {
        const result = await getJSON("/api/simulator", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({Scenario: button.dataset.s})
        });
        button.querySelector("span").textContent = result.decision + " · " + result.details;
        await load();
      } catch (error) {
        button.querySelector("span").textContent = "Error";
        console.error(error);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function navigation() {
  document.querySelectorAll(".nav").forEach(function (button) {
    button.addEventListener("click", function () {
      const target = document.getElementById(button.dataset.target);
      if (target) target.scrollIntoView({behavior: "smooth", block: "start"});
      document.querySelectorAll(".nav").forEach(function (item) { item.classList.remove("active"); });
      button.classList.add("active");
    });
  });
}

simulator();
navigation();
load();
setInterval(load, 8000);
window.addEventListener("resize", load);
