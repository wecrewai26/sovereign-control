// AEGIS Control Tower. Talks only to the same-origin /v1 API with the signed-in user's token.
// Every value from the API is inserted as text nodes or textContent, never parsed as markup.

const TOKEN_KEY = "aegis.token";
const THEME_KEY = "aegis.theme";
const $ = (sel) => document.querySelector(sel);

// ---------------------------------------------------------------- storage (may be unavailable)
const store = {
  get(area, key) { try { return window[area].getItem(key); } catch { return null; } },
  set(area, key, value) { try { window[area].setItem(key, value); } catch { /* private mode */ } },
  del(area, key) { try { window[area].removeItem(key); } catch { /* ignore */ } },
};
let memoryToken = null;
const getToken = () => store.get("sessionStorage", TOKEN_KEY) || memoryToken;
const setToken = (t) => { memoryToken = t; store.set("sessionStorage", TOKEN_KEY, t); };
const clearToken = () => { memoryToken = null; store.del("sessionStorage", TOKEN_KEY); };

// ---------------------------------------------------------------- api
class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(path, { method = "GET", body, raw = false } = {}) {
  const headers = { Authorization: `Bearer ${getToken()}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (resp.status === 401) { signOut("Your session token was not accepted. Sign in again."); throw new ApiError(401, "unauthorized"); }
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try { message = (await resp.json()).error || message; } catch { /* not JSON */ }
    throw new ApiError(resp.status, message);
  }
  return raw ? resp : resp.json();
}

// ---------------------------------------------------------------- dom helpers
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const svg = (tag, attrs = {}) => {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
};

function table(columns, rows, { onRow, selectedKey, rowKey, empty = "Nothing to show." } = {}) {
  if (!rows.length) return el("div", { class: "table-wrap" }, el("div", { class: "empty" }, empty));
  const head = el("tr", {}, columns.map((c) => el("th", { class: c.num ? "num" : null, scope: "col" }, c.label)));
  const body = rows.map((row) => {
    const key = rowKey ? rowKey(row) : null;
    const tr = el("tr", {
      class: [onRow ? "clickable" : "", key !== null && key === selectedKey ? "selected" : ""].join(" ").trim() || null,
      tabindex: onRow ? "0" : null,
    }, columns.map((c) => el("td", { class: [c.num ? "num" : "", c.wrap ? "wrap" : ""].join(" ").trim() || null },
      c.render ? c.render(row) : row[c.key] ?? "—")));
    if (onRow) {
      tr.addEventListener("click", () => onRow(row));
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") onRow(row); });
    }
    return tr;
  });
  return el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, body)));
}

// ---------------------------------------------------------------- formatting
function age(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600),
    m = Math.floor((seconds % 3600) / 60);
  if (d >= 10) return `${d}d`;
  if (d > 0) return `${d}d${h}h`;
  if (h > 0) return `${h}h${m}m`;
  if (m > 0) return `${m}m`;
  return `${seconds}s`;
}
function cores(v) {
  if (v === null || v === undefined) return "—";
  return v < 1 ? `${Math.round(v * 1000)}m` : `${v.toFixed(2)}`;
}
function bytes(v) {
  if (v === null || v === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—");
const when = (iso) => (iso ? new Date(iso).toLocaleString() : "—");

// Status always shows an icon and a word; color is never the only signal.
const STATUS = {
  good: ["✓", ["Running", "Succeeded", "Completed", "succeeded", "resolved", "closed", "approved", "Normal"]],
  warning: ["…", ["Pending", "ContainerCreating", "PodInitializing", "Terminating", "pending_approval", "executing",
    "investigating", "mitigating", "open", "recommended", "Warning"]],
  serious: ["!", ["CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "Error", "OOMKilled",
    "CreateContainerConfigError", "rolled_back", "interrupted", "execution_failed"]],
  critical: ["✕", ["Evicted", "Failed", "Unknown", "NodeLost", "denied", "rejected", "rollback_failed"]],
};
function statusPill(text, override) {
  let role = override || "neutral";
  if (!override) for (const [r, [, words]] of Object.entries(STATUS)) if (words.includes(text)) role = r;
  const icon = STATUS[role] ? STATUS[role][0] : "•";
  return el("span", { class: `status ${role}` }, el("span", { class: "dot", "aria-hidden": "true" }, icon),
    String(text).replaceAll("_", " "));
}
const SEVERITY_ROLE = { critical: "critical", high: "serious", medium: "warning", low: "neutral" };
const severityPill = (s) => statusPill(s, SEVERITY_ROLE[s] || "neutral");

// ---------------------------------------------------------------- chart (single series line, hover)
function lineChart({ title, points, format, emptyText, binary = false }) {
  const root = el("div", { class: "chart" });
  const latest = points.length ? format(points[points.length - 1][1]) : "—";
  root.append(el("div", { class: "chart-head" }, el("span", { class: "chart-title" }, title),
    el("span", { class: "chart-latest" }, points.length ? `now ${latest}` : "")));
  if (!points.length) {
    root.append(el("p", { class: "notice" }, emptyText));
    return root;
  }
  const W = 560, H = 170, L = 56, R = 12, T = 10, B = 24;
  const xs = points.map((p) => p[0]), ys = points.map((p) => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs) || x0 + 1;
  // Byte axes get round binary ticks (e.g. 0, 64, 128, 192, 256 MiB) instead of decimal ones.
  const peak = Math.max(...ys, 0);
  const unit = binary ? 1024 ** Math.max(0, Math.floor(Math.log(Math.max(peak, 1)) / Math.log(1024))) : 1;
  const yMax = binary ? niceBinaryMax(peak / unit) * unit : niceMax(peak);
  const sx = (t) => L + ((t - x0) / Math.max(1, x1 - x0)) * (W - L - R);
  const sy = (v) => T + (1 - v / yMax) * (H - T - B);

  const chart = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `${title}, latest ${latest}` });
  const grid = svg("g", { class: "grid" }), axis = svg("g", { class: "axis" });
  for (let i = 0; i <= 4; i += 1) {
    const v = (yMax * i) / 4, y = sy(v);
    grid.append(svg("line", { x1: L, x2: W - R, y1: y, y2: y }));
    const t = svg("text", { x: L - 8, y: y + 4, "text-anchor": "end" }); t.textContent = format(v); axis.append(t);
  }
  for (let i = 0; i <= 3; i += 1) {
    const t = x0 + ((x1 - x0) * i) / 3;
    const label = svg("text", { x: sx(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === 3 ? "end" : "middle" });
    label.textContent = new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    axis.append(label);
  }
  const d = points.map((p, i) => `${i ? "L" : "M"}${sx(p[0]).toFixed(1)},${sy(p[1]).toFixed(1)}`).join(" ");
  const cross = svg("line", { class: "crosshair", y1: T, y2: H - B, visibility: "hidden" });
  const marker = svg("circle", { class: "marker", r: 4.5, visibility: "hidden" });
  const hit = svg("rect", { x: L, y: T, width: W - L - R, height: H - T - B, fill: "transparent" });
  chart.append(grid, axis, svg("path", { class: "line", d }), cross, marker, hit);

  const box = el("div", { class: "chart-box" }, chart);
  const tip = el("div", { class: "tooltip", hidden: true });
  box.append(tip);
  const show = (clientX) => {
    const rect = chart.getBoundingClientRect();
    const t = x0 + ((clientX - rect.left) / rect.width * W - L) / (W - L - R) * (x1 - x0);
    let best = points[0];
    for (const p of points) if (Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
    const x = sx(best[0]), y = sy(best[1]);
    for (const n of [cross, marker]) n.setAttribute("visibility", "visible");
    cross.setAttribute("x1", x); cross.setAttribute("x2", x);
    marker.setAttribute("cx", x); marker.setAttribute("cy", y);
    tip.hidden = false;
    tip.textContent = `${new Date(best[0] * 1000).toLocaleTimeString()} · ${format(best[1])}`;
    tip.style.left = `${(x / W) * 100}%`;
    tip.style.top = `${(y / H) * rect.height}px`;
  };
  const hide = () => { for (const n of [cross, marker]) n.setAttribute("visibility", "hidden"); tip.hidden = true; };
  hit.addEventListener("pointermove", (e) => show(e.clientX));
  hit.addEventListener("pointerleave", hide);
  root.append(box);

  // Table view of the same data, for screen readers and exact values.
  const recent = points.slice(-30).reverse();
  root.append(el("details", { class: "data-table" }, el("summary", {}, "Show values"),
    table([{ label: "Time", render: (p) => new Date(p[0] * 1000).toLocaleTimeString() },
      { label: title, num: true, render: (p) => format(p[1]) }], recent)));
  return root;
}
function niceBinaryMax(v) {
  if (v <= 0) return 1;
  for (const m of [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]) if (m >= v * 1.05) return m;
  return 1024;
}
function niceMax(v) {
  if (v <= 0) return 1;
  const exp = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * exp >= v * 1.05) return m * exp;
  return 10 * exp;
}

// ---------------------------------------------------------------- shell
let me = null;
let current = "tower";
const views = {};

function signOut(message) {
  clearToken();
  me = null;
  $("#app").hidden = true;
  $("#signout").hidden = true;
  $("#whoami").textContent = "";
  $("#signin").hidden = false;
  $("#signin-error").textContent = message || "";
  $("#token").value = "";
  $("#token").focus();
}

async function signIn() {
  me = await api("/v1/me");
  $("#signin").hidden = true;
  $("#app").hidden = false;
  $("#signout").hidden = false;
  $("#whoami").textContent = `${me.id} · ${me.roles.join(", ") || "no roles"}`;
  const fromHash = location.hash.slice(1);
  show(views[fromHash] ? fromHash : "tower");
}

async function show(name) {
  current = name;
  if (location.hash.slice(1) !== name) history.replaceState(null, "", `#${name}`);
  for (const b of document.querySelectorAll(".nav-item")) {
    if (b.dataset.view === name) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  const main = $("#main");
  main.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  try {
    await views[name](main);
  } catch (err) {
    if (err.status !== 401) main.replaceChildren(el("p", { class: "error", role: "alert" }, `Could not load: ${err.message}`));
  }
  refreshBadges();
}

async function refreshBadges() {
  try {
    const tower = await api("/v1/control-tower");
    const setBadge = (id, n) => { const b = $(id); b.hidden = !n; b.textContent = n || ""; };
    setBadge("#badge-approvals", tower.pending_approvals);
    setBadge("#badge-incidents", Object.values(tower.open_incidents || {}).reduce((a, b) => a + b, 0));
  } catch { /* badges are best-effort */ }
}

// ---------------------------------------------------------------- view: overview
views.tower = async (main) => {
  const t = await api("/v1/control-tower");
  const openTotal = Object.values(t.open_incidents || {}).reduce((a, b) => a + b, 0);
  const bySeverity = ["critical", "high", "medium", "low"].filter((s) => t.open_incidents?.[s])
    .map((s) => `${t.open_incidents[s]} ${s}`).join(" · ");
  const tile = (label, value, sub) => el("div", { class: "tile" }, el("div", { class: "label" }, label),
    el("div", { class: "value" }, value), sub ? el("div", { class: "sub" }, sub) : null);
  main.replaceChildren(
    el("h1", {}, "Overview"),
    el("p", { class: "muted" }, "Agents, approvals, incidents and the health of the audit trail."),
    el("div", { class: "tiles" },
      tile("Pending approvals", t.pending_approvals, t.pending_approvals ? "waiting on a person" : "nothing waiting"),
      tile("Open incidents", openTotal, bySeverity || "none open"),
      tile("Active agents", `${t.agents.active}/${t.agents.total}`),
      tile("Blocked actions", t.blocked_actions, "denied by policy"),
      tile("Escalations", t.escalations, "handed to a person"),
      el("div", { class: "tile" }, el("div", { class: "label" }, "Audit trail"),
        el("div", { class: "value" }, statusPill(t.audit.chain_valid ? "intact" : "broken",
          t.audit.chain_valid ? "good" : "critical")),
        el("div", { class: "sub" }, `${t.audit.events} events, hash chain verified`))),
    el("h2", {}, "High-risk actions"),
    table([
      { label: "Execution", render: (r) => el("span", { class: "mono" }, r.execution_id) },
      { label: "Agent", key: "agent_id" }, { label: "Tool", key: "tool_id" },
      { label: "Risk", render: (r) => r.risk }, { label: "Status", render: (r) => statusPill(r.status) },
    ], (t.risky_actions || []).slice().reverse(), { empty: "No high or critical risk actions yet." }),
  );
};

// ---------------------------------------------------------------- view: approvals
views.approvals = async (main) => {
  const { approvals } = await api("/v1/approvals");
  const details = await Promise.all(approvals.map((a) => api(`/v1/executions/${encodeURIComponent(a.execution_id)}`)));
  main.replaceChildren(el("h1", {}, "Approvals"),
    el("p", { class: "muted" }, "Each request shows the agent's evidence and the risk assessment before you decide."));
  if (!approvals.length) { main.append(el("div", { class: "table-wrap" }, el("div", { class: "empty" }, "Nothing is waiting for approval."))); return; }
  approvals.forEach((a, i) => main.append(approvalCard(a, details[i])));
};

function approvalCard(a, ex) {
  const ctx = ex.context || {};
  const roles = me.roles.filter((r) => !a.required_role || r === a.required_role);
  const roleSelect = el("select", { "aria-label": "Approve as role" }, roles.map((r) => el("option", { value: r }, r)));
  const reason = el("input", { type: "text", placeholder: "Reason (for rejecting)", "aria-label": "Reason for rejecting" });
  const message = el("p", { class: "error", role: "alert" });
  const act = async (path, body) => {
    try { await api(path, { method: "POST", body }); show("approvals"); }
    catch (err) { message.textContent = err.message; }
  };
  return el("article", { class: "approval" },
    el("h2", {}, `${ex.tool_id} in ${ex.environment}`),
    el("div", { class: "muted" }, `requested by ${a.requested_by} · ${a.mode} approval` +
      (a.required_role ? ` · needs role ${a.required_role}` : "") +
      ` · ${a.approvers.length}/${a.required_approvals} approvals · expires ${when(a.expires_at)}`),
    el("dl", { class: "kv" },
      el("dt", {}, "Risk"), el("dd", {}, `${ex.risk.score} (${ex.risk.level})`),
      el("dt", {}, "Why"), el("dd", {}, ex.policy.reasons.join("; ")),
      ...(ex.risk.notes || []).length ? [el("dt", {}, "Risk notes"), el("dd", {}, ex.risk.notes.join("; "))] : [],
      el("dt", {}, "Parameters"), el("dd", { class: "mono" }, JSON.stringify(ex.params)),
      el("dt", {}, "Hypothesis"), el("dd", {}, ctx.hypothesis || "—"),
      el("dt", {}, "Confidence"), el("dd", {}, `${Math.round((ctx.confidence ?? 0) * 100)}%`)),
    (ctx.evidence || []).length ? el("ul", { class: "evidence-list" }, ctx.evidence.map((e) => el("li", {}, e))) : null,
    el("div", { class: "actions" },
      roles.length ? [roleSelect, el("button", { type: "button",
        onclick: () => act(`/v1/executions/${encodeURIComponent(ex.execution_id)}/approve`, { role: roleSelect.value }) }, "Approve")]
        : el("span", { class: "muted" }, a.required_role ? `You don't hold the ${a.required_role} role.` : "You hold no roles."),
      reason,
      el("button", { type: "button", class: "danger",
        onclick: () => act(`/v1/executions/${encodeURIComponent(ex.execution_id)}/reject`, { reason: reason.value }) }, "Reject")),
    message);
}

// ---------------------------------------------------------------- view: incidents
let selectedIncident = null;
views.incidents = async (main) => {
  const { incidents } = await api("/v1/incidents");
  incidents.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  const split = el("div", { class: `split ${selectedIncident ? "open" : ""}` });
  const list = table([
    { label: "Incident", render: (i) => el("span", { class: "mono" }, i.incident_id) },
    { label: "Title", key: "title", wrap: true },
    { label: "Severity", render: (i) => severityPill(i.severity) },
    { label: "Status", render: (i) => statusPill(i.status) },
    { label: "Service", render: (i) => i.service || "—" },
    { label: "Alerts", num: true, key: "alert_count" },
    { label: "Opened", render: (i) => when(i.created_at) },
  ], incidents, { onRow: (i) => { selectedIncident = i.incident_id; show("incidents"); },
    rowKey: (i) => i.incident_id, selectedKey: selectedIncident, empty: "No incidents." });
  split.append(el("div", {}, list));
  if (selectedIncident) split.append(await incidentPanel(selectedIncident));
  main.replaceChildren(el("h1", {}, "Incidents"), el("p", { class: "muted" }, "Select an incident for its timeline and evidence."), split);
};

async function incidentPanel(id) {
  const inc = await api(`/v1/incidents/${encodeURIComponent(id)}`);
  const download = async () => {
    const resp = await api(`/v1/incidents/${encodeURIComponent(id)}/evidence`, { raw: true });
    const url = URL.createObjectURL(await resp.blob());
    const a = el("a", { href: url, download: `${id}-evidence.zip` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  };
  return el("aside", { class: "panel", "aria-label": `Incident ${id}` },
    el("h2", {}, `${inc.incident_id}: ${inc.title}`),
    el("dl", { class: "kv" },
      el("dt", {}, "Severity"), el("dd", {}, severityPill(inc.severity)),
      el("dt", {}, "Status"), el("dd", {}, statusPill(inc.status)),
      el("dt", {}, "Affected"), el("dd", {}, [inc.service, ...(inc.affected_services || [])].filter(Boolean)
        .filter((v, i, a) => a.indexOf(v) === i).join(", ") || "—"),
      el("dt", {}, "Owner"), el("dd", {}, inc.owner || "—"),
      el("dt", {}, "Root cause"), el("dd", {}, inc.root_cause || "—"),
      el("dt", {}, "Resolution"), el("dd", {}, inc.resolution || "—")),
    el("div", { class: "actions" }, el("button", { type: "button", class: "ghost", onclick: download }, "Download evidence bundle"),
      el("button", { type: "button", class: "ghost", onclick: () => { selectedIncident = null; show("incidents"); } }, "Close")),
    el("h2", {}, "Timeline"),
    el("ol", { class: "timeline" }, inc.timeline.map((e) => el("li", {},
      el("span", { class: "muted mono" }, clock(e.time)),
      el("span", {}, el("strong", {}, e.event), " ", el("span", { class: "muted" }, `by ${e.actor}`))))));
}

// ---------------------------------------------------------------- view: clusters (Lens-style)
const clusterState = { env: null, ns: null, tab: "pods", pod: null, container: "", tail: 200, minutes: 60, clusters: [] };
const remember = () => store.set("localStorage", "aegis.cluster", JSON.stringify(
  { env: clusterState.env, ns: clusterState.ns, tab: clusterState.tab }));
try { Object.assign(clusterState, JSON.parse(store.get("localStorage", "aegis.cluster") || "{}")); } catch { /* ignore */ }

views.cluster = async (main) => {
  const { clusters } = await api("/v1/clusters");
  clusterState.clusters = clusters;
  main.replaceChildren(el("h1", {}, "Clusters"),
    el("p", { class: "muted" }, "Live, read-only views. Each load uses a short-lived credential and is recorded in the audit trail."));
  if (!clusters.length) { main.append(el("div", { class: "table-wrap" }, el("div", { class: "empty" }, "No clusters are configured."))); return; }
  if (!clusters.some((c) => c.environment === clusterState.env)) clusterState.env = clusters[0].environment;
  const cluster = clusters.find((c) => c.environment === clusterState.env);
  if (!cluster.namespaces.includes(clusterState.ns)) clusterState.ns = cluster.namespaces[0];

  const envSelect = el("select", { id: "env", onchange: (e) => { clusterState.env = e.target.value; clusterState.pod = null; remember(); show("cluster"); } },
    clusters.map((c) => el("option", { value: c.environment, selected: c.environment === clusterState.env }, c.environment)));
  const nsSelect = el("select", { id: "ns", onchange: (e) => { clusterState.ns = e.target.value; clusterState.pod = null; remember(); show("cluster"); } },
    cluster.namespaces.map((n) => el("option", { value: n, selected: n === clusterState.ns }, n)));
  const tabButton = (tab, label) => el("button", { type: "button", class: clusterState.tab === tab ? "" : "ghost",
    "aria-pressed": String(clusterState.tab === tab), onclick: () => { clusterState.tab = tab; clusterState.pod = null; remember(); show("cluster"); } }, label);
  main.append(el("div", { class: "toolbar" },
    el("label", { for: "env" }, "Cluster"), envSelect, el("label", { for: "ns" }, "Namespace"), nsSelect,
    tabButton("pods", "Pods"), tabButton("deployments", "Deployments"), tabButton("events", "Events"),
    el("span", { class: "spacer" }), el("button", { type: "button", class: "ghost", onclick: () => show("cluster") }, "Refresh")));

  const base = `/v1/clusters/${encodeURIComponent(clusterState.env)}/namespaces/${encodeURIComponent(clusterState.ns)}`;
  if (clusterState.tab === "deployments") {
    const { deployments } = await api(`${base}/deployments`);
    main.append(table([
      { label: "Name", key: "name" },
      { label: "Ready", render: (d) => statusPill(`${d.ready}/${d.replicas}`, d.ready === d.replicas ? "good" : d.ready ? "warning" : "critical") },
      { label: "Up to date", num: true, key: "updated" }, { label: "Available", num: true, key: "available" },
      { label: "Revision", num: true, render: (d) => d.revision ?? "—" }, { label: "Age", render: (d) => age(d.age_seconds) },
    ], deployments, { empty: "No deployments in this namespace." }));
    return;
  }
  if (clusterState.tab === "events") {
    const { events } = await api(`${base}/events`);
    main.append(table([
      { label: "Type", render: (e) => statusPill(e.type || "—", e.type === "Warning" ? "warning" : "neutral") },
      { label: "Reason", key: "reason" }, { label: "Object", key: "object" },
      { label: "Message", key: "message", wrap: true }, { label: "Count", num: true, key: "count" },
      { label: "Last seen", render: (e) => age(e.age_seconds) },
    ], events, { empty: "No recent events." }));
    return;
  }

  const { pods, metrics } = await api(`${base}/pods`);
  const columns = [
    { label: "Name", render: (p) => el("span", { class: "mono" }, p.name) },
    { label: "Containers", render: containerSquares },
    { label: "Restarts", num: true, key: "restarts" },
    { label: "Controlled by", render: (p) => (p.controlled_by ? `${p.controlled_by.kind}/${p.controlled_by.name}` : "—") },
    { label: "Node", render: (p) => p.node || "—" },
    { label: "QoS", render: (p) => p.qos || "—" },
    { label: "Age", render: (p) => age(p.age_seconds) },
    { label: "Status", render: (p) => statusPill(p.status) },
  ];
  if (metrics) columns.splice(3, 0, { label: "CPU", num: true, render: (p) => cores(p.cpu_cores) },
    { label: "Memory", num: true, render: (p) => bytes(p.memory_bytes) });
  const counts = pods.reduce((acc, p) => { acc[p.status] = (acc[p.status] || 0) + 1; return acc; }, {});
  main.append(el("p", { class: "notice" }, `${pods.length} pods · ` +
    Object.entries(counts).map(([s, n]) => `${n} ${s}`).join(" · ")));

  const split = el("div", { class: `split ${clusterState.pod ? "open" : ""}` });
  split.append(el("div", {}, table(columns, pods, {
    onRow: (p) => { clusterState.pod = p.name; clusterState.container = ""; show("cluster"); },
    rowKey: (p) => p.name, selectedKey: clusterState.pod, empty: "No pods in this namespace." })));
  const pod = pods.find((p) => p.name === clusterState.pod);
  if (pod) split.append(podPanel(pod, base, metrics));
  main.append(split);
};

function containerSquares(p) {
  const ready = p.containers.filter((c) => c.ready).length;
  return el("span", { class: "containers", "aria-label": `${ready} of ${p.containers.length} containers ready` },
    p.containers.map((c) => el("i", {
      class: c.ready ? "ready" : c.state === "running" || c.state === "waiting" || c.state === "ContainerCreating" ? "waiting" : "notready",
      title: `${c.name}: ${c.ready ? "ready" : c.state}${c.restarts ? `, ${c.restarts} restarts` : ""}` })),
    el("span", { class: "count" }, `${ready}/${p.containers.length}`));
}

function podPanel(pod, base, metrics) {
  const podPath = `${base}/pods/${encodeURIComponent(pod.name)}`;
  const logBox = el("pre", { class: "logs mono", tabindex: "0", "aria-label": "Pod logs" }, "Loading logs…");
  const logNote = el("p", { class: "notice" });
  const containerSelect = el("select", { "aria-label": "Container" },
    pod.containers.map((c) => el("option", { value: c.name, selected: c.name === clusterState.container }, c.name)));
  const tailSelect = el("select", { "aria-label": "Lines" }, [100, 200, 500, 1000, 2000].map((n) =>
    el("option", { value: n, selected: n === clusterState.tail }, `last ${n} lines`)));
  const loadLogs = async () => {
    clusterState.container = containerSelect.value;
    clusterState.tail = Number(tailSelect.value);
    logBox.textContent = "Loading logs…";
    try {
      const q = new URLSearchParams({ container: clusterState.container, tail: clusterState.tail });
      const res = await api(`${podPath}/logs?${q}`);
      logBox.textContent = res.lines.length ? res.lines.join("\n") : "(no log lines)";
      logBox.scrollTop = logBox.scrollHeight;
      logNote.textContent = res.redactions ? `${res.redactions} secret-looking value(s) hidden as [REDACTED].` : "";
    } catch (err) { logBox.textContent = `Could not load logs: ${err.message}`; }
  };
  containerSelect.addEventListener("change", loadLogs);
  tailSelect.addEventListener("change", loadLogs);

  const charts = el("div", {});
  const rangeSelect = el("select", { "aria-label": "Time range" }, [[15, "15 minutes"], [60, "1 hour"], [360, "6 hours"], [1440, "24 hours"]]
    .map(([m, label]) => el("option", { value: m, selected: m === clusterState.minutes }, label)));
  const loadMetrics = async () => {
    clusterState.minutes = Number(rangeSelect.value);
    charts.replaceChildren(el("p", { class: "muted" }, "Loading metrics…"));
    try {
      const m = await api(`${podPath}/metrics?minutes=${clusterState.minutes}`);
      const empty = "Prometheus has no data for this pod in this range.";
      charts.replaceChildren(
        lineChart({ title: "CPU (cores)", points: m.cpu_cores, format: cores, emptyText: empty }),
        lineChart({ title: "Memory (working set)", points: m.memory_bytes, format: bytes, emptyText: empty, binary: true }));
    } catch (err) { charts.replaceChildren(el("p", { class: "error" }, `Could not load metrics: ${err.message}`)); }
  };
  rangeSelect.addEventListener("change", loadMetrics);

  const panel = el("aside", { class: "panel", "aria-label": `Pod ${pod.name}` },
    el("h2", {}, pod.name),
    el("dl", { class: "kv" },
      el("dt", {}, "Status"), el("dd", {}, statusPill(pod.status)),
      pod.message ? [el("dt", {}, "Message"), el("dd", {}, pod.message)] : [],
      el("dt", {}, "Node"), el("dd", {}, pod.node || "—"),
      el("dt", {}, "Controlled by"), el("dd", {}, pod.controlled_by ? `${pod.controlled_by.kind}/${pod.controlled_by.name}` : "—"),
      el("dt", {}, "Containers"), el("dd", {}, pod.containers.map((c) => `${c.name} (${c.ready ? "ready" : c.state}, ${c.restarts} restarts)`).join(", "))),
    el("div", { class: "actions" }, el("button", { type: "button", class: "ghost",
      onclick: () => { clusterState.pod = null; show("cluster"); } }, "Close")),
    metrics ? [el("h2", {}, "Usage"), el("div", { class: "toolbar" }, rangeSelect), charts] : [],
    el("h2", {}, "Logs"),
    el("div", { class: "toolbar" }, containerSelect, tailSelect,
      el("button", { type: "button", class: "ghost", onclick: loadLogs }, "Refresh logs")),
    logNote, logBox);
  loadLogs();
  if (metrics) loadMetrics();
  return panel;
}

// ---------------------------------------------------------------- boot
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
}
applyTheme(store.get("localStorage", THEME_KEY));
$("#theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  store.set("localStorage", THEME_KEY, next);
});
$("#signout").addEventListener("click", () => signOut());
for (const b of document.querySelectorAll(".nav-item")) b.addEventListener("click", () => show(b.dataset.view));
$("#signin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setToken($("#token").value.trim());
  try { await signIn(); } catch (err) { if (err.status !== 401) $("#signin-error").textContent = err.message; }
});
if (getToken()) signIn().catch(() => signOut()); else signOut();
