"use strict";

const state = { csrfToken: "", administrator: undefined, page: "overview", generatedKey: "" };
const titles = {
  overview: "Overview",
  shops: "Shops",
  licenses: "Licenses",
  generate: "Generate license key",
  plans: "Plans & settings",
  payments: "Payments",
  activations: "Activation history",
  audit: "Audit logs"
};
const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const pageContent = document.querySelector("#page-content");
const loginError = document.querySelector("#login-error");
const globalNotice = document.querySelector("#global-notice");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function date(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? escapeHtml(value) : parsed.toLocaleString();
}

function money(amount, currency) {
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(amount / 100);
  } catch {
    return `${amount} ${currency}`;
  }
}

function setNotice(message, error = false) {
  globalNotice.textContent = message;
  globalNotice.className = `global-notice ${error ? "notice-error" : "notice-success"}`;
  globalNotice.hidden = false;
  window.setTimeout(() => { globalNotice.hidden = true; }, 6000);
}

async function api(url, options = {}) {
  const method = options.method ?? "GET";
  const headers = { accept: "application/json", ...(options.headers ?? {}) };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") headers["x-csrf-token"] = state.csrfToken;
  const response = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  if (response.status === 204) return undefined;
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}

function showLogin() {
  loginView.hidden = false;
  appView.hidden = true;
  document.querySelector("#admin-token").value = "";
  state.csrfToken = "";
  state.administrator = undefined;
  state.generatedKey = "";
}

async function restoreSession() {
  try {
    const result = await api("/admin/session");
    state.csrfToken = result.csrfToken;
    state.administrator = result.administrator;
    showDashboard();
  } catch {
    showLogin();
  }
}

function showDashboard() {
  loginView.hidden = true;
  appView.hidden = false;
  document.querySelector("#admin-identity").textContent =
    `${state.administrator.id} · ${state.administrator.roles.join(", ")}`;
  renderPage(state.page);
}

async function login(event) {
  event.preventDefault();
  loginError.hidden = true;
  const tokenInput = document.querySelector("#admin-token");
  try {
    const result = await api("/admin/session", {
      method: "POST",
      headers: { authorization: `Bearer ${tokenInput.value}` }
    });
    state.csrfToken = result.csrfToken;
    state.administrator = result.administrator;
    tokenInput.value = "";
    state.page = "overview";
    showDashboard();
  } catch (error) {
    loginError.textContent = error.message;
    loginError.hidden = false;
  }
}

async function logout() {
  try {
    await api("/admin/session", { method: "DELETE" });
    setNotice("You have signed out.");
  } catch (error) {
    setNotice(error.message, true);
  } finally {
    showLogin();
  }
}

function table(headers, rows, emptyText = "No records found.") {
  if (!rows.length) return `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
  return `<div class="table-wrap"><table><thead><tr>${headers.map(item => `<th>${escapeHtml(item)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function statusBadge(status) {
  const kind = ["active", "trial", "grace_period"].includes(status) ? "good"
    : ["suspended", "revoked", "cancelled", "expired"].includes(status) ? "bad" : "neutral";
  return `<span class="status-badge ${kind}">${escapeHtml(status?.replaceAll("_", " ") || "unknown")}</span>`;
}

async function renderOverview() {
  const data = await api("/admin/dashboard");
  pageContent.innerHTML = `
    <div class="metric-grid">
      <article class="metric-card"><span>Registered shops</span><strong>${data.shops}</strong><small>Verified and managed here</small></article>
      <article class="metric-card"><span>Total licenses</span><strong>${data.licenses}</strong><small>Including historical records</small></article>
      <article class="metric-card"><span>Sales-enabled</span><strong>${data.active}</strong><small>Active, trial, or grace period</small></article>
      <article class="metric-card"><span>Expired</span><strong>${data.expired}</strong><small>Existing shop data remains local</small></article>
    </div>
    <section class="panel"><div class="panel-heading"><div><h2>Recent activity</h2><p>Administrative and activation events from the persistent license database.</p></div><button class="button button-secondary" data-go="audit">View audit log</button></div>
      ${table(["Event", "Shop ID", "License", "Administrator / actor", "Time"], data.recentActivity.map(item => `<tr><td>${escapeHtml(item.event)}</td><td class="mono">${escapeHtml(item.localShopId || "—")}</td><td class="mono">${escapeHtml(item.licenseId || "—")}</td><td>${escapeHtml(item.actorId || "—")}</td><td>${date(item.createdAt)}</td></tr>`))}
    </section>
    <p class="callout">Activation keys are displayed only in the response to issuance and are never retrievable from the database. Keep this browser session private.</p>`;
}

async function renderShops() {
  const [{ shops }, { licenses }] = await Promise.all([api("/admin/shops"), api("/admin/licenses")]);
  const licenseByShop = new Map();
  for (const license of licenses) {
    const list = licenseByShop.get(license.shopId) || [];
    list.push(license);
    licenseByShop.set(license.shopId, list);
  }
  const rows = shops.map(shop => {
    const latest = (licenseByShop.get(shop.id) || [])[0];
    return `<tr><td>${escapeHtml(shop.name)}</td><td class="mono">${escapeHtml(shop.localShopId || "Not linked")}</td><td class="mono">${escapeHtml(shop.id)}</td><td class="mono">${escapeHtml(latest?.licenseId || "—")}</td><td>${latest ? statusBadge(latest.status) : "No license"}</td><td>${shop.verifiedAt ? `Verified by ${escapeHtml(shop.verifiedBy)}<small>${date(shop.verifiedAt)}</small>` : "—"}</td><td><button class="text-button" data-issue-shop="${escapeHtml(shop.id)}" ${shop.localShopId ? "" : "disabled"}>Issue bound key</button></td></tr>`;
  });
  pageContent.innerHTML = `
    <section class="panel"><div class="panel-heading"><div><h2>Shop registry</h2><p>Existing local Shop IDs are linked only after an administrator attests ownership.</p></div><input id="shop-search" class="search-input" placeholder="Search shops, IDs, license IDs"></div>
      ${table(["Shop", "Local Shop ID", "Server Shop ID", "Latest license", "Latest status", "Registration", "Action"], rows, "No shops registered.")}
    </section>
    <section class="panel"><div class="panel-heading"><div><h2>Register existing ShopPOS shop</h2><p>Confirm shop identity with the owner using your established verification procedure; an ID alone is not proof of ownership.</p></div></div>
      <form id="register-shop-form" class="form-grid">
        <label>Shop name<input name="shopName" maxlength="120" required></label>
        <label>Existing ShopPOS Shop ID<input name="localShopId" inputmode="text" required pattern="[0-9a-fA-F-]{36}"></label>
        <label>Re-enter Shop ID to confirm<input name="confirmationShopId" required pattern="[0-9a-fA-F-]{36}"></label>
        <div class="form-actions"><button class="button button-primary">Register verified shop</button></div>
      </form>
    </section>`;
  document.querySelector("#shop-search").addEventListener("input", event => {
    const query = event.target.value.toLowerCase();
    document.querySelectorAll("tbody tr").forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(query); });
  });
  document.querySelector("#register-shop-form").addEventListener("submit", registerShop);
  pageContent.querySelectorAll("[data-issue-shop]").forEach(button => button.addEventListener("click", () => {
    state.issueShopId = button.dataset.issueShop;
    renderPage("generate");
  }));
}

async function renderLicenses() {
  const [{ licenses }, { shops }] = await Promise.all([api("/admin/licenses"), api("/admin/shops")]);
  const shopById = new Map(shops.map(shop => [shop.id, shop]));
  const rows = licenses.map(license => {
    const shop = shopById.get(license.shopId);
    const actions = [
      `<button data-license-action="renew" data-license-id="${escapeHtml(license.licenseId)}">Renew</button>`,
      license.status === "suspended"
        ? `<button data-license-action="reactivate" data-license-id="${escapeHtml(license.licenseId)}">Reactivate</button>`
        : `<button data-license-action="suspend" data-license-id="${escapeHtml(license.licenseId)}">Suspend</button>`,
      `<button data-license-action="revoke" data-license-id="${escapeHtml(license.licenseId)}">Revoke</button>`
    ].join("");
    return `<tr><td>${escapeHtml(shop?.name || license.shopName)}</td><td class="mono">${escapeHtml(license.localShopId || license.intendedLocalShopId || "Unbound")}</td><td class="mono">${escapeHtml(license.licenseId)}</td><td>${escapeHtml(license.planName)}</td><td>${statusBadge(license.status)}</td><td>${date(license.activatedAt)}</td><td>${date(license.expiresAt)}</td><td class="mono">${escapeHtml(license.deviceId || "—")}</td><td class="action-cell">${actions}</td></tr>`;
  });
  pageContent.innerHTML = `<section class="panel"><div class="panel-heading"><div><h2>License ledger</h2><p>Binding, status, activation, and expiry are read directly from the service database.</p></div><input id="license-search" class="search-input" placeholder="Search shop, Shop ID, license ID"></div>
    ${table(["Shop", "Shop ID", "License ID", "Plan", "Status", "Activated", "Expires", "Installation", "Actions"], rows, "No licenses issued.")}</section>`;
  document.querySelector("#license-search").addEventListener("input", event => {
    const query = event.target.value.toLowerCase();
    document.querySelectorAll("tbody tr").forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(query); });
  });
  pageContent.querySelectorAll("[data-license-action]").forEach(button => button.addEventListener("click", () => changeLicense(
    button.dataset.licenseId, button.dataset.licenseAction
  )));
}

async function renderGenerate() {
  const [{ shops }, { plans }] = await Promise.all([api("/admin/shops"), api("/admin/plans")]);
  const boundShops = shops.filter(shop => shop.localShopId);
  const selected = boundShops.find(shop => shop.id === state.issueShopId);
  const availablePlans = plans.filter(plan => plan.available);
  pageContent.innerHTML = `
    <section class="panel narrow-panel"><div class="panel-heading"><div><h2>Issue a one-time activation key</h2><p>The server stores only a SHA-256 hash. The full key is shown once and cannot be recovered later.</p></div></div>
      <form id="issue-key-form" class="stack">
        <label>Registered ShopPOS installation<select name="shopId" required><option value="">Select a verified shop</option>${boundShops.map(shop => `<option value="${escapeHtml(shop.id)}" ${selected?.id === shop.id ? "selected" : ""}>${escapeHtml(shop.name)} · ${escapeHtml(shop.localShopId)}</option>`).join("")}</select></label>
        <label>Confirm exact ShopPOS Shop ID<input name="confirmedLocalShopId" required value="${escapeHtml(selected?.localShopId || "")}" placeholder="Paste the Shop ID verified with the owner"></label>
        <label>Plan<select name="planId" required>${availablePlans.map(plan => `<option value="${escapeHtml(plan.id)}">${escapeHtml(plan.name)} · ${escapeHtml(plan.interval)} · ${money(plan.priceMinor, plan.currency)}</option>`).join("")}</select></label>
        <label>Optional custom expiry<input name="expiresAt" type="datetime-local"><small>Leave blank to use the plan trial/term. Custom expiry is stored as UTC.</small></label>
        <label class="confirm-row"><input name="confirmTarget" type="checkbox" required> I verified this shop owner and confirm this exact local Shop ID is the intended recipient.</label>
        <button class="button button-primary">Generate key once</button>
      </form>
    </section>
    <section id="generated-key-panel" class="panel key-panel" hidden><p class="eyebrow">COPY NOW — SHOWN ONCE</p><h2>Activation key generated</h2><p>Deliver this key privately to the shop owner. Leaving this page clears it from the dashboard.</p><code id="generated-key"></code><button id="copy-key" class="button button-primary">Copy activation key</button></section>`;
  document.querySelector("#issue-key-form").addEventListener("submit", issueKey);
}

async function renderPlans() {
  const { plans } = await api("/admin/plans");
  pageContent.innerHTML = `<section class="panel"><div class="panel-heading"><div><h2>Configured entitlement plans</h2><p>Plan availability and terms are stored in the license database. Only monthly/yearly terms are supported by current desktop token validation; feature flags and lifetime licenses are not part of this entitlement model.</p></div></div>
    ${table(["Name", "Plan ID", "Interval", "Price", "Trial days", "Grace days", "Available", "Update"], plans.map(plan => `<tr><td><input data-plan-field="name" value="${escapeHtml(plan.name)}" maxlength="80"></td><td class="mono">${escapeHtml(plan.id)}</td><td><select data-plan-field="interval"><option value="monthly" ${plan.interval === "monthly" ? "selected" : ""}>Monthly</option><option value="yearly" ${plan.interval === "yearly" ? "selected" : ""}>Yearly</option></select></td><td><div class="inline-input"><input data-plan-field="priceMinor" type="number" min="0" step="1" value="${plan.priceMinor}"><select data-plan-field="currency"><option ${plan.currency === "USD" ? "selected" : ""}>USD</option><option ${plan.currency === "PKR" ? "selected" : ""}>PKR</option><option ${plan.currency === "EUR" ? "selected" : ""}>EUR</option><option ${plan.currency === "GBP" ? "selected" : ""}>GBP</option><option ${plan.currency === "AED" ? "selected" : ""}>AED</option></select></div></td><td><input data-plan-field="trialDays" type="number" min="0" max="365" value="${plan.trialDays}"></td><td><input data-plan-field="graceDays" type="number" min="0" max="60" value="${plan.graceDays}"></td><td><input data-plan-field="available" type="checkbox" ${plan.available ? "checked" : ""}></td><td><button class="text-button" data-save-plan="${escapeHtml(plan.id)}">Save plan</button></td></tr>`))}
    </section>
    <section class="panel"><div class="panel-heading"><div><h2>Add plan</h2><p>Plan IDs are permanent once referenced by a license.</p></div></div>
      <form id="add-plan-form" class="form-grid">
        <label>Plan ID<input name="id" maxlength="40" pattern="[a-z0-9_-]+" required></label><label>Display name<input name="name" maxlength="80" required></label>
        <label>Interval<select name="interval"><option value="monthly">Monthly</option><option value="yearly">Yearly</option></select></label>
        <label>Price (minor currency units)<input name="priceMinor" type="number" min="0" step="1" required></label>
        <label>Currency<input name="currency" value="USD" pattern="[A-Z]{3}" maxlength="3" required></label>
        <label>Trial days<input name="trialDays" type="number" min="0" max="365" value="0" required></label>
        <label>Grace days<input name="graceDays" type="number" min="0" max="60" value="0" required></label>
        <label class="confirm-row"><input name="available" type="checkbox" checked> Available for issuance</label>
        <div class="form-actions"><button class="button button-primary">Add plan</button></div>
      </form>
    </section>`;
  pageContent.querySelectorAll("[data-save-plan]").forEach(button => button.addEventListener("click", () => savePlan(button)));
  document.querySelector("#add-plan-form").addEventListener("submit", addPlan);
}

async function renderPayments() {
  const { status: filterStatus, limit } = (() => {
    const url = new URL(window.location.href);
    return { status: url.searchParams.get("status") || null, limit: Number(url.searchParams.get("limit")) || 50 };
  })();
  const query = filterStatus ? `?status=${encodeURIComponent(filterStatus)}&limit=${limit}` : `?limit=${limit}`;
  const { payments } = await api(`/admin/payments${query}`);
  const rows = payments.map(payment => {
    const actions = payment.status === "pending"
      ? `<td class="action-cell"><button class="button" data-approve="${escapeHtml(payment.id)}">Approve</button> <button class="button button-outline" data-reject="${escapeHtml(payment.id)}">Reject</button></td>`
      : `<td class="action-cell"><span class="status-badge ${payment.status === "approved" ? "good" : "bad"}">${escapeHtml(payment.status)}</span></td>`;
    return `<tr><td class="mono">${escapeHtml(payment.id)}</td><td>${escapeHtml(payment.shopName)}</td><td class="mono">${escapeHtml(payment.licenseId)}</td><td>${escapeHtml(payment.planId)}</td><td>${money(payment.amountMinor, payment.currency)}</td><td>${payment.method}</td><td>${escapeHtml(payment.reference)}</td><td>${statusBadge(payment.status)}</td><td>${date(payment.submittedAt)}</td>${actions}</tr>`;
  });
  pageContent.innerHTML = `<section class="panel"><div class="panel-heading"><div><h2>Payment management</h2><p>All manual payment requests submitted by licensees. Amounts and renewals are verified server-side; the browser never supplies trustworthy values.</p></div><div class="payment-filters"><label>Status<select id="payment-status-filter"><option value="">All statuses</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="failed">Failed</option></select></label><label>Limit<input id="payment-limit" type="number" min="1" max="500" value="${limit}"></label><button class="button button-primary" id="payment-refresh">Refresh</button></div></div>
    ${table(["Payment ID", "Shop", "License ID", "Plan", "Amount", "Method", "Reference", "Status", "Submitted", "Action"], rows, "No payment requests.")}</section>`;
  document.querySelector("#payment-status-filter").value = filterStatus || "";
  document.querySelector("#payment-limit").value = limit;
  document.querySelector("#payment-status-filter").addEventListener("change", () => {
    const status = document.querySelector("#payment-status-filter").value;
    const lim = document.querySelector("#payment-limit").value;
    window.history.replaceState({}, "", `?status=${encodeURIComponent(status)}&limit=${encodeURIComponent(lim)}`);
    renderPayments();
  });
  document.querySelector("#payment-limit").addEventListener("change", () => {
    const status = document.querySelector("#payment-status-filter").value;
    const lim = document.querySelector("#payment-limit").value;
    window.history.replaceState({}, "", `?status=${encodeURIComponent(status)}&limit=${encodeURIComponent(lim)}`);
    renderPayments();
  });
  document.querySelector("#payment-refresh").addEventListener("click", renderPayments);
  pageContent.querySelectorAll("[data-approve]").forEach(button => button.addEventListener("click", () => confirmPaymentAction(button.dataset.approve, "approve")));
  pageContent.querySelectorAll("[data-reject]").forEach(button => button.addEventListener("click", () => confirmPaymentAction(button.dataset.reject, "reject")));
}

async function confirmPaymentAction(paymentId, action) {
  const payment = (await api(`/admin/payments/${encodeURIComponent(paymentId)}`));
  const confirmation = action === "reject"
    ? `Reject payment ${paymentId} for ${payment.shopName}? You must provide a reason.`
    : `Approve payment ${paymentId} for ${payment.shopName} for ${money(payment.amountMinor, payment.currency)}? This renews the subscription exactly once.`;
  if (!window.confirm(confirmation)) return;
  try {
    if (action === "reject") {
      const reason = window.prompt("Rejection reason (required):", "");
      if (!reason || reason.trim().length < 3) {
        setNotice("A rejection reason of at least 3 characters is required.", true);
        return;
      }
      await api(`/admin/payments/${encodeURIComponent(paymentId)}/reject`, { method: "POST", body: { reason: reason.trim() } });
      setNotice(`Payment ${paymentId} rejected.`);
    } else {
      await api(`/admin/payments/${encodeURIComponent(paymentId)}/approve`, { method: "POST", body: {} });
      setNotice(`Payment ${paymentId} approved; subscription renewed.`);
    }
    await renderPayments();
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function renderActivations() {
  const { activations } = await api("/admin/activations");
  pageContent.innerHTML = `<section class="panel"><div class="panel-heading"><div><h2>Activation history</h2><p>Successful and rejected key-redemption attempts.</p></div></div>
    ${table(["Result", "Local Shop ID", "License ID", "Installation", "Detail", "Time"], activations.map(item => `<tr><td>${statusBadge(item.event === "activation_succeeded" ? "active" : "rejected")}</td><td class="mono">${escapeHtml(item.localShopId || "—")}</td><td class="mono">${escapeHtml(item.licenseId || "—")}</td><td class="mono">${escapeHtml(item.deviceId || "—")}</td><td>${escapeHtml(item.detail)}</td><td>${date(item.createdAt)}</td></tr>`))}</section>`;
}

async function renderAudit() {
  const { logs } = await api("/admin/logs");
  pageContent.innerHTML = `<section class="panel"><div class="panel-heading"><div><h2>Audit log</h2><p>Most recent 500 license and administrator events.</p></div><input id="audit-search" class="search-input" placeholder="Filter events"></div>
    ${table(["Event", "Actor", "License", "Shop ID", "Installation", "Remote address", "Detail", "Time"], logs.map(item => `<tr><td>${escapeHtml(item.event)}</td><td>${escapeHtml(item.actorId || "—")}</td><td class="mono">${escapeHtml(item.licenseId || "—")}</td><td class="mono">${escapeHtml(item.localShopId || "—")}</td><td class="mono">${escapeHtml(item.deviceId || "—")}</td><td>${escapeHtml(item.remoteAddress || "—")}</td><td>${escapeHtml(item.detail)}</td><td>${date(item.createdAt)}</td></tr>`))}</section>`;
  document.querySelector("#audit-search").addEventListener("input", event => {
    const query = event.target.value.toLowerCase();
    document.querySelectorAll("tbody tr").forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(query); });
  });
}

async function renderPage(page) {
  state.page = page;
  state.generatedKey = "";
  document.querySelector("#page-title").textContent = titles[page];
  document.querySelectorAll(".nav-link[data-page]").forEach(button => button.classList.toggle("active", button.dataset.page === page));
  pageContent.innerHTML = `<div class="loading-state">Loading secure license data…</div>`;
  try {
    const renderers = {
      overview: renderOverview, shops: renderShops, licenses: renderLicenses,
      generate: renderGenerate, plans: renderPlans, payments: renderPayments,
      activations: renderActivations, audit: renderAudit
    };
    await renderers[page]();
  } catch (error) {
    if (/session|authentication/i.test(error.message)) showLogin();
    else pageContent.innerHTML = `<div class="notice notice-error" role="alert">${escapeHtml(error.message)}</div>`;
  }
}

async function registerShop(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  if (!window.confirm(`Register ShopPOS Shop ID ${data.localShopId} for ${data.shopName}? Confirm that ownership was independently verified.`)) return;
  try {
    await api("/admin/shops/register", { method: "POST", body: data });
    setNotice("Existing ShopPOS shop registered. You can now issue a bound license.");
    form.reset();
    await renderShops();
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function issueKey(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  if (!formData.get("confirmTarget")) return;
  const shopId = String(formData.get("shopId"));
  const confirmation = String(formData.get("confirmedLocalShopId"));
  if (!window.confirm(`Issue a new activation key bound to ShopPOS Shop ID ${confirmation}? The key can be redeemed only once.`)) return;
  const expiry = String(formData.get("expiresAt") || "");
  const body = {
    confirmedLocalShopId: confirmation,
    planId: String(formData.get("planId")),
    ...(expiry ? { expiresAt: new Date(expiry).toISOString() } : {})
  };
  try {
    const license = await api(`/admin/shops/${encodeURIComponent(shopId)}/licenses`, { method: "POST", body });
    state.generatedKey = license.licenseKey;
    document.querySelector("#generated-key").textContent = state.generatedKey;
    document.querySelector("#generated-key-panel").hidden = false;
    document.querySelector("#copy-key").addEventListener("click", async () => {
      await navigator.clipboard.writeText(state.generatedKey);
      setNotice("Activation key copied. Keep it private; it will not be shown again.");
    }, { once: true });
    setNotice(`Key issued for ${license.shopName}. Copy it now; leaving this screen clears it.`);
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function changeLicense(licenseId, action) {
  const confirmation = action === "renew"
    ? `Renew license ${licenseId} by the configured plan term?`
    : `${action[0].toUpperCase()}${action.slice(1)} license ${licenseId}? This does not delete shop data.`;
  if (!window.confirm(confirmation)) return;
  try {
    await api(`/admin/licenses/${encodeURIComponent(licenseId)}/${action}`, { method: "POST", body: {} });
    setNotice(`License ${action} completed.`);
    await renderLicenses();
  } catch (error) {
    setNotice(error.message, true);
  }
}

function planFromRow(row, id) {
  const value = field => row.querySelector(`[data-plan-field="${field}"]`);
  return {
    id,
    name: value("name").value.trim(),
    interval: value("interval").value,
    priceMinor: Number(value("priceMinor").value),
    currency: value("currency").value,
    trialDays: Number(value("trialDays").value),
    graceDays: Number(value("graceDays").value),
    available: value("available").checked
  };
}

async function savePlan(button) {
  try {
    const row = button.closest("tr");
    await api("/admin/plans", { method: "PUT", body: planFromRow(row, button.dataset.savePlan) });
    setNotice("Plan settings saved.");
    await renderPlans();
  } catch (error) {
    setNotice(error.message, true);
  }
}

async function addPlan(event) {
  event.preventDefault();
  const values = Object.fromEntries(new FormData(event.currentTarget));
  const plan = {
    ...values,
    priceMinor: Number(values.priceMinor),
    trialDays: Number(values.trialDays),
    graceDays: Number(values.graceDays),
    available: values.available === "on"
  };
  try {
    await api("/admin/plans", { method: "PUT", body: plan });
    setNotice("Plan added to the license service.");
    await renderPlans();
  } catch (error) {
    setNotice(error.message, true);
  }
}

document.querySelector("#login-form").addEventListener("submit", login);
document.querySelector("#logout-button").addEventListener("click", logout);
document.querySelector("#navigation").addEventListener("click", event => {
  const button = event.target.closest("[data-page]");
  if (button) renderPage(button.dataset.page);
});
pageContent.addEventListener("click", event => {
  const button = event.target.closest("[data-go]");
  if (button) renderPage(button.dataset.go);
});

void restoreSession();
