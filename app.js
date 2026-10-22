const DATA_URL = "data/veille.json";
const fallback = { generatedAt: null, fortinet: [], cyber: [], kev: [], errors: [], community: [], communityStatus: null };
const $ = (id) => document.getElementById(id);
let currentData = fallback;

function safeDate(value) {
  if (!value) return "Date non précisée";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" }).format(date);
}
function escapeHTML(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
}
function linkOrFallback(item) {
  const url = item.url || item.link;
  return /^https?:\/\//i.test(url || "") ? url : "#sources";
}
function renderArticles(items) {
  if (!items.length) return '<div class="empty-card">Aucun élément disponible pour le moment. La prochaine synchronisation automatique actualisera ce flux.</div>';
  return items.slice(0, 6).map(item => `
    <a class="article-card" href="${escapeHTML(linkOrFallback(item))}" target="_blank" rel="noopener noreferrer">
      <span class="article-badge">${escapeHTML(item.label || "FORTIGUARD")}</span>
      <div class="article-copy"><h3>${escapeHTML(item.title || "Publication sans titre")}</h3><p>${escapeHTML(item.summary || "Ouvrir la source pour consulter les détails et les recommandations de l'éditeur.")}</p></div>
      <span class="article-meta">${escapeHTML(safeDate(item.date))} ↗</span>
    </a>`).join("");
}
function renderCyber(items) {
  if (!items.length) return '<div class="empty-card">Aucune actualité chargée pour le moment.</div>';
  return items.slice(0, 8).map(item => `
    <article class="news-card"><div class="news-top"><span class="news-category">${escapeHTML(item.label || item.source || "CYBER ACTUALITÉ")}</span><span class="news-date">${escapeHTML(safeDate(item.date))}</span></div>
    <h3>${escapeHTML(item.title || "Publication sans titre")}</h3><p>${escapeHTML(item.summary || "Consultez la publication originale pour le contexte complet.")}</p>
    <a class="read-link" href="${escapeHTML(linkOrFallback(item))}" target="_blank" rel="noopener noreferrer">Lire la source ↗</a></article>`).join("");
}
function renderKev(items, filter = "") {
  const query = filter.trim().toLowerCase();
  const filtered = items.filter(item => [item.cve, item.title, item.vendorProject, item.product, item.shortDescription].join(" ").toLowerCase().includes(query));
  $("cve-count").textContent = `${filtered.length} résultat(s)`;
  if (!filtered.length) return '<div class="empty-card">Aucun résultat. Essaie un autre mot-clé.</div>';
  return filtered.slice(0, 30).map(item => {
    const cve = item.cve || item.cveID || "CVE non précisée";
    const title = item.title || item.vulnerabilityName || item.shortDescription || "Description non disponible";
    const description = item.shortDescription || item.description || "Consultez la fiche officielle pour les détails techniques.";
    const product = [item.vendorProject, item.product].filter(Boolean).join(" · ");
    return `<article class="cve-card"><div class="cve-id">${escapeHTML(cve)}</div><div><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p>${product ? `<div class="cve-product">${escapeHTML(product)}</div>` : ""}</div><span class="cve-date">${escapeHTML(safeDate(item.dateAdded || item.date))}</span></article>`;
  }).join("");
}

function renderCommunity(data) {
  const items = data.community || [];
  const product = $("community-product").value;
  const version = $("community-version").value.trim().toLowerCase();
  const state = $("community-state").value;
  const query = $("community-search").value.trim().toLowerCase();
  const filtered = items.filter(item => {
    const searchable = [item.title, item.symptom, item.impact, item.product, item.versionLabel, ...(item.versions || [])].join(" ").toLowerCase();
    return (!product || item.product === product) &&
      (!version || searchable.includes(version)) &&
      (!state || item.status === state) &&
      (!query || searchable.includes(query));
  });
  const status = data.communityStatus;
  $("community-status").className = "community-status " + (status && status.status === "ok" ? "is-ok" : "is-partial");
  $("community-status").textContent = status
    ? `Collecte ${status.status === "ok" ? "complète" : status.status === "partial" ? "partielle" : "en échec"} · ${safeDate(status.checkedAt)} · ${(status.successfulProducts || []).length}/6 rubriques consultées${(status.failedProducts || []).length ? " · " + status.failedProducts.join(" | ") : ""}`
    : "Aucun état de collecte forum fourni.";
  if (!filtered.length) {
    $("community-list").innerHTML = '<div class="empty-card">Aucun sujet correspondant. Une rubrique inaccessible ne signifie pas qu’il n’existe aucun bug.</div>';
    return;
  }
  $("community-list").innerHTML = filtered.slice(0, 80).map(item => {
    const url = /^https:\/\//i.test(item.url || "") ? item.url : "https://community.fortinet.com/";
    const versions = (item.versions && item.versions.length) ? item.versions.join(", ") : "non précisé";
    return `<article class="community-card">
      <div class="community-card-head"><span class="community-product">${escapeHTML(item.product || "Produit non précisé")}</span><span class="community-version">Version : ${escapeHTML(versions)}</span></div>
      <h3><a href="${escapeHTML(url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.title || "Sujet sans titre")} ↗</a></h3>
      <p>${escapeHTML(item.symptom || item.title || "Symptôme non précisé")}</p>
      <div class="community-meta"><span>${escapeHTML(item.status || "statut à confirmer")}</span><span>Publié : ${escapeHTML(safeDate(item.publishedAt))}</span><span>Confiance : ${escapeHTML(item.confidence || "à confirmer")}</span></div>
      <p class="community-impact"><strong>Impact :</strong> ${escapeHTML(item.impact || "à confirmer")}</p>
      <p class="community-impact"><strong>Résolution :</strong> ${escapeHTML(item.resolution || "non précisé")} · <strong>Version corrigée :</strong> ${escapeHTML(item.fixedVersion || "à confirmer")}</p>
    </article>`;
  }).join("");
}

function updateDashboard(data) {
  currentData = { ...fallback, ...data };
  const fortinet = currentData.fortinet || [];
  const cyber = currentData.cyber || [];
  const kev = currentData.kev || [];
  $("metric-fortinet").textContent = fortinet.length;
  $("metric-kev").textContent = kev.length;
  $("metric-cyber").textContent = cyber.length;
  const updated = currentData.generatedAt;
  $("metric-updated").textContent = updated ? new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" }).format(new Date(updated)) : "—";
  $("metric-updated-detail").textContent = updated ? `Données du ${safeDate(updated)}` : "Pas encore de synchronisation";
  $("sync-status").textContent = updated ? `Mis à jour le ${safeDate(updated)}` : "Données en attente";
  $("fortinet-list").innerHTML = renderArticles(fortinet);
  $("cyber-list").innerHTML = renderCyber(cyber);
  $("cve-list").innerHTML = renderKev(kev, $("cve-search").value);
  renderCommunity(currentData);
}
async function loadData() {
  const button = $("refresh-btn");
  button.disabled = true;
  button.innerHTML = "↻ <span>Chargement…</span>";
  try {
    const response = await fetch(`${DATA_URL}?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    updateDashboard(await response.json());
  } catch (error) {
    $("sync-status").textContent = "Flux indisponibles";
    if (!currentData.generatedAt) {
      $("fortinet-list").innerHTML = '<div class="error-card">Les données ne sont pas encore disponibles. Vérifie que le workflow de synchronisation a tourné et que le fichier data/veille.json est publié.</div>';
      $("cyber-list").innerHTML = '<div class="empty-card">Les actualités apparaîtront après la première synchronisation.</div>';
      $("cve-list").innerHTML = '<div class="empty-card">Le catalogue CISA apparaîtra après la première synchronisation.</div>';
    }
    console.error("Impossible de charger la veille :", error);
  } finally {
    button.disabled = false;
    button.innerHTML = "↻ <span>Actualiser</span>";
  }
}
$("refresh-btn").addEventListener("click", loadData);
$("cve-search").addEventListener("input", () => {
  $("cve-list").innerHTML = renderKev(currentData.kev || [], $("cve-search").value);
});
loadData();
["community-product", "community-version", "community-state", "community-search"].forEach(id => {
  $(id).addEventListener("input", () => renderCommunity(currentData));
  $(id).addEventListener("change", () => renderCommunity(currentData));
});
