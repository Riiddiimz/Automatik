const DATA_URL = "data/veille.json";
const fallback = { generatedAt: null, fortinet: [], cyber: [], kev: [], errors: [] };
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
  const filtered = items.filter(item => [item.cve, item.cveID, item.title, item.vulnerabilityName, item.vendorProject, item.product, item.shortDescription, item.description, item.requiredAction, item.notes].filter(Boolean).join(" ").toLowerCase().includes(query));
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

const COMMUNITY_URL = "data/community.json";
let communityData = { topics: [], incidents: [], generatedAt: null, partial: false, errors: [] };

function renderCommunity() {
  const query = ($("community-search").value || "").trim().toLowerCase();
  const product = $("community-product").value;
  const version = $("community-version").value;
  const status = $("community-status-filter").value;
  const incidents = (communityData.incidents || []).filter(item => {
    const sourceText = (item.sources || []).map(source => [source.title, source.summary].join(" ")).join(" ");
    const text = [item.title, item.summary, item.symptom, item.impact, item.solution, item.status, sourceText, ...(item.products || []), ...(item.versions || []), ...(item.versionFamilies || [])].join(" ").toLowerCase();
    return (!query || text.includes(query))
      && (!product || (item.products || []).includes(product))
      && (!version || (item.versionFamilies || []).includes(version))
      && (!status || (item.status || "À vérifier") === status);
  });
  $("community-count").textContent = `${incidents.length} problème(s)`;
  if (!incidents.length) {
    $("community-list").innerHTML = '<div class="empty-card">Aucun point de vigilance ne correspond aux critères retenus. Les signalements isolés non documentés sont exclus.</div>';
    return;
  }
  $("community-list").innerHTML = incidents.slice(0, 100).map(item => {
    const products = (item.products || []).map(escapeHTML).join(" · ") || "Produit à confirmer";
    const families = (item.versionFamilies || []).map(v => escapeHTML(v) + ".x").join(", ");
    const exact = (item.versions || []).map(v => escapeHTML(v)).join(", ");
    const versionMeta = families
      ? `<span>Famille(s) : ${families}</span>${exact ? `<span>Versions exactes : ${exact}</span>` : ""}`
      : `<span>Version : non précisée par la source</span>`;
    const sources = (item.sources || []).slice(0, 5).map(source => {
      const url = /^https:\/\//i.test(source.url || "") ? source.url : "https://community.fortinet.com/";
      const sourceLabel = source.sourceType === "fortinet_article" ? "Article Fortinet" : source.sourceType === "forum_discussion" ? "Discussion utilisateur" : "Source";
      return `<li><a href="${escapeHTML(url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(source.title || "Source")} ↗</a><span>${escapeHTML(sourceLabel)} · ${escapeHTML(safeDate(source.date))}</span></li>`;
    }).join("");
    const extra = Math.max(0, (item.sources || []).length - 5);
    return `<article class="community-card incident-card">
      <div class="community-card-top"><span class="community-products">${products}</span><span class="community-status-badge">${escapeHTML(item.status || "Point de vigilance")}</span></div>
      <h3>${escapeHTML(item.title || "Point de vigilance Fortinet")}</h3>
      <div class="incident-details">
        <section class="incident-detail"><strong>Symptôme</strong><p>${escapeHTML(item.symptom || item.summary || "Résumé indisponible : consulter les sources.")}</p></section>
        <section class="incident-detail"><strong>Impact</strong><p>${escapeHTML(item.impact || "Non précisé par la source.")}</p></section>
        <section class="incident-detail"><strong>Solution / correctif</strong><p>${escapeHTML(item.solution || "Non précisé dans les sources consultées.")}</p></section>
      </div>
      <div class="community-meta"><span>${item.forumReportCount ?? 0} signalement(s) utilisateur(s) distinct(s)</span>${item.documentedSourceCount ? `<span>${item.documentedSourceCount} source(s) Fortinet documentée(s)</span>` : ""}${versionMeta}<span>Dernière activité source : ${escapeHTML(safeDate(item.lastSeen))}</span></div>
      <details class="incident-sources"><summary>Consulter les sources (${(item.sources || []).length})</summary><ul>${sources}</ul>${extra ? `<p class="source-extra">Et ${extra} autre(s) source(s) dans ce regroupement.</p>` : ""}</details>
      <div class="community-caution">${escapeHTML(item.confidence || "Critères de preuve appliqués.")}. Les versions, symptômes et sources restent consultables avant toute décision de mise à niveau.</div>
    </article>`;
  }).join("");
}
async function loadCommunity() {
  try {
    const response = await fetch(`${COMMUNITY_URL}?t=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    communityData = await response.json();
    const versions = [...new Set((communityData.incidents || []).flatMap(item => item.versionFamilies || []))].sort((a, b) => a.localeCompare(b, "fr", { numeric: true }));
    $("community-version").innerHTML = '<option value="">Toutes les familles</option>' + versions.map(version => `<option value="${escapeHTML(version)}">${escapeHTML(version)}.x</option>`).join("");
    const statuses = [...new Set((communityData.incidents || []).map(item => item.status || "À vérifier"))].sort((a, b) => a.localeCompare(b, "fr"));
    $("community-status-filter").innerHTML = '<option value="">Tous les statuts</option>' + statuses.map(status => `<option value="${escapeHTML(status)}">${escapeHTML(status)}</option>`).join("");
    const date = communityData.generatedAt ? safeDate(communityData.generatedAt) : "jamais";
    $("community-status").textContent = communityData.partial
      ? `Collecte partielle — historique conservé · dernière tentative : ${date}`
      : `Dernière collecte : ${date} · ${communityData.incidentCount ?? communityData.incidents?.length ?? 0} points de vigilance retenus depuis ${communityData.topics?.length || 0} sujets`;
    const warnings = (communityData.errors || []).filter(Boolean);
    if (warnings.length) {
      $("community-status").textContent += ` · ${warnings.length} avertissement(s) : ${warnings[0]}`;
    }
    $("community-status").title = [communityData.synthesisNote, ...warnings].filter(Boolean).join("\n\n");
    renderCommunity();
  } catch (error) {
    $("community-status").textContent = "Flux Community indisponible. L’historique affiché n’a pas pu être chargé.";
    $("community-list").innerHTML = '<div class="error-card">Vérifie que data/community.json est publié et consulte les exécutions du workflow Collecte Fortinet Community.</div>';
    console.error("Impossible de charger la veille Community :", error);
  }
}
function updateDashboard(data) {
  currentData = { ...fallback, ...data };
  const health = $("data-health");
  const sourceErrors = Array.isArray(currentData.errors) ? currentData.errors.filter(Boolean) : [];
  if (health) {
    if (sourceErrors.length) {
      const details = sourceErrors.slice(0, 3).join(" · ");
      const extra = sourceErrors.length > 3 ? ` · +${sourceErrors.length - 3} autre(s) erreur(s)` : "";
      health.hidden = false;
      health.textContent = `Actualisation partielle : ${sourceErrors.length} source(s) en erreur. Les données précédentes ont pu être conservées ; vérifie les dates et les liens avant toute décision. Détails : ${details}${extra}`;
    } else {
      health.hidden = true;
      health.textContent = "";
    }
  }
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
$("refresh-btn").addEventListener("click", () => { loadData(); loadCommunity(); });
$("cve-search").addEventListener("input", () => {
  $("cve-list").innerHTML = renderKev(currentData.kev || [], $("cve-search").value);
});
loadData();
loadCommunity();
["community-search", "community-product", "community-version", "community-status-filter"].forEach(id => {
  $(id).addEventListener(id === "community-search" ? "input" : "change", renderCommunity);
});
