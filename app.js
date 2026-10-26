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
    const text = [item.title, item.summary, item.symptom, item.impact, item.solution, item.status, sourceText, ...(item.products || []), ...(item.versions || []), ...(item.versionFamilies || []), ...(item.fixVersions || [])].join(" ").toLowerCase();
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
    const aiReview = item.aiReview && item.aiReview.reviewedAt ? item.aiReview : {};
    const aiReviewPanel = aiReview.reviewedAt
      ? `<div class="incident-ai-review"><span>RELECTURE IA · À VÉRIFIER</span><p>${escapeHTML(aiReview.summary || "Aucune reformulation proposée.")}</p>${aiReview.note ? `<small>${escapeHTML(aiReview.note)}</small>` : ""}</div>`
      : "";
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
    const shortSummary = aiReview.summary || item.summary || item.symptom || "Ouvrir la fiche pour consulter les détails.";
    return `<details class="community-card incident-card incident-accordion">
      <summary class="incident-accordion-summary">
        <span class="incident-summary-main">
          <span class="community-products">${products}</span>
          <strong>${escapeHTML(item.title || "Point de vigilance Fortinet")}</strong>
          <span class="incident-summary-preview">${escapeHTML(shortSummary)}</span>
        </span>
        <span class="incident-summary-side">
          <span class="community-status-badge">${escapeHTML(item.status || "Point de vigilance")}</span>
          <span class="incident-expand-label"><span class="incident-expand-open">Voir les détails</span><span class="incident-expand-close">Réduire</span><span class="incident-chevron" aria-hidden="true">⌄</span></span>
        </span>
      </summary>
      <div class="incident-accordion-body">
        ${aiReviewPanel}
        <div class="incident-details">
          <section class="incident-detail"><strong>Symptôme</strong><p>${escapeHTML(aiReview.symptom || item.symptom || item.summary || "Résumé indisponible : consulter les sources.")}</p></section>
          <section class="incident-detail"><strong>Impact</strong><p>${escapeHTML(aiReview.impact || item.impact || "Non précisé par la source.")}</p></section>
          <section class="incident-detail"><strong>Solution / correctif</strong><p>${escapeHTML(aiReview.solution || item.solution || "Non précisé dans les sources consultées.")}</p></section>
          <section class="incident-detail"><strong>Version de correctif mentionnée</strong><p>${escapeHTML((item.fixVersions || []).join(", ") || "Non précisée par la source.")}</p></section>
        </div>
        <div class="community-meta"><span>${item.forumReportCount ?? 0} signalement(s) utilisateur(s) distinct(s)</span>${item.documentedSourceCount ? `<span>${item.documentedSourceCount} source(s) Fortinet documentée(s)</span>` : ""}${versionMeta}<span>Dernière activité source : ${escapeHTML(safeDate(item.lastSeen))}</span></div>
        <details class="incident-sources"><summary>Consulter les sources (${(item.sources || []).length})</summary><ul>${sources}</ul>${extra ? `<p class="source-extra">Et ${extra} autre(s) source(s) dans ce regroupement.</p>` : ""}</details>
        <div class="community-caution">${escapeHTML(item.confidence || "Critères de preuve appliqués.")}. Les versions, symptômes et sources restent consultables avant toute décision de mise à niveau.</div>
      </div>
    </details>`;
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
      ? `Dernier état partiel publié le ${date} — historique conservé`
      : `Dernier état publié : ${date} · ${communityData.incidentCount ?? communityData.incidents?.length ?? 0} points de vigilance retenus depuis ${communityData.topics?.length || 0} sujets`;
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
  const workflowHealth = $("workflow-health");
  if (workflowHealth) workflowHealth.hidden = page !== "overview";
  const sourceErrors = Array.isArray(currentData.errors) ? currentData.errors.filter(Boolean) : [];
  if (health) {
    if (sourceErrors.length) {
      const details = sourceErrors.slice(0, 3).join(" · ");
      const extra = sourceErrors.length > 3 ? ` · +${sourceErrors.length - 3} autre(s) erreur(s)` : "";
      health.hidden = !document.body.classList.contains("page-overview");
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
const HEALTH_FILES = [
  { key: "veille", label: "Veille cyber officielle", path: "data/health-veille.json" },
  { key: "community", label: "Fortinet Community", path: "data/health-community.json" }
];

function healthDate(value) {
  if (!value) return "Jamais enregistrée";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Date inconnue";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function loadWorkflowHealth() {
  const container = $("workflow-health");
  if (!container) return;
  const results = await Promise.all(HEALTH_FILES.map(async source => {
    try {
      const response = await fetch(`${source.path}?t=${Date.now()}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return { ...source, data: await response.json() };
    } catch (error) {
      return { ...source, error: error.message };
    }
  }));
  const now = Date.now();
  container.innerHTML = results.map(result => {
    if (result.error) {
      return `<article class="workflow-health-card is-unknown"><div class="workflow-health-top"><strong>${escapeHTML(result.label)}</strong><span class="workflow-health-badge">Inconnu</span></div><p>Impossible de charger le statut de cette collecte.</p></article>`;
    }
    const data = result.data || {};
    let status = data.status || "unknown";
    let label = status === "ok" ? "OK" : status === "partial" ? "Partiel" : status === "error" ? "Échec" : "En attente";
    const checked = data.checkedAt ? new Date(data.checkedAt).getTime() : 0;
    const stale = !checked || !Number.isFinite(checked) || now - checked > 12 * 60 * 60 * 1000;
    if (stale && status !== "error") {
      status = "stale";
      label = "À vérifier";
    }
    const detail = status === "error"
      ? (data.message || "La dernière exécution a échoué. Les données déjà publiées peuvent être anciennes.")
      : status === "partial"
        ? (data.message || "La collecte est partielle : certaines sources n'ont pas été actualisées.")
        : status === "stale"
          ? "Aucun état récent reçu depuis plus de 12 heures. Vérifie les exécutions GitHub Actions."
          : status === "ok"
            ? (data.message || "Dernière exécution terminée sans erreur.")
            : "Le statut sera disponible après la prochaine exécution du workflow.";
    const lastSuccess = data.lastSuccessAt ? `Dernière réussite complète : ${healthDate(data.lastSuccessAt)}` : "Aucune réussite complète enregistrée";
    const checkedText = data.checkedAt ? `Dernier contrôle : ${healthDate(data.checkedAt)}` : "Aucun contrôle enregistré";
    const url = /^https:\/\//i.test(data.runUrl || "") ? data.runUrl : "https://github.com/Riiddiimz/Automatik/actions";
    return `<article class="workflow-health-card is-${escapeHTML(status)}">
      <div class="workflow-health-top"><strong>${escapeHTML(result.label)}</strong><span class="workflow-health-badge">${escapeHTML(label)}</span></div>
      <p>${escapeHTML(detail)}</p>
      <div class="workflow-health-meta"><span>${escapeHTML(checkedText)}</span><span>${escapeHTML(lastSuccess)}</span></div>
      <a href="${escapeHTML(url)}" target="_blank" rel="noopener noreferrer">Voir les exécutions GitHub Actions ↗</a>
    </article>`;
  }).join("");
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
loadWorkflowHealth();
["community-search", "community-product", "community-version", "community-status-filter"].forEach(id => {
  $(id).addEventListener(id === "community-search" ? "input" : "change", renderCommunity);
});


// Navigation par pages : un seul espace de veille est visible à la fois.
function activatePage(pageId, updateHash = false) {
  const allowed = new Set(["overview", "fortinet", "community", "cves", "cyber", "sources"]);
  const page = allowed.has(pageId) ? pageId : "overview";
  document.body.classList.toggle("page-overview", page === "overview");
  document.querySelectorAll(".content-section").forEach(section => {
    const active = section.id === page;
    section.classList.toggle("page-visible", active);
    section.hidden = !active;
  });
  document.querySelectorAll(".nav-link").forEach(link => {
    const active = link.getAttribute("href") === `#${page}`;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  const hero = document.querySelector(".hero");
  const metrics = document.querySelector(".metrics");
  const health = $("data-health");
  if (hero) hero.hidden = page !== "overview";
  if (metrics) metrics.hidden = page !== "overview";
  if (health) health.hidden = page !== "overview" || !health.textContent.trim();
  if (updateHash && location.hash !== `#${page}`) history.pushState(null, "", `#${page}`);
  window.scrollTo({ top: 0, behavior: "smooth" });
}
document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", event => {
    const page = (link.getAttribute("href") || "").slice(1);
    if (!page) return;
    event.preventDefault();
    activatePage(page, true);
  });
});
window.addEventListener("hashchange", () => activatePage(location.hash.slice(1)));
window.addEventListener("popstate", () => activatePage(location.hash.slice(1)));
activatePage(location.hash.slice(1) || "overview");
