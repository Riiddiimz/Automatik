const DATA_URL = "data/veille.json";
const fallback = { generatedAt: null, fortinet: [], cyber: [], kev: [], errors: [], fortinetSecurityUpdates: null };
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

function renderFortinetSecurityMatrix(matrix) {
  const items = Array.isArray(matrix && matrix.items) ? matrix.items : [];
  if (!items.length) return "";
  const sourceUrl = /^https:\/\//i.test(matrix.source || "")
    ? matrix.source
    : "https://www.fortinet.com/blog/ciso-collective";
  let disclosureStatus = "Date de publication des avis PSIRT détaillés non précisée.";
  if (matrix.disclosureDate) {
    const date = new Date(matrix.disclosureDate + "T00:00:00Z");
    disclosureStatus = !Number.isNaN(date.getTime()) && date.getTime() > Date.now()
      ? "Avis PSIRT détaillés annoncés pour le " + safeDate(matrix.disclosureDate) + "."
      : "Échéance annoncée (" + safeDate(matrix.disclosureDate) + ") atteinte ou dépassée : vérifier le portail PSIRT.";
  }
  const cards = items.map(item => {
    const product = item.product === "FortiOS" ? "FortiOS · FortiGate" : item.product;
    const availability = item.availableAt ? safeDate(item.availableAt) : (item.availability || "Non précisée");
    return '<article class="security-matrix-item">' +
      '<div class="security-matrix-product"><strong>' + escapeHTML(product || "Produit non précisé") +
      '</strong><span>Branche ' + escapeHTML(item.branch || "non précisée") + '</span></div>' +
      '<dl><div><dt>Versions affectées</dt><dd>' + escapeHTML(item.affectedVersions || "Non précisées") + '</dd></div>' +
      '<div><dt>Version corrigée annoncée</dt><dd>' + escapeHTML(item.fixedVersion || "Non précisée") + '</dd></div>' +
      '<div><dt>Disponibilité annoncée</dt><dd>' + escapeHTML(availability) + '</dd></div></dl></article>';
  }).join("");
  return '<section class="security-matrix-card" aria-label="Matrice officielle des versions Fortinet affectées et corrigées">' +
    '<div class="security-matrix-heading"><div><span class="security-matrix-eyebrow">ANNONCE OFFICIELLE FORTINET</span>' +
    '<h3>' + escapeHTML(matrix.title || "Mises à jour de sécurité Fortinet") + '</h3>' +
    '<p>' + (matrix.publishedAt ? "Publié le " + escapeHTML(safeDate(matrix.publishedAt)) : "Date de publication non précisée") + '</p></div>' +
    '<a href="' + escapeHTML(sourceUrl) + '" target="_blank" rel="noopener noreferrer">Lire l’annonce ↗</a></div>' +
    '<p class="security-matrix-note">' + escapeHTML(matrix.note || "Consulter les avis PSIRT détaillés avant toute décision de remédiation.") + '</p>' +
    '<div class="security-matrix-grid">' + cards + '</div>' +
    '<div class="security-matrix-meta">' + escapeHTML(matrix.severityNote || "") + ' <span>·</span> ' +
    escapeHTML(disclosureStatus) + ' <span>·</span> Vérifiée le ' + escapeHTML(safeDate(matrix.checkedAt)) + '</div></section>';
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
    const sourceText = (item.sources || []).map(source => [
      source.title,
      source.summary,
      ...(Array.isArray(source.replies) ? source.replies.flatMap(reply => [reply.author, reply.authorRole, reply.text]) : [])
    ].join(" ")).join(" ");
    const text = [item.title, item.summary, item.symptom, item.impact, item.solution, item.status, item.fixStatus || "", sourceText, ...(item.products || []), ...(item.versions || []), ...(item.versionFamilies || []), ...(item.versionScopes || []), ...(item.fixVersions || []), ...(item.fixBuilds || []), ...(item.fixEngineReleases || []).flatMap(release => [release.engine, release.version, release.build]), item.fixBuildNote || ""].join(" ").toLowerCase();
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
    const scopes = (item.versionScopes || []).map(escapeHTML).join(" · ");
    const scopeMeta = scopes ? `<span>Périmètre indiqué par la source : ${scopes}</span>` : "";
    const versionMeta = families
      ? `<span>Famille(s) : ${families}</span>${exact ? `<span>Versions citées : ${exact}</span>` : ""}${scopeMeta}`
      : `${scopeMeta || "<span>Version : non précisée par la source</span>"}`;
    const sources = (item.sources || []).slice(0, 5).map(source => {
      const url = /^https:\/\//i.test(source.url || "") ? source.url : "https://community.fortinet.com/";
      const sourceLabel = source.sourceType === "fortinet_article" ? "Article Fortinet" : source.sourceType === "forum_discussion" ? "Discussion utilisateur" : "Source";
      const publicationDate = source.date ? "Publié " + safeDate(source.date) : "Date de publication non précisée";
      const updatedDate = source.updatedAt && source.updatedAt !== source.date
        ? " · mis à jour " + safeDate(source.updatedAt)
        : "";
      const versionScope = source.versionScope
        ? "<span>Périmètre de version : " + escapeHTML(source.versionScope) + "</span>"
        : "";
      const replies = Array.isArray(source.replies) ? source.replies.slice(0, 5) : [];
      const replyItems = replies.map(reply => {
        const role = reply.authorRole ? "Rôle indiqué : " + escapeHTML(reply.authorRole) : "Rôle non précisé";
        const replyDate = reply.date ? " · " + escapeHTML(safeDate(reply.date)) : "";
        return "<li><strong>" + escapeHTML(reply.author || "Auteur non précisé") + "</strong><span>" + role + replyDate + "</span><p>" + escapeHTML(reply.text || "") + "</p></li>";
      }).join("");
      const replyDetails = replyItems
        ? "<details class=\"source-replies\"><summary>Réponses structurées (" + replies.length + ")</summary><ul>" + replyItems + "</ul><small>Le rôle est repris de la page publique; il ne constitue pas une confirmation technique.</small></details>"
        : "";
      return "<li><a href=\"" + escapeHTML(url) + "\" target=\"_blank\" rel=\"noopener noreferrer\">" + escapeHTML(source.title || "Source") + " ↗</a><span>" + escapeHTML(sourceLabel) + " · " + escapeHTML(publicationDate) + escapeHTML(updatedDate) + "</span>" + versionScope + replyDetails + "</li>";
    }).join("");
    const extra = Math.max(0, (item.sources || []).length - 5);
    const engineReleases = (item.fixEngineReleases || []).map(release => {
      const engine = release.engine || "IPS Engine";
      const version = release.version || "version non précisée";
      const build = release.build ? " (Build " + release.build + ")" : " (build non précisé)";
      return "<li>" + escapeHTML(engine) + " " + escapeHTML(version) + escapeHTML(build) + "</li>";
    }).join("");
    const engineReleasePanel = engineReleases
      ? "<section class=\"incident-detail\"><strong>Correctifs du moteur IPS (distincts du firmware FortiOS)</strong><ul>" + engineReleases + "</ul></section>"
      : "";
    const fixVersionLabel = item.fixStatus === "planned"
      ? "Correctif annoncé (non encore disponible)"
      : item.fixStatus === "available"
        ? "Version corrective indiquée comme disponible"
        : item.fixStatus === "mentioned"
          ? "Version corrective mentionnée (disponibilité à confirmer)"
          : "Version de correctif mentionnée";
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
          <section class="incident-detail"><strong>${escapeHTML(fixVersionLabel)}</strong><p>${escapeHTML((item.fixVersions || []).join(", ") || "Non précisée par la source.")}</p></section>
          ${(item.fixBuilds || []).length ? `<section class="incident-detail"><strong>Build correctif mentionné</strong><p>${escapeHTML(item.fixBuilds.join(", "))}</p>${item.fixBuildNote ? `<p>${escapeHTML(item.fixBuildNote)}</p>` : ""}</section>` : ""}
          ${engineReleasePanel}
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
    if (Number.isFinite(Number(communityData.boardPageCount)) && Number(communityData.boardPageCount) > 0) {
      const pageCount = Number(communityData.boardPageCount);
      const topicCount = Number(communityData.boardTopicCount || 0);
      $("community-status").textContent += ` · Index produits : ${pageCount} page(s) consultée(s), ${topicCount} lien(s) repéré(s)`;
    }
    const warnings = (communityData.errors || []).filter(Boolean);
    if (warnings.length) {
      $("community-status").textContent += ` · ${warnings.length} avertissement(s) : ${warnings[0]}`;
    }
    const aiReviewLabels = {
      success: "Relecture IA effectuée",
      partial: "Relecture IA partielle",
      skipped: "Relecture IA non effectuée",
      error: "Relecture IA indisponible",
      pending: "Relecture IA en attente"
    };
    if (communityData.aiReviewStatus) {
      $("community-status").textContent += ` · ${aiReviewLabels[communityData.aiReviewStatus] || "État de la relecture IA inconnu"}`;
    }
    $("community-status").title = [communityData.synthesisNote, ...warnings, communityData.aiReviewMessage].filter(Boolean).join("\n\n");
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
  if (workflowHealth) workflowHealth.hidden = !document.body.classList.contains("page-overview");
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
  $("fortinet-security-matrix").innerHTML = renderFortinetSecurityMatrix(currentData.fortinetSecurityUpdates);
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
$("refresh-btn").addEventListener("click", () => { loadData(); loadCommunity(); loadWorkflowHealth(); });
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
  const workflowHealth = $("workflow-health");
  if (workflowHealth) workflowHealth.hidden = page !== "overview";
  if (hero) hero.hidden = page !== "overview";
  if (metrics) metrics.hidden = page !== "overview";
  if (health) health.hidden = page !== "overview" || !health.textContent.trim();
  if (updateHash && location.hash !== `#${page}`) history.pushState(null, "", `#${page}`);
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
}
document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", event => {
    const page = (link.getAttribute("href") || "").slice(1);
    if (!page) return;
    event.preventDefault();
    activatePage(page, true);
  });
});
function handlePageNavigation() {
  const pageId = location.hash.slice(1);
  // The skip link targets the main landmark, not a dashboard page.
  if (pageId === "main-content") return;
  activatePage(pageId);
}
window.addEventListener("hashchange", handlePageNavigation);
window.addEventListener("popstate", handlePageNavigation);
activatePage(location.hash.slice(1) || "overview");
