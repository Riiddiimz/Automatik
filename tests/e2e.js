const assert = require("node:assert/strict");
const { chromium } = require("playwright");

(async () => {
  const baseUrl = process.env.BASE_URL || "http://127.0.0.1:4173";
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const pageErrors = [];
  page.on("pageerror", error => pageErrors.push(error.message));

  try {
    const dashboardResponse = await page.request.get(`${baseUrl}/data/veille.json`);
    assert.equal(dashboardResponse.status(), 200, "veille.json doit être servi");
    const dashboardData = await dashboardResponse.json();
    for (const key of ["fortinet", "cyber", "kev"]) {
      assert.ok(Array.isArray(dashboardData[key]), `veille.json doit contenir un tableau ${key}`);
    }

    const dataResponse = await page.request.get(`${baseUrl}/data/community.json`);
    assert.equal(dataResponse.status(), 200, "community.json doit être servi");
    const data = await dataResponse.json();

    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#metric-fortinet")?.textContent !== "—");
    assert.equal(await page.locator("#metric-fortinet").innerText(), String(dashboardData.fortinet.length));
    assert.equal(await page.locator("#metric-cyber").innerText(), String(dashboardData.cyber.length));
    assert.equal(await page.locator("#metric-kev").innerText(), String(dashboardData.kev.length));
    const sourceErrors = Array.isArray(dashboardData.errors) ? dashboardData.errors : [];
    const healthBanner = page.locator("#data-health");
    assert.equal(await healthBanner.isVisible(), sourceErrors.length > 0, "les erreurs de flux doivent être signalées dans le tableau de bord");
    if (sourceErrors.length) assert.match(await healthBanner.innerText(), /Actualisation partielle/);
    assert.match(await page.title(), /Automatik/i);
    await page.locator("#community-status").waitFor();
    await page.waitForFunction(() => {
      const status = document.querySelector("#community-status")?.textContent || "";
      return !status.includes("En attente de la première collecte");
    });
    assert.match(await page.locator("#community-status").innerText(), /points de vigilance retenus|Collecte partielle|Flux Community indisponible/);

    const cards = page.locator("#community-list .incident-card");
    assert.equal(await cards.count(), Math.min(data.incidents?.length || 0, 100), "les fiches rendues doivent correspondre au JSON");

    await page.locator("#community-search").fill("terme-inexistant-automatik-e2e");
    assert.equal(await cards.count(), 0, "la recherche doit filtrer les fiches");
    assert.match(await page.locator("#community-list").innerText(), /Aucun point de vigilance/);
    await page.locator("#community-search").fill("");

    const matchingProductCount = (data.incidents || []).filter(item => (item.products || []).includes("FortiGate")).length;
    await page.locator("#community-product").selectOption("FortiGate");
    assert.equal(await cards.count(), matchingProductCount, "le filtre produit doit fonctionner");
    for (const productLabel of await page.locator(".incident-card .community-products").allInnerTexts()) {
      assert.match(productLabel, /FortiGate/);
    }
    await page.locator("#community-product").selectOption("");

    const versionSelect = page.locator("#community-version");
    const versionOptions = await versionSelect.locator("option").evaluateAll(options => options.map(option => option.value).filter(Boolean));
    if (versionOptions.length) {
      const version = versionOptions[0];
      const expected = (data.incidents || []).filter(item => (item.versionFamilies || []).includes(version)).length;
      await versionSelect.selectOption(version);
      assert.equal(await cards.count(), expected, "le filtre de famille de version doit fonctionner");
      await versionSelect.selectOption("");
    }

    const statusSelect = page.locator("#community-status-filter");
    const statusOptions = await statusSelect.locator("option").evaluateAll(options => options.map(option => option.value).filter(Boolean));
    if (statusOptions.length) {
      const status = statusOptions[0];
      const expected = (data.incidents || []).filter(item => (item.status || "À vérifier") === status).length;
      await statusSelect.selectOption(status);
      assert.equal(await cards.count(), expected, "le filtre de statut doit fonctionner");
      await statusSelect.selectOption("");
    }

    if ((data.incidents || []).length) {
      const firstCard = cards.first();
      for (const label of ["Symptôme", "Impact", "Solution / correctif"]) {
        assert.equal(await firstCard.getByText(label, { exact: true }).count(), 1, `le champ "${label}" doit être affiché`);
      }
      const firstDetails = page.locator("#community-list .incident-sources").first();
      await firstDetails.locator("summary").click();
      assert.equal(await firstDetails.locator("ul").isVisible(), true, "les sources doivent pouvoir être dépliées");
      const firstLink = firstDetails.locator("a").first();
      if (await firstLink.count()) {
        assert.match(await firstLink.getAttribute("href"), /^https:\/\//, "les sources doivent avoir un lien HTTPS");
      }
    }

    await page.setViewportSize({ width: 390, height: 844 });
    const widthCheck = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      content: document.documentElement.scrollWidth
    }));
    assert.ok(widthCheck.content <= widthCheck.viewport + 2, `débordement horizontal mobile: ${JSON.stringify(widthCheck)}`);

    await page.locator("#refresh-btn").click();
    await page.locator("#refresh-btn").waitFor({ state: "visible" });
    await page.waitForFunction(() => !document.querySelector("#refresh-btn")?.disabled);
    assert.deepEqual(pageErrors, [], "aucune erreur JavaScript non gérée ne doit apparaître");
    console.log(`Playwright OK — ${data.incidents?.length || 0} fiche(s), filtres, sources, mobile et actualisation vérifiés.`);
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
