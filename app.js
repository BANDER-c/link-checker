(function (global) {
  "use strict";

  const BACKEND_URL = "https://lc-backend-7viz.onrender.com";
  let activeScanId = 0;

  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }
  function addText(parent, tag, text, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = String(text == null ? "" : text);
    parent.appendChild(node);
    return node;
  }

  function getErrorMessage(data, fallback) {
    if (typeof data === "string" && data.trim()) return data.trim();
    if (data && typeof data.error === "string" && data.error.trim()) return data.error.trim();
    if (data && data.error && typeof data.error === "object") {
      if (typeof data.error.message === "string" && data.error.message.trim()) return data.error.message.trim();
      if (typeof data.error.code === "string" && data.error.code.trim()) return `${data.error.code}: تعذر إكمال الطلب.`;
    }
    if (data && data.message && typeof data.message === "string") return data.message.trim();
    return fallback;
  }

  function normalizeInput(value) {
    let url = String(value || "").trim();
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    return url;
  }

  function getLevelInfo(score) {
    const level = window.CyberLinkAnalyzer.getRiskLevel(score);
    return {
      level,
      title: ({ low: "منخفض", medium: "متوسط", high: "مرتفع", critical: "حرج" })[level],
      icon: ({ low: "🟢", medium: "🟡", high: "🟠", critical: "🔴" })[level]
    };
  }

  function recommendationFor(score) {
    if (score >= 75) return "توجد مؤشرات متعددة وقوية تستحق الحذر الشديد. لا تفتح الرابط قبل التحقق من مصدره ووجهته.";
    if (score >= 50) return "توجد عدة مؤشرات تستحق الحذر. تحقق من النطاق والمرسل والوجهة قبل المتابعة.";
    if (score >= 25) return "توجد مؤشرات تستحق التحقق قبل فتح الرابط.";
    return "لم يتم اكتشاف مؤشرات خطورة واضحة ضمن الفحوصات المتاحة.";
  }

  function renderLocalResult(url, analysis, brandResult) {
    const result = $("result");
    clear(result);
    result.style.display = "block";
    result.className = "result " + analysis.level;

    const header = document.createElement("div");
    header.className = "result-header";
    const info = getLevelInfo(analysis.score);
    addText(header, "div", `${info.icon} مستوى المؤشر: ${info.title}`, "result-level");
    addText(header, "div", "Risk Score", "result-label");
    result.appendChild(header);

    const score = document.createElement("div");
    score.className = "score-display";
    addText(score, "strong", `${analysis.score}/100`, "score-number");
    addText(score, "span", "مؤشر الخطورة المحلي", "score-caption");
    result.appendChild(score);

    const barWrap = document.createElement("div");
    barWrap.className = "risk-bar";
    const bar = document.createElement("div");
    bar.className = "risk-bar-fill";
    bar.style.width = `${analysis.score}%`;
    barWrap.appendChild(bar);
    result.appendChild(barWrap);

    addText(result, "p", recommendationFor(analysis.score), "recommendation");
    addText(result, "p", `الرابط الذي تم تحليله: ${url}`, "analyzed-url");

    const evidenceTitle = document.createElement("h3");
    evidenceTitle.textContent = `🔎 المؤشرات المكتشفة (${analysis.indicators.length})`;
    result.appendChild(evidenceTitle);

    const list = document.createElement("div");
    list.className = "indicator-list";
    if (!analysis.indicators.length) {
      const empty = document.createElement("div");
      empty.className = "indicator-empty";
      empty.textContent = "لا توجد مؤشرات مكتشفة في الفحوصات المحلية الحالية.";
      list.appendChild(empty);
    } else {
      analysis.indicators.forEach(item => {
        const card = document.createElement("article");
        card.className = "indicator-card";
        const top = document.createElement("div");
        top.className = "indicator-top";
        addText(top, "strong", item.name || item.title);
        addText(top, "span", `+${item.weight} · ${item.severity}`);
        card.appendChild(top);
        addText(card, "p", item.description);
        addText(card, "small", `Evidence: ${item.evidence}`);
        list.appendChild(card);
      });
    }
    result.appendChild(list);

    const meta = document.createElement("div");
    meta.className = "metadata-grid";
    const entries = [
      ["Protocol", analysis.metadata.protocol],
      ["Hostname", analysis.metadata.hostname],
      ["Subdomains", analysis.metadata.subdomainCount],
      ["URL length", analysis.metadata.urlLength],
      ["Hostname length", analysis.metadata.hostnameLength],
      ["Port", analysis.metadata.port == null ? "افتراضي" : analysis.metadata.port]
    ];
    entries.forEach(([label, value]) => {
      const box = document.createElement("div");
      addText(box, "small", label);
      addText(box, "strong", value);
      meta.appendChild(box);
    });
    result.appendChild(meta);

    if (brandResult && brandResult.detected && !brandResult.official) {
      const brandBox = document.createElement("div");
      brandBox.className = "brand-note";
      addText(brandBox, "strong", "🧩 Brand Impersonation");
      addText(brandBox, "p", `تشابه محتمل مع ${brandResult.brand} (${brandResult.similarity}%).`);
      addText(brandBox, "small", "التشابه Evidence وليس حكمًا قطعيًا على التصيد.");
      result.appendChild(brandBox);
    }

    const actions = document.createElement("div");
    actions.className = "result-actions";
    const externalButton = document.createElement("button");
    externalButton.type = "button";
    externalButton.className = "secondary-btn";
    externalButton.id = "externalCheckBtn";
    externalButton.textContent = "🛡️ تحقق خارجي عبر VirusTotal";
    actions.appendChild(externalButton);
    result.appendChild(actions);

    const privacy = document.createElement("p");
    privacy.className = "privacy-inline";
    privacy.textContent = "لن يتم إرسال الرابط إلى VirusTotal إلا عند اختيار التحقق الخارجي.";
    result.appendChild(privacy);

    externalButton.addEventListener("click", () => runExternalScan(url, analysis, activeScanId));
  }

  function renderExternalPending(message) {
    const result = $("result");
    const box = document.createElement("div");
    box.className = "external-box loading";
    addText(box, "strong", "⏳ VirusTotal");
    addText(box, "p", message);
    result.appendChild(box);
  }

  function renderExternalResult(stats, analysis, scanId) {
    if (scanId !== activeScanId) return;
    const result = $("result");
    const existing = result.querySelector(".external-box");
    if (existing) existing.remove();

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const total = malicious + suspicious + harmless + undetected;

    const box = document.createElement("div");
    box.className = "external-box";
    addText(box, "strong", "🛡️ External Reputation");
    addText(box, "p", `${malicious + suspicious} engines flagged · ${harmless} clean · ${undetected} undetected`);

    const grid = document.createElement("div");
    grid.className = "vt-grid";
    [["ضار", malicious], ["مشبوه", suspicious], ["سليم", harmless], ["غير مكتشف", undetected]].forEach(([label, value]) => {
      const item = document.createElement("div");
      addText(item, "small", label);
      addText(item, "strong", value);
      grid.appendChild(item);
    });
    box.appendChild(grid);

    const assessment = malicious > 0
      ? "تم العثور على مؤشرات خارجية ضارة من بعض المحركات؛ تعامل مع الرابط بحذر شديد."
      : suspicious > 0
        ? "تم العثور على مؤشرات خارجية مشبوهة؛ يلزم التحقق من المصدر والوجهة."
        : "لم يتم اكتشاف مؤشرات ضارة واضحة من النتائج الخارجية المتاحة.";
    addText(box, "p", `Final Assessment: ${assessment}`);
    addText(box, "small", `إجمالي المحركات التي أعادت إحصاءات: ${total}. نتائج VirusTotal خدمة خارجية وليست ضمانًا مطلقًا.`);
    result.appendChild(box);
  }

  async function fetchJSON(url, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      const data = await response.json().catch(() => ({}));
      return { response, data };
    } finally {
      clearTimeout(timeout);
    }
  }

  function renderExternalIncomplete(message) {
    const result = $("result");
    const existing = result.querySelector(".external-box");
    if (existing) existing.remove();
    const box = document.createElement("div");
    box.className = "external-box error";
    addText(box, "strong", "ℹ️ التحقق الخارجي غير مكتمل");
    addText(box, "p", message);
    addText(box, "small", "نتيجة التحليل المحلي ما زالت صالحة للعرض ولا تعتمد على توفر VirusTotal.");
    result.appendChild(box);
  }

  async function runExternalScan(url, localAnalysis, scanId) {
    const button = $("externalCheckBtn");
    let canonicalUrl;
    try {
      const parsed = new URL(String(url || "").trim());
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("unsupported-protocol");
      if (parsed.username || parsed.password) {
        renderExternalIncomplete("لن يتم إرسال رابط يحتوي على بيانات userinfo إلى الخدمة الخارجية حفاظًا على الخصوصية. التحليل المحلي متاح دون إرسال الرابط.");
        return;
      }
      canonicalUrl = parsed.href;
    } catch (_) {
      renderExternalIncomplete("تعذر تجهيز الرابط بصيغة HTTP/HTTPS صحيحة قبل إرساله إلى VirusTotal.");
      return;
    }

    if (button) { button.disabled = true; button.textContent = "⏳ جاري بدء التحقق الخارجي..."; }
    renderExternalPending("سيتم إرسال الرابط إلى Backend المشروع ثم إلى VirusTotal. لم يتم فتح الرابط في المتصفح.");

    try {
      // The external request is deliberately bounded. Local analysis never waits
      // for this request, and a slow VT service cannot keep the page stuck.
      const started = await fetchJSON(`${BACKEND_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: canonicalUrl })
      }, 15000);

      if (!started.response.ok) throw new Error(getErrorMessage(started.data, "تعذر بدء الفحص الخارجي."));

      const directStats = started.data && started.data.data && started.data.data.attributes && started.data.data.attributes.last_analysis_stats;
      if (directStats) {
        renderExternalResult(directStats, localAnalysis, scanId);
        if (button) { button.disabled = false; button.textContent = "🔄 إعادة التحقق الخارجي"; }
        return;
      }

      const analysisId = started.data && started.data.data && started.data.data.id;
      if (!analysisId) throw new Error("لم يتم الحصول على رقم التحليل الخارجي.");

      const quickDelays = [0, 600, 1000, 1500, 2200, 3000];
      for (const delay of quickDelays) {
        if (delay) await new Promise(resolve => setTimeout(resolve, delay));
        if (scanId !== activeScanId) return;
        try {
          const check = await fetchJSON(`${BACKEND_URL}/scan/${encodeURIComponent(analysisId)}`, {}, 6000);
          if (!check.response.ok) throw new Error(getErrorMessage(check.data, "تعذر الحصول على نتيجة VirusTotal."));
          const analysis = check.data && check.data.data;
          if (analysis && analysis.attributes && analysis.attributes.status === "completed") {
            renderExternalResult(analysis.attributes.stats || {}, localAnalysis, scanId);
            if (button) { button.disabled = false; button.textContent = "🔄 إعادة التحقق الخارجي"; }
            return;
          }
        } catch (pollError) {
          // A transient polling failure should not hide the already-rendered local result.
          if (delay === quickDelays[quickDelays.length - 1]) throw pollError;
        }
      }

      renderExternalPending("التحليل الخارجي ما زال قيد المعالجة. يمكنك متابعة النتيجة المحلية، وستستطيع إعادة التحقق لاحقًا.");
      if (button) { button.disabled = false; button.textContent = "🔄 إعادة التحقق الخارجي"; }

      // Continue in the background, but never leave an endless loading state.
      const backgroundDelays = [5000, 7000, 9000, 11000];
      for (const delay of backgroundDelays) {
        await new Promise(resolve => setTimeout(resolve, delay));
        if (scanId !== activeScanId) return;
        try {
          const check = await fetchJSON(`${BACKEND_URL}/scan/${encodeURIComponent(analysisId)}`, {}, 6000);
          if (!check.response.ok) break;
          const analysis = check.data && check.data.data;
          if (analysis && analysis.attributes && analysis.attributes.status === "completed") {
            renderExternalResult(analysis.attributes.stats || {}, localAnalysis, scanId);
            return;
          }
        } catch (_) {
          // Keep local analysis usable; retry is available to the user.
        }
      }
      renderExternalIncomplete("لم تكتمل نتيجة VirusTotal ضمن فترة الانتظار. يمكنك إعادة التحقق دون التأثير على التحليل المحلي.");
    } catch (error) {
      if (scanId !== activeScanId) return;
      const message = error.name === "AbortError"
        ? "انتهت مهلة الاتصال بالخدمة الخارجية. يمكنك إعادة المحاولة لاحقًا؛ نتيجة التحليل المحلي لا تتأثر."
        : (String(error.message || "").toLowerCase().includes("unable to canonicalize url")
          ? "VirusTotal لم يتمكن من تحويل هذا الرابط إلى صيغة قابلة للتحليل. قد يحدث ذلك مع بعض الروابط غير القابلة للمعالجة خارجيًا."
          : getErrorMessage(error, "تعذر إكمال التحقق الخارجي حاليًا."));
      renderExternalIncomplete(message);
      if (button) { button.disabled = false; button.textContent = "🛡️ إعادة التحقق عبر VirusTotal"; }
    }
  }

  function analyzeURL() {
    const input = $("urlInput");
    const result = $("result");
    if (!input || !result) return;
    const value = input.value.trim();
    if (!value) {
      clear(result);
      result.style.display = "block";
      result.className = "result warning";
      addText(result, "h2", "⚠️ أدخل رابطًا أولًا");
      addText(result, "p", "ضع الرابط في الخانة ثم اضغط فحص الرابط.");
      return;
    }

    const url = normalizeInput(value);
    const analysis = window.CyberLinkAnalyzer.analyzeURL(url);
    if (!analysis.valid) {
      clear(result);
      result.style.display = "block";
      result.className = "result danger";
      addText(result, "h2", "❌ الرابط غير صالح");
      addText(result, "p", analysis.error || "تعذر تحليل الرابط.");
      return;
    }

    activeScanId += 1;
    const scanId = activeScanId;
    const brandResult = window.CyberLinkBrandDetector
      ? window.CyberLinkBrandDetector.detectBrandImpersonation(url)
      : null;

    if (brandResult && brandResult.detected && !brandResult.official) {
      const brandIndicator = {
        id: "brand-similarity",
        name: "تشابه محتمل مع علامة معروفة",
        title: "تشابه محتمل مع علامة معروفة",
        description: brandResult.message,
        detected: true,
        weight: 22,
        severity: "medium",
        evidence: `brand=${brandResult.brand}; similarity=${brandResult.similarity}%`
      };
      analysis.indicators = [...analysis.indicators, brandIndicator];
      analysis.score = Math.min(100, analysis.indicators.reduce((sum, item) => sum + Number(item.weight || 0), 0));
      analysis.level = window.CyberLinkAnalyzer.getRiskLevel(analysis.score);
    }

    renderLocalResult(url, analysis, brandResult);
    window.LC_LAST_ANALYSIS = { url, analysis, brandResult };
  }

  function initTheme() {
    const button = $("themeBtn");
    if (!button) return;
    const saved = localStorage.getItem("lc-theme");
    if (saved === "dark") document.body.classList.add("dark");
    button.textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
    button.addEventListener("click", () => {
      document.body.classList.toggle("dark");
      const dark = document.body.classList.contains("dark");
      button.textContent = dark ? "☀️" : "🌙";
      localStorage.setItem("lc-theme", dark ? "dark" : "light");
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    const input = $("urlInput");
    if (input) input.addEventListener("keydown", e => { if (e.key === "Enter") analyzeURL(); });
  });

  global.analyzeURL = analyzeURL;
  global.CyberLinkApp = { analyzeURL, runExternalScan };
})(window);
