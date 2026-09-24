(function (global) {
  "use strict";

  const TRUSTED_BRANDS = global.CyberLinkTrustedBrands || (typeof require === "function" ? require("./data/trusted-brands.js") : []);

  const SUBSTITUTIONS = Object.freeze({ "0": "o", "1": "l", "3": "e", "4": "a", "5": "s" });
  const VISUAL_SUBSTITUTIONS = Object.freeze({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "@": "a", "$": "s"
  });

  function normalize(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/[01345@$]/g, char => VISUAL_SUBSTITUTIONS[char] || char)
      .replace(/[^a-z0-9]/g, "");
  }

  function levenshtein(a, b) {
    const first = String(a), second = String(b);
    const prev = Array.from({ length: second.length + 1 }, (_, i) => i);
    for (let i = 1; i <= first.length; i++) {
      const current = [i];
      for (let j = 1; j <= second.length; j++) {
        const cost = first[i - 1] === second[j - 1] ? 0 : 1;
        current[j] = Math.min(current[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      }
      for (let j = 0; j < current.length; j++) prev[j] = current[j];
    }
    return prev[second.length];
  }

  function similarity(a, b) {
    const first = normalize(a), second = normalize(b);
    if (!first || !second) return 0;
    if (first === second) return 100;
    const maxLength = Math.max(first.length, second.length);
    return Math.round(((maxLength - levenshtein(first, second)) / maxLength) * 100);
  }

  function getRegisteredDomain(hostname) {
    const labels = String(hostname || "").toLowerCase().split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");
    const secondLevelTlds = new Set(["com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "co.uk", "org.uk", "com.au", "co.nz"]);
    const lastTwo = labels.slice(-2).join(".");
    return secondLevelTlds.has(lastTwo) ? labels.slice(-3).join(".") : labels.slice(-2).join(".");
  }

  function isOfficialDomain(hostname, officialDomain) {
    const host = String(hostname || "").toLowerCase();
    const official = String(officialDomain || "").toLowerCase();
    return host === official || host.endsWith("." + official);
  }

  function detectHomoglyphSimilarity(label, brand) {
    const source = String(label || "").toLowerCase();
    const target = String(brand || "").toLowerCase();
    const sourceNormalized = source.split("").map(c => SUBSTITUTIONS[c] || c).join("");
    return similarity(sourceNormalized, target);
  }

  function detectBrandImpersonation(url) {
    let parsed;
    try { parsed = new URL(url); } catch (_) {
      return { detected: false, official: false, brand: null, similarity: 0, matchedLabel: null, message: "تعذر تحليل النطاق." };
    }

    const hostname = parsed.hostname.toLowerCase();
    for (const brand of TRUSTED_BRANDS) {
      for (const domain of brand.domains) {
        if (isOfficialDomain(hostname, domain)) {
          return { detected: false, official: true, brand: brand.name, similarity: 100, matchedLabel: null, message: "النطاق يطابق نطاقًا رسميًا معروفًا." };
        }
      }
    }

    const registeredDomain = getRegisteredDomain(hostname);
    const labels = registeredDomain.split(".").filter(Boolean);
    const domainLabel = labels.length >= 2 ? labels[labels.length - 2] : labels[0] || "";
    let bestMatch = null;

    for (const brand of TRUSTED_BRANDS) {
      const direct = similarity(domainLabel, brand.name);
      const visual = detectHomoglyphSimilarity(domainLabel, brand.name);
      const score = Math.max(direct, visual);
      const normalizedDomain = normalize(domainLabel);
      const normalizedBrand = normalize(brand.name);
      if (score >= 75 && domainLabel.toLowerCase() !== brand.name.toLowerCase()) {
        if (!bestMatch || score > bestMatch.similarity) {
          bestMatch = { brand: brand.name, similarity: score, matchedLabel: domainLabel };
        }
      }
    }

    if (!bestMatch) {
      return { detected: false, official: false, brand: null, similarity: 0, matchedLabel: null, message: "لم يتم اكتشاف تشابه واضح مع علامة معروفة." };
    }

    return {
      detected: true,
      official: false,
      brand: bestMatch.brand,
      similarity: bestMatch.similarity,
      matchedLabel: bestMatch.matchedLabel,
      message: `تم اكتشاف تشابه محتمل مع ${bestMatch.brand} بنسبة تشابه تقريبية ${bestMatch.similarity}%. هذا المؤشر وحده لا يثبت أن الرابط تصيدي.`
    };
  }

  const api = { TRUSTED_BRANDS, normalize, levenshtein, similarity, getRegisteredDomain, isOfficialDomain, detectBrandImpersonation };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof global !== "undefined") global.CyberLinkBrandDetector = api;
})(typeof window !== "undefined" ? window : globalThis);
