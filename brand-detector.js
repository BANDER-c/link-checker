(function (global) {
  "use strict";

  const TRUSTED_BRANDS = global.CyberLinkTrustedBrands || (typeof require === "function" ? require("./data/trusted-brands.js") : []);

  const SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s"
  };

  function normalize(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/[01345]/g, function (char) {
        return SUBSTITUTIONS[char] || char;
      })
      .replace(/[^a-z0-9]/g, "");
  }

  function levenshtein(a, b) {
    const first = String(a);
    const second = String(b);

    const matrix = Array.from(
      { length: first.length + 1 },
      function () {
        return new Array(second.length + 1).fill(0);
      }
    );

    for (let i = 0; i <= first.length; i++) {
      matrix[i][0] = i;
    }

    for (let j = 0; j <= second.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= first.length; i++) {
      for (let j = 1; j <= second.length; j++) {
        const cost = first[i - 1] === second[j - 1] ? 0 : 1;

        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[first.length][second.length];
  }

  function similarity(a, b) {
    const first = normalize(a);
    const second = normalize(b);

    if (!first || !second) {
      return 0;
    }

    if (first === second) {
      return 100;
    }

    const distance = levenshtein(first, second);
    const maxLength = Math.max(first.length, second.length);

    if (!maxLength) {
      return 0;
    }

    return Math.round(
      ((maxLength - distance) / maxLength) * 100
    );
  }

  function getRegisteredDomain(hostname) {
    const labels = String(hostname || "")
      .toLowerCase()
      .split(".")
      .filter(Boolean);

    if (labels.length <= 2) {
      return labels.join(".");
    }

    const secondLevelTlds = [
      "com.sa",
      "net.sa",
      "org.sa",
      "edu.sa",
      "gov.sa",
      "co.uk",
      "org.uk",
      "com.au",
      "co.nz"
    ];

    const lastTwo = labels.slice(-2).join(".");

    if (secondLevelTlds.includes(lastTwo) && labels.length >= 3) {
      return labels.slice(-3).join(".");
    }

    return labels.slice(-2).join(".");
  }

  function isOfficialDomain(hostname, officialDomain) {
    const host = String(hostname || "").toLowerCase();
    const official = String(officialDomain || "").toLowerCase();

    return host === official || host.endsWith("." + official);
  }

  function detectBrandImpersonation(url) {
    let parsed;

    try {
      parsed = new URL(url);
    } catch (error) {
      return {
        detected: false,
        official: false,
        brand: null,
        similarity: 0,
        matchedLabel: null,
        message: "تعذر تحليل النطاق."
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const registeredDomain = getRegisteredDomain(hostname);

    for (const brand of TRUSTED_BRANDS) {
      for (const domain of brand.domains) {
        if (isOfficialDomain(hostname, domain)) {
          return {
            detected: false,
            official: true,
            brand: brand.name,
            similarity: 100,
            matchedLabel: null,
            message: "النطاق يطابق نطاقًا رسميًا معروفًا."
          };
        }
      }
    }

    const labels = hostname
      .split(".")
      .filter(Boolean);

    /*
     * نفحص اسم النطاق المسجل أساسًا.
     * وجود اسم علامة في subdomain وحده لا يكفي للتحذير.
     */
    const registeredLabels = registeredDomain.split(".");

    const domainLabel =
      registeredLabels.length >= 2
        ? registeredLabels[registeredLabels.length - 2]
        : registeredLabels[0];

    let bestMatch = null;

    for (const brand of TRUSTED_BRANDS) {
      const score = similarity(domainLabel, brand.name);

      if (score >= 75 && domainLabel !== normalize(brand.name)) {
        if (!bestMatch || score > bestMatch.similarity) {
          bestMatch = {
            brand: brand.name,
            similarity: score,
            matchedLabel: domainLabel
          };
        }
      }
    }

    if (!bestMatch) {
      return {
        detected: false,
        official: false,
        brand: null,
        similarity: 0,
        matchedLabel: null,
        message: "لم يتم اكتشاف تشابه واضح مع علامة معروفة."
      };
    }

    return {
      detected: true,
      official: false,
      brand: bestMatch.brand,
      similarity: bestMatch.similarity,
      matchedLabel: bestMatch.matchedLabel,
      message:
        "تم اكتشاف تشابه محتمل مع اسم علامة معروفة. " +
        "هذا المؤشر وحده لا يثبت أن الرابط تصيدي."
    };
  }

  const api = {
    TRUSTED_BRANDS,
    normalize,
    levenshtein,
    similarity,
    getRegisteredDomain,
    isOfficialDomain,
    detectBrandImpersonation
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (typeof global !== "undefined") {
    global.CyberLinkBrandDetector = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
