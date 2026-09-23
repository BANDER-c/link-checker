const TRUSTED_BRANDS = [
  { name: "google", domains: ["google.com"] },
  { name: "microsoft", domains: ["microsoft.com"] },
  { name: "apple", domains: ["apple.com"] },
  { name: "amazon", domains: ["amazon.com"] },
  { name: "paypal", domains: ["paypal.com"] },
  { name: "netflix", domains: ["netflix.com"] },
  { name: "facebook", domains: ["facebook.com"] },
  { name: "instagram", domains: ["instagram.com"] },
  { name: "whatsapp", domains: ["whatsapp.com"] },
  { name: "telegram", domains: ["telegram.org"] },
  { name: "stc", domains: ["stc.com.sa"] },
  { name: "alrajhi", domains: ["alrajhibank.com.sa"] },
  { name: "riyadbank", domains: ["riyadbank.com"] },
  { name: "snb", domains: ["alahli.com"] },
  { name: "sab", domains: ["sab.com"] },
  { name: "nafath", domains: ["nafath.sa"] },
  { name: "absher", domains: ["absher.sa"] }
];

function normalize(value) {
  return String(value)
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/[^a-z0-9]/g, "");
}

function levenshtein(a, b) {
  const matrix = Array.from(
    { length: a.length + 1 },
    () => Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) {
    matrix[i][0] = i;
  }

  for (let j = 0; j <= b.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;

      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[a.length][b.length];
}

function detectBrandImpersonation(url) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    return {
      detected: false,
      brand: null,
      similarity: 0,
      message: "الرابط غير صالح."
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  const labels = hostname
    .split(".")
    .filter(Boolean);

  const registeredDomain =
    labels.length >= 2
      ? labels.slice(-2).join(".")
      : hostname;

  // النطاق الرسمي لا يعتبر انتحالًا.
  for (const brand of TRUSTED_BRANDS) {
    if (
      brand.domains.some(
        domain =>
          registeredDomain === domain ||
          registeredDomain.endsWith("." + domain)
      )
    ) {
      return {
        detected: false,
        brand: brand.name,
        official: true,
        similarity: 100,
        message: "النطاق يطابق نطاقًا رسميًا معروفًا."
      };
    }
  }

  let bestMatch = null;

  for (const brand of TRUSTED_BRANDS) {
    const normalizedBrand = normalize(brand.name);

    for (const label of labels) {
      const normalizedLabel = normalize(label);

      if (!normalizedLabel) {
        continue;
      }

      const distance = levenshtein(
        normalizedLabel,
        normalizedBrand
      );

      const maxLength = Math.max(
        normalizedLabel.length,
        normalizedBrand.length
      );

      const similarity =
        maxLength === 0
          ? 0
          : Math.round(
              (1 - distance / maxLength) * 100
            );

      if (
        similarity >= 75 &&
        (!bestMatch ||
          similarity > bestMatch.similarity)
      ) {
        bestMatch = {
          brand: brand.name,
          similarity,
          matchedLabel: label
        };
      }
    }
  }

  if (!bestMatch) {
    return {
      detected: false,
      brand: null,
      official: false,
      similarity: 0,
      message: "لم يتم اكتشاف تشابه واضح مع علامة معروفة."
    };
  }

  return {
    detected: true,
    brand: bestMatch.brand,
    official: false,
    similarity: bestMatch.similarity,
    matchedLabel: bestMatch.matchedLabel,
    message:
      "تشابه محتمل مع اسم علامة معروفة. هذا المؤشر وحده لا يثبت أن الرابط تصيدي."
  };
}

if (typeof window !== "undefined") {
  window.CyberLinkBrandDetector = {
    detectBrandImpersonation
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    detectBrandImpersonation
  };
}
