(function (global) {
  "use strict";

  const SHORTENER_DOMAINS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly", "ow.ly"
  ]);

  const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "secure",
    "account", "password", "wallet", "bank", "confirm", "unlock",
    "urgent", "payment"
  ];

  const REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "url", "target", "next", "continue",
    "return", "returnurl", "destination"
  ];

  const ENCODING_PATTERN = /%[0-9a-f]{2}/gi;
  const RISK_LEVELS = Object.freeze({
    low: { min: 0, max: 24, title: "منخفض" },
    medium: { min: 25, max: 49, title: "متوسط" },
    high: { min: 50, max: 74, title: "مرتفع" },
    critical: { min: 75, max: 100, title: "حرج" }
  });

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function getRiskLevel(score) {
    const n = clamp(Number(score) || 0, 0, 100);
    if (n >= 75) return "critical";
    if (n >= 50) return "high";
    if (n >= 25) return "medium";
    return "low";
  }

  function createIndicator({ id, name, description, weight, severity, evidence }) {
    return {
      id,
      name,
      title: name,
      description,
      detected: true,
      weight: Math.max(0, Number(weight) || 0),
      severity,
      evidence: String(evidence || description || "تم اكتشاف المؤشر.")
    };
  }

  function isIPv4(hostname) {
    const parts = String(hostname || "").split(".");
    if (parts.length !== 4) return false;
    return parts.every(function (part) {
      if (!/^\d+$/.test(part)) return false;
      if (part.length > 1 && part[0] === "0") return false;
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
  }

  function isIPv6(hostname) {
    let value = String(hostname || "").trim().toLowerCase();
    value = value.replace(/^\[/, "").replace(/\]$/, "");
    if (!value.includes(":")) return false;
    return /^[0-9a-f:.]+$/i.test(value) && value.split(":").length >= 3;
  }

  function hasUnicode(value) {
    return /[^\x00-\x7F]/.test(String(value || ""));
  }

  function normalizeLookalike(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s");
  }

  function getSubdomainCount(hostname) {
    const host = String(hostname || "").toLowerCase();
    if (!host || isIPv4(host) || isIPv6(host)) return 0;
    const labels = host.split(".").filter(Boolean);
    if (labels.length <= 2) return 0;
    const secondLevelTlds = new Set([
      "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa",
      "co.uk", "org.uk", "com.au", "co.nz"
    ]);
    const lastTwo = labels.slice(-2).join(".");
    return secondLevelTlds.has(lastTwo)
      ? Math.max(0, labels.length - 3)
      : Math.max(0, labels.length - 2);
  }

  function getLengthIndicator(length) {
    if (length >= 300) {
      return { weight: 7, severity: "medium", name: "رابط طويل جدًا", description: "طول الرابط مرتفع جدًا وقد يصعّب التحقق من الوجهة." };
    }
    if (length >= 180) {
      return { weight: 5, severity: "low", name: "رابط طويل", description: "الرابط أطول من المعتاد ويحتاج إلى تحقق إضافي." };
    }
    if (length >= 120) {
      return { weight: 2, severity: "low", name: "طول الرابط مرتفع نسبيًا", description: "طول الرابط أعلى من المعتاد." };
    }
    return null;
  }

  function getRawHostname(raw) {
    try {
      const match = String(raw).trim().match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
      if (!match) return "";
      const authority = match[1].replace(/^[^@]*@/, "");
      return authority.replace(/^\[/, "").split("]")[0].split(":")[0];
    } catch (_) {
      return "";
    }
  }

  function analyzeURL(input) {
    const raw = String(input || "").trim();
    if (!raw) {
      return { valid: false, score: 0, level: "low", indicators: [], metadata: {}, error: "الرابط فارغ." };
    }

    let parsed;
    try {
      parsed = new URL(raw);
    } catch (_) {
      return { valid: false, score: 0, level: "low", indicators: [], metadata: {}, error: "صيغة الرابط غير صالحة." };
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, score: 0, level: "low", indicators: [], metadata: {}, error: "البروتوكول المسموح به هو HTTP أو HTTPS فقط." };
    }

    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) {
      return { valid: false, score: 0, level: "critical", indicators: [createIndicator({ id: "missing-host", name: "اسم نطاق غير موجود", description: "تعذر العثور على اسم نطاق صالح داخل الرابط.", weight: 20, severity: "high", evidence: "لا يحتوي الرابط على اسم نطاق صالح." })], metadata: {}, error: "اسم النطاق غير موجود." };
    }

    const indicators = [];
    const add = (data) => indicators.push(createIndicator(data));
    const pathAndQuery = parsed.pathname + parsed.search;
    const lowerPathAndQuery = pathAndQuery.toLowerCase();
    const keywordSearchText = `${hostname}${pathAndQuery}`.toLowerCase();
    const rawHostname = getRawHostname(raw);
    const ipv4 = isIPv4(hostname);
    const ipv6 = isIPv6(hostname);
    const hasUsername = Boolean(parsed.username);
    const hasPassword = Boolean(parsed.password);
    const hasCredentials = hasUsername || hasPassword;
    const hasAt = /@/.test((raw.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i) || ["", ""])[1] || "");
    const unicodeInRawHost = hasUnicode(rawHostname);
    const punycode = hostname.includes("xn--");
    const subdomainCount = getSubdomainCount(hostname);
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const port = parsed.port ? Number(parsed.port) : null;

    if (parsed.protocol === "http:") {
      add({ id: "http", name: "اتصال HTTP", description: "الرابط يستخدم HTTP غير المشفر، لذلك لا يوفر تشفير HTTPS.", weight: 3, severity: "low", evidence: "protocol = http:" });
    }
    if (ipv4) {
      add({ id: "ipv4", name: "استخدام عنوان IPv4", description: "الرابط يستخدم عنوان IP بدل اسم نطاق، وهذا يستحق تحققًا إضافيًا.", weight: 8, severity: "medium", evidence: `hostname = ${hostname}` });
    }
    if (ipv6) {
      add({ id: "ipv6", name: "استخدام عنوان IPv6", description: "الرابط يستخدم عنوان IPv6 بدل اسم نطاق.", weight: 8, severity: "medium", evidence: `hostname = ${hostname}` });
    }
    if (hasUsername) {
      add({ id: "username", name: "اسم مستخدم داخل URL", description: "الرابط يحتوي على اسم مستخدم ضمن جزء userinfo من URL.", weight: 10, severity: "medium", evidence: `username = ${parsed.username}` });
    }
    if (hasPassword) {
      add({ id: "password", name: "كلمة مرور داخل URL", description: "الرابط يحتوي على كلمة مرور ضمن جزء userinfo من URL.", weight: 14, severity: "high", evidence: "تم اكتشاف password داخل userinfo دون عرض قيمتها." });
    }
    if (hasAt) {
      add({ id: "at-symbol", name: "الرمز @ داخل userinfo", description: "وجود @ داخل جزء userinfo قد يجعل اسم الوجهة أقل وضوحًا. لا يكفي وحده للحكم على الرابط.", weight: 5, severity: "medium", evidence: "تم العثور على @ في authority قبل اسم المضيف." });
    }
    if (punycode) {
      add({ id: "punycode", name: "استخدام Punycode", description: "النطاق يحتوي على Punycode وقد يستحق التحقق من الأحرف الظاهرة.", weight: 7, severity: "medium", evidence: `hostname = ${hostname}` });
    }
    if (unicodeInRawHost) {
      add({ id: "unicode", name: "أحرف Unicode في النطاق", description: "اسم النطاق يحتوي على أحرف غير ASCII وقد تحتاج إلى تحقق إضافي.", weight: 5, severity: "medium", evidence: `النطاق الأصلي = ${rawHostname}` });
    }

    const normalizedHost = normalizeLookalike(rawHostname || hostname);
    if (!ipv4 && !ipv6 && /[01345]/.test(rawHostname || "") && normalizedHost !== String(rawHostname || hostname).toLowerCase()) {
      add({ id: "homoglyph", name: "مؤشر تشابه بصري", description: "يحتوي اسم النطاق على استبدالات رقمية شائعة قد تجعل الاسم مشابهًا لاسم آخر.", weight: 5, severity: "medium", evidence: `النطاق = ${rawHostname || hostname}` });
    }

    const lengthInfo = getLengthIndicator(raw.length);
    if (lengthInfo) add({ id: "url-length", ...lengthInfo, evidence: `طول الرابط = ${raw.length} حرفًا` });

    if (hostname.length >= 80) {
      add({ id: "hostname-length", name: "اسم نطاق طويل جدًا", description: "اسم المضيف طويل بشكل ملحوظ وقد يصعّب التحقق البصري.", weight: 5, severity: "medium", evidence: `طول hostname = ${hostname.length}` });
    } else if (hostname.length >= 55) {
      add({ id: "hostname-length", name: "اسم نطاق طويل", description: "اسم المضيف أطول من المعتاد ويحتاج إلى تحقق إضافي.", weight: 3, severity: "low", evidence: `طول hostname = ${hostname.length}` });
    }

    if (subdomainCount >= 5) {
      add({ id: "subdomains", name: "عدد كبير من النطاقات الفرعية", description: "الرابط يحتوي على عدد مرتفع من النطاقات الفرعية.", weight: 5, severity: "medium", evidence: `عدد subdomains = ${subdomainCount}` });
    } else if (subdomainCount >= 3) {
      add({ id: "subdomains", name: "عدة نطاقات فرعية", description: "الرابط يحتوي على عدة نطاقات فرعية. هذا ليس دليلًا منفردًا على الخطر.", weight: 3, severity: "low", evidence: `عدد subdomains = ${subdomainCount}` });
    }

    if (hyphenCount >= 6) {
      add({ id: "hyphens", name: "عدد مرتفع من الشرطات", description: "اسم النطاق يحتوي على عدد مرتفع من الشرطات.", weight: 4, severity: "low", evidence: `عدد الشرطات = ${hyphenCount}` });
    } else if (hyphenCount >= 4) {
      add({ id: "hyphens", name: "عدة شرطات في النطاق", description: "اسم النطاق يحتوي على عدة شرطات.", weight: 2, severity: "low", evidence: `عدد الشرطات = ${hyphenCount}` });
    }

    if (port !== null && ![80, 443].includes(port)) {
      add({ id: "custom-port", name: "منفذ غير افتراضي", description: "الرابط يستخدم منفذًا غير افتراضي ويستحق تحققًا إضافيًا. وجوده وحده لا يعني أن الرابط ضار.", weight: [8080, 8443].includes(port) ? 1 : 2, severity: "low", evidence: `port = ${port}` });
    }

    const encodingMatches = (pathAndQuery.match(ENCODING_PATTERN) || []).length;
    if (encodingMatches >= 8) {
      add({ id: "encoded-characters", name: "ترميز URL متكرر", description: "الرابط يحتوي على عدد كبير من أحرف URL المرمزة وقد تصبح الوجهة أقل وضوحًا.", weight: 7, severity: "medium", evidence: `عدد رموز %XX = ${encodingMatches}` });
    } else if (encodingMatches >= 2) {
      add({ id: "encoded-characters", name: "ترميز URL", description: "الرابط يحتوي على أحرف مرمزة تحتاج إلى تحقق من السياق.", weight: 3, severity: "low", evidence: `عدد رموز %XX = ${encodingMatches}` });
    }

    const parameterNames = [];
    parsed.searchParams.forEach(function (_, key) { parameterNames.push(String(key).toLowerCase()); });
    const redirectFound = parameterNames.filter(name => REDIRECT_PARAMS.includes(name));
    if (redirectFound.length) {
      add({ id: "redirect-parameter", name: "معامل إعادة توجيه", description: "الرابط يحتوي على parameter قد يستخدم لتحديد وجهة إعادة توجيه.", weight: 5, severity: "medium", evidence: `parameters = ${redirectFound.join(", ")}` });
    }

    const suspiciousFound = SUSPICIOUS_KEYWORDS.filter(word => keywordSearchText.includes(word));
    if (suspiciousFound.length) {
      add({ id: "suspicious-keywords", name: "كلمات مرتبطة بالحساب أو التحقق", description: "الرابط يحتوي على كلمات شائعة في صفحات تسجيل الدخول أو التحقق. وجودها وحدها لا يعني أن الرابط خبيث.", weight: Math.min(suspiciousFound.length * 2, 8), severity: "low", evidence: `الكلمات = ${suspiciousFound.join(", ")}` });
    }

    if (SHORTENER_DOMAINS.has(hostname)) {
      add({ id: "shortener", name: "رابط مختصر", description: "الرابط مختصر ويخفي الوجهة النهائية، لذلك يوصى بالتحقق من الوجهة قبل فتحه.", weight: 6, severity: "medium", evidence: `shortener = ${hostname}` });
    }

    const score = clamp(indicators.reduce((sum, item) => sum + item.weight, 0), 0, 100);
    const level = getRiskLevel(score);

    return {
      valid: true,
      score,
      level,
      indicators,
      metadata: {
        protocol: parsed.protocol,
        hostname,
        rawHostname,
        registeredDomainCandidate: hostname,
        subdomainCount,
        urlLength: raw.length,
        hostnameLength: hostname.length,
        port,
        isIPv4: ipv4,
        isIPv6: ipv6,
        hasUsername,
        hasPassword,
        hasCredentials,
        hasAt,
        hasPunycode: punycode,
        hasUnicode: unicodeInRawHost,
        shortener: SHORTENER_DOMAINS.has(hostname),
        suspiciousKeywords: suspiciousFound,
        redirectParameters: redirectFound,
        encodedCharacterCount: encodingMatches
      }
    };
  }

  const api = {
    analyzeURL,
    analyzeUrl: analyzeURL,
    getRiskLevel,
    isIPv4,
    isIPv6,
    hasUnicode,
    hasUnusualUnicode: hasUnicode,
    normalizeLookalike,
    getSubdomainCount,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    REDIRECT_PARAMS,
    RISK_LEVELS
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof global !== "undefined") global.CyberLinkAnalyzer = api;
})(typeof window !== "undefined" ? window : globalThis);
