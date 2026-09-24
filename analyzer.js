(function (global) {
  "use strict";

  const SHORTENER_DOMAINS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at"
  ]);

  const SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "password",
    "wallet",
    "bank",
    "confirm",
    "unlock",
    "urgent"
  ];

  const REDIRECT_PARAMS = [
    "redirect",
    "redirect_uri",
    "url",
    "target",
    "next",
    "continue",
    "return",
    "returnurl",
    "destination"
  ];

  const ENCODING_PATTERNS = [
    "%2f",
    "%40",
    "%3a",
    "%2e"
  ];

  function indicator(id, title, description, weight, severity, detected) {
    return {
      id,
      title,
      description,
      weight,
      severity,
      detected
    };
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function getRiskLevel(score) {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";
    return "low";
  }

  function isIPv4(hostname) {
    const parts = String(hostname || "").split(".");
    if (parts.length !== 4) return false;

    return parts.every(function (part) {
      if (!/^\d+$/.test(part)) return false;
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
  }

  function isIPv6(hostname) {
    const value = String(hostname || "");
    return value.includes(":") && /^[0-9a-f:]+$/i.test(value);
  }

  function hasUnusualUnicode(value) {
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

    if (!host || isIPv4(host) || isIPv6(host)) {
      return 0;
    }

    const labels = host
      .split(".")
      .filter(Boolean);

    if (labels.length <= 2) {
      return 0;
    }

    const secondLevelTlds = new Set([
      "com.sa",
      "net.sa",
      "org.sa",
      "edu.sa",
      "gov.sa",
      "co.uk",
      "org.uk",
      "com.au",
      "co.nz"
    ]);

    const lastTwo = labels.slice(-2).join(".");

    if (secondLevelTlds.has(lastTwo)) {
      return Math.max(0, labels.length - 3);
    }

    return Math.max(0, labels.length - 2);
  }

  function getLengthInfo(length) {
    if (length >= 250) {
      return {
        weight: 6,
        severity: "medium",
        title: "رابط طويل جدًا",
        description: "طول الرابط مرتفع وقد يصعّب التحقق من محتواه."
      };
    }

    if (length >= 150) {
      return {
        weight: 4,
        severity: "low",
        title: "رابط طويل",
        description: "الرابط أطول من المعتاد ويحتاج إلى تحقق إضافي."
      };
    }

    if (length > 120) {
      return {
        weight: 2,
        severity: "low",
        title: "طول الرابط مرتفع نسبيًا",
        description: "طول الرابط أعلى من المعتاد."
      };
    }

    return null;
  }

  function analyzeURL(input) {
    const raw = String(input || "").trim();

    if (!raw) {
      return {
        valid: false,
        score: 0,
        level: "low",
        indicators: [],
        metadata: {},
        error: "الرابط فارغ."
      };
    }

    let parsed;

    try {
      parsed = new URL(raw);
    } catch (error) {
      return {
        valid: false,
        score: 0,
        level: "low",
        indicators: [],
        metadata: {},
        error: "صيغة الرابط غير صالحة."
      };
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        valid: false,
        score: 0,
        level: "low",
        indicators: [],
        metadata: {},
        error: "البروتوكول المسموح به هو HTTP أو HTTPS فقط."
      };
    }

    const indicators = [];
    const hostname = parsed.hostname.toLowerCase();
    const pathnameAndQuery = parsed.pathname + parsed.search;

    function add(id, title, description, weight, severity) {
      indicators.push(
        indicator(
          id,
          title,
          description,
          weight,
          severity,
          true
        )
      );
    }

    if (parsed.protocol === "http:") {
      add(
        "http",
        "اتصال HTTP",
        "الرابط يستخدم HTTP غير المشفر، لذلك لا يوفر تشفير HTTPS.",
        3,
        "low"
      );
    }

    const ipv4 = isIPv4(hostname);

    if (ipv4) {
      add(
        "ipv4",
        "استخدام عنوان IPv4",
        "الرابط يستخدم عنوان IP بدل اسم نطاق، وهذا يستحق تحققًا إضافيًا.",
        10,
        "medium"
      );
    }

    const ipv6 = isIPv6(hostname);

    if (ipv6) {
      add(
        "ipv6",
        "استخدام عنوان IPv6",
        "الرابط يستخدم عنوان IPv6 بدل اسم نطاق.",
        10,
        "medium"
      );
    }

    const hasCredentials =
      Boolean(parsed.username) ||
      Boolean(parsed.password);

    if (hasCredentials) {
      add(
        "credentials",
        "بيانات دخول داخل الرابط",
        "الرابط يحتوي على اسم مستخدم أو كلمة مرور ضمن عنوان URL.",
        18,
        "high"
      );
    }

    if (hostname.includes("xn--")) {
      add(
        "punycode",
        "استخدام Punycode",
        "النطاق يحتوي على Punycode وقد يستحق التحقق من الأحرف الظاهرة.",
        7,
        "medium"
      );
    }

    if (hasUnusualUnicode(hostname)) {
      add(
        "unicode",
        "أحرف Unicode غير معتادة",
        "اسم النطاق يحتوي على أحرف غير ASCII وقد تحتاج إلى تحقق إضافي.",
        5,
        "medium"
      );
    }

    const normalizedHost = normalizeLookalike(hostname);

    if (
      !ipv4 &&
      !ipv6 &&
      normalizedHost !== hostname &&
      /[01345]/.test(hostname)
    ) {
      add(
        "homoglyph",
        "مؤشر تشابه في اسم النطاق",
        "يحتوي اسم النطاق على استبدالات رقمية قد تجعل الاسم مشابهًا لاسم آخر.",
        5,
        "medium"
      );
    }

    const lengthInfo = getLengthInfo(raw.length);

    if (lengthInfo) {
      add(
        "url-length",
        lengthInfo.title,
        lengthInfo.description,
        lengthInfo.weight,
        lengthInfo.severity
      );
    }

    const subdomainCount = getSubdomainCount(hostname);

    if (subdomainCount >= 5) {
      add(
        "subdomains",
        "عدد كبير من النطاقات الفرعية",
        "الرابط يحتوي على عدد مرتفع من النطاقات الفرعية.",
        5,
        "medium"
      );
    } else if (subdomainCount >= 3) {
      add(
        "subdomains",
        "عدة نطاقات فرعية",
        "الرابط يحتوي على عدة نطاقات فرعية.",
        3,
        "low"
      );
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 5) {
      add(
        "hyphens",
        "عدد مرتفع من الشرطات",
        "اسم النطاق يحتوي على عدد مرتفع من الشرطات.",
        3,
        "low"
      );
    } else if (hyphenCount >= 4) {
      add(
        "hyphens",
        "عدة شرطات في النطاق",
        "اسم النطاق يحتوي على عدة شرطات.",
        2,
        "low"
      );
    }

    const port = parsed.port
      ? Number(parsed.port)
      : null;

    if (port !== null) {
      if (port === 80 || port === 443) {
        add(
          "common-port",
          "منفذ شائع",
          "الرابط يستخدم منفذًا شائعًا للويب.",
          0,
          "low"
        );
      } else if (port === 8080 || port === 8443) {
        add(
          "common-port",
          "منفذ ويب بديل",
          "الرابط يستخدم منفذ ويب بديلًا شائعًا، وهذا ليس دليلًا على الخطر بحد ذاته.",
          1,
          "low"
        );
      } else {
        add(
          "custom-port",
          "منفذ غير افتراضي",
          "الرابط يستخدم منفذًا غير افتراضي ويستحق تحققًا إضافيًا.",
          2,
          "low"
        );
      }
    }

    const lowerPathAndQuery = pathnameAndQuery.toLowerCase();

    const encodingMatches = ENCODING_PATTERNS.filter(function (pattern) {
      return lowerPathAndQuery.includes(pattern);
    }).length;

    if (encodingMatches >= 3) {
      add(
        "encoded-characters",
        "ترميز URL متكرر",
        "الرابط يحتوي على عدة أنماط ترميز قد تجعل الوجهة أقل وضوحًا.",
        6,
        "medium"
      );
    } else if (encodingMatches > 0) {
      add(
        "encoded-characters",
        "ترميز URL",
        "الرابط يحتوي على أحرف مرمزة تحتاج إلى تحقق من السياق.",
        2,
        "low"
      );
    }

    const parameterNames = [];

    parsed.searchParams.forEach(function (_value, key) {
      parameterNames.push(String(key).toLowerCase());
    });

    const redirectFound = parameterNames.some(function (name) {
      return REDIRECT_PARAMS.includes(name);
    });

    if (redirectFound) {
      add(
        "redirect-parameter",
        "معامل إعادة توجيه",
        "الرابط يحتوي على معامل قد يستخدم لتحديد وجهة إعادة توجيه.",
        5,
        "medium"
      );
    }

    const suspiciousFound = SUSPICIOUS_KEYWORDS.filter(function (word) {
      return lowerPathAndQuery.includes(word);
    });

    if (suspiciousFound.length > 0) {
      add(
        "suspicious-keywords",
        "كلمات مرتبطة بالحساب أو التحقق",
        "الرابط يحتوي على كلمات شائعة في صفحات تسجيل الدخول أو التحقق. وجودها وحده لا يعني أن الرابط خبيث.",
        Math.min(suspiciousFound.length * 2, 6),
        "low"
      );
    }

    if (SHORTENER_DOMAINS.has(hostname)) {
      add(
        "shortener",
        "رابط مختصر",
        "الرابط مختصر ويخفي الوجهة النهائية، لذلك يحتاج إلى تحقق إضافي.",
        6,
        "medium"
      );
    }

    let score = 0;

    for (const item of indicators) {
      score += Number(item.weight) || 0;
    }

    score = clamp(score, 0, 100);

    return {
      valid: true,
      score,
      level: getRiskLevel(score),
      indicators,
      metadata: {
        protocol: parsed.protocol,
        hostname,
        subdomainCount,
        urlLength: raw.length,
        port,
        isIPv4: ipv4,
        isIPv6: ipv6,
        hasCredentials,
        hasPunycode: hostname.includes("xn--"),
        hasUnicode: hasUnusualUnicode(hostname),
        shortener: SHORTENER_DOMAINS.has(hostname)
      }
    };
  }

  const api = {
    analyzeURL,
    analyzeUrl: analyzeURL,
    getRiskLevel,
    isIPv4,
    isIPv6,
    hasUnusualUnicode,
    normalizeLookalike,
    getSubdomainCount,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    REDIRECT_PARAMS
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (typeof global !== "undefined") {
    global.CyberLinkAnalyzer = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
