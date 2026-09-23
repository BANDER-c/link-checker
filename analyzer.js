/*
 * Cyber Link Analyzer
 * V2.1-A — URL Analysis Engine
 *
 * هذا الملف يحلل خصائص URL فقط.
 * لا يفتح الرابط ولا يحمل الصفحة الهدف.
 */

const CLA_SHORTENER_DOMAINS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "ow.ly",
  "buff.ly",
  "rb.gy"
];

const CLA_SUSPICIOUS_WORDS = [
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

const CLA_REDIRECT_PARAMETERS = [
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

const CLA_BRAND_LOOKALIKE_REPLACEMENTS = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s"
};

function claIsIPv4(hostname) {
  const parts = hostname.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every(part => {
    if (!/^\d+$/.test(part)) {
      return false;
    }

    const value = Number(part);

    return value >= 0 && value <= 255;
  });
}

function claIsIPv6(hostname) {
  if (!hostname.includes(":")) {
    return false;
  }

  return /^[0-9a-f:]+$/i.test(hostname);
}

function claIsShortener(hostname) {
  const host = hostname.toLowerCase();

  return CLA_SHORTENER_DOMAINS.some(domain =>
    host === domain || host.endsWith("." + domain)
  );
}

function claNormalizeLookalike(value) {
  return value
    .toLowerCase()
    .replace(/[01345]/g, char =>
      CLA_BRAND_LOOKALIKE_REPLACEMENTS[char] || char
    );
}

function claHasUnicode(hostname) {
  return /[^\x00-\x7F]/.test(hostname);
}

function claGetSubdomainCount(hostname) {
  const parts = hostname
    .split(".")
    .filter(Boolean);

  if (parts.length <= 2) {
    return 0;
  }

  return Math.max(parts.length - 2, 0);
}

function claGetUrlLengthSeverity(length) {
  if (length >= 250) {
    return "high";
  }

  if (length >= 150) {
    return "medium";
  }

  if (length > 120) {
    return "low";
  }

  return null;
}

function claAnalyzeEncoding(url) {
  const matches = url.match(/%[0-9a-f]{2}/gi) || [];

  return {
    count: matches.length,
    values: [...new Set(matches.map(value => value.toUpperCase()))]
  };
}

function claAnalyzeUrl(url) {
  const indicators = [];

  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    return {
      valid: false,
      score: 100,
      level: "critical",
      indicators: [{
        id: "invalid-url",
        title: "رابط غير صالح",
        description: "تعذر تحليل الرابط باستخدام معيار URL.",
        weight: 100,
        severity: "high",
        detected: true
      }]
    };
  }

  if (
    parsed.protocol !== "http:" &&
    parsed.protocol !== "https:"
  ) {
    return {
      valid: false,
      score: 100,
      level: "critical",
      indicators: [{
        id: "unsupported-protocol",
        title: "بروتوكول غير مدعوم",
        description: "الأداة تحلل روابط HTTP وHTTPS فقط.",
        weight: 100,
        severity: "high",
        detected: true
      }]
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.href.toLowerCase();

  // HTTP
  if (parsed.protocol === "http:") {
    indicators.push({
      id: "http",
      title: "اتصال غير مشفر",
      description: "الرابط يستخدم HTTP بدل HTTPS.",
      weight: 5,
      severity: "low",
      detected: true
    });
  }

  // IPv4
  if (claIsIPv4(hostname)) {
    indicators.push({
      id: "ipv4-host",
      title: "استخدام عنوان IPv4",
      description: "الرابط يستخدم عنوان IP بدل اسم نطاق.",
      weight: 15,
      severity: "medium",
      detected: true
    });
  }

  // IPv6
  if (claIsIPv6(hostname)) {
    indicators.push({
      id: "ipv6-host",
      title: "استخدام عنوان IPv6",
      description: "الرابط يستخدم عنوان IPv6 بدل اسم نطاق.",
      weight: 15,
      severity: "medium",
      detected: true
    });
  }

  // Username / password
  if (parsed.username || parsed.password) {
    indicators.push({
      id: "url-credentials",
      title: "بيانات دخول داخل الرابط",
      description:
        "يحتوي الرابط على اسم مستخدم أو كلمة مرور داخل مكونات URL.",
      weight: 20,
      severity: "high",
      detected: true
    });
  }

  // Punycode
  if (hostname.includes("xn--")) {
    indicators.push({
      id: "punycode",
      title: "Punycode",
      description:
        "النطاق يحتوي على Punycode، وقد يستحق التحقق من الاسم الأصلي.",
      weight: 10,
      severity: "medium",
      detected: true
    });
  }

  // Unicode
  if (claHasUnicode(hostname)) {
    indicators.push({
      id: "unicode-host",
      title: "أحرف Unicode في النطاق",
      description:
        "النطاق يحتوي على أحرف غير ASCII وقد يحتاج إلى تحقق إضافي.",
      weight: 8,
      severity: "low",
      detected: true
    });
  }

  // URL length
  const lengthSeverity = claGetUrlLengthSeverity(url.length);

  if (lengthSeverity) {
    const weight =
      lengthSeverity === "high"
        ? 8
        : lengthSeverity === "medium"
          ? 5
          : 3;

    indicators.push({
      id: "url-length",
      title: "طول الرابط",
      description:
        "طول الرابط أعلى من المستويات المعتادة وقد يصعب مراجعته يدويًا.",
      weight,
      severity: lengthSeverity,
      detected: true
    });
  }

  // Subdomains
  const subdomainCount = claGetSubdomainCount(hostname);

  if (subdomainCount >= 4) {
    indicators.push({
      id: "many-subdomains",
      title: "عدد كبير من النطاقات الفرعية",
      description:
        "يحتوي النطاق على عدد كبير من المستويات الفرعية.",
      weight: 8,
      severity: "low",
      detected: true
    });
  } else if (subdomainCount >= 2) {
    indicators.push({
      id: "multiple-subdomains",
      title: "عدة نطاقات فرعية",
      description:
        "يحتوي النطاق على أكثر من مستوى فرعي.",
      weight: 3,
      severity: "low",
      detected: true
    });
  }

  // Hyphens
  const hyphenCount =
    (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 4) {
    indicators.push({
      id: "many-hyphens",
      title: "كثرة الشرطات",
      description:
        "يحتوي اسم النطاق على عدد كبير من الشرطات. هذا مؤشر ضعيف وليس دليلًا مستقلًا على التصيد.",
      weight: 4,
      severity: "low",
      detected: true
    });
  }

  // Port
  if (parsed.port) {
    const port = Number(parsed.port);

    indicators.push({
      id: "custom-port",
      title: "منفذ محدد",
      description:
        "الرابط يستخدم منفذًا محددًا: " + port +
        ". وجود منفذ مخصص لا يعني بحد ذاته أن الرابط خبيث.",
      weight: 2,
      severity: "low",
      detected: true
    });
  }

  // Encoding
  const encoding = claAnalyzeEncoding(parsed.href);

  if (encoding.count >= 6) {
    indicators.push({
      id: "heavy-encoding",
      title: "ترميز URL مرتفع",
      description:
        "يحتوي الرابط على عدد مرتفع من قيم URL Encoding.",
      weight: 7,
      severity: "medium",
      detected: true
    });
  } else if (encoding.count >= 3) {
    indicators.push({
      id: "url-encoding",
      title: "URL Encoding",
      description:
        "يحتوي الرابط على عدة قيم URL Encoding.",
      weight: 3,
      severity: "low",
      detected: true
    });
  }

  // Redirect parameters
  const redirectParameters = [];

  for (const [key] of parsed.searchParams.entries()) {
    if (
      CLA_REDIRECT_PARAMETERS.includes(
        key.toLowerCase()
      )
    ) {
      redirectParameters.push(key);
    }
  }

  if (redirectParameters.length > 0) {
    indicators.push({
      id: "redirect-parameter",
      title: "معامل إعادة توجيه",
      description:
        "يحتوي الرابط على معاملات قد تستخدم لتمرير وجهة أخرى: " +
        redirectParameters.join(", "),
      weight: 6,
      severity: "low",
      detected: true
    });
  }

  // Suspicious keywords
  const foundWords = CLA_SUSPICIOUS_WORDS.filter(word =>
    fullUrl.includes(word)
  );

  if (foundWords.length > 0) {
    indicators.push({
      id: "suspicious-keywords",
      title: "كلمات تستحق التحقق",
      description:
        "يحتوي الرابط على كلمات قد تظهر في صفحات تسجيل الدخول أو التحقق أو الاسترداد: " +
        foundWords.join(", ") +
        ". وجودها وحده لا يعني أن الرابط خبيث.",
      weight: Math.min(foundWords.length * 2, 8),
      severity: "low",
      detected: true
    });
  }

  // Short URL
  if (claIsShortener(hostname)) {
    indicators.push({
      id: "short-url",
      title: "رابط مختصر",
      description:
        "الرابط يستخدم خدمة اختصار وقد يخفي الوجهة النهائية، لذلك يحتاج إلى تحقق إضافي.",
      weight: 6,
      severity: "medium",
      detected: true
    });
  }

  // @ character is reported only as supporting information
  if (fullUrl.includes("@")) {
    indicators.push({
      id: "at-symbol",
      title: "الرمز @",
      description:
        "يحتوي الرابط على الرمز @. يتم تفسيره مع username/password وباقي خصائص URL.",
      weight: 3,
      severity: "low",
      detected: true
    });
  }

  /*
   * Homoglyph / lookalike indicator.
   * لا يقرر انتحال العلامة التجارية وحده.
   */
  const normalizedHost = claNormalizeLookalike(hostname);

  if (
    normalizedHost !== hostname &&
    /[01345]/.test(hostname)
  ) {
    indicators.push({
      id: "lookalike-characters",
      title: "أحرف قد تشبه أحرفًا أخرى",
      description:
        "تم اكتشاف استبدالات رقمية قد تجعل اسم النطاق مشابهًا لاسم معروف.",
      weight: 5,
      severity: "medium",
      detected: true
    });
  }

  const rawScore = indicators.reduce(
    (total, indicator) =>
      total + Number(indicator.weight || 0),
    0
  );

  const score = Math.min(
    Math.max(rawScore, 0),
    100
  );

  let level = "low";

  if (score >= 75) {
    level = "critical";
  } else if (score >= 50) {
    level = "high";
  } else if (score >= 25) {
    level = "medium";
  }

  return {
    valid: true,
    url: parsed.href,
    hostname,
    protocol: parsed.protocol,
    score,
    level,
    indicators,
    metadata: {
      isIPv4: claIsIPv4(hostname),
      isIPv6: claIsIPv6(hostname),
      isShortUrl: claIsShortener(hostname),
      hasPunycode: hostname.includes("xn--"),
      hasUnicode: claHasUnicode(hostname),
      subdomainCount,
      hyphenCount,
      port: parsed.port || null,
      encodingCount: encoding.count,
      redirectParameters
    }
  };
}

// دعم المتصفح و Node.js للاختبارات.
if (typeof window !== "undefined") {
  window.CyberLinkAnalyzer = {
    analyzeURL: claAnalyzeUrl
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    analyzeURL: claAnalyzeUrl
  };
}
