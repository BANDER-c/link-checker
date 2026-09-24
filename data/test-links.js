(function (global) {
  "use strict";

  const TEST_LINKS = [
    { id: "safe-001", category: "SAFE", label: "HTTPS طبيعي", url: "https://example.com", expected: "safe" },
    { id: "safe-002", category: "SAFE", label: "HTTPS login طبيعي", url: "https://example.com/login", expected: "safe" },
    { id: "safe-003", category: "SAFE", label: "اسم علامة في subdomain فقط", url: "https://google.example.com", expected: "safe" },
    { id: "safe-004", category: "SAFE", label: "HTTPS مع query طبيعي", url: "https://example.com/search?q=security", expected: "safe" },
    { id: "safe-005", category: "SAFE", label: "منفذ ويب بديل", url: "https://example.com:8080/test", expected: "safe" },
    { id: "safe-006", category: "SAFE", label: "نطاق رسمي للعلامة", url: "https://www.google.com/account", expected: "safe" },
    { id: "safe-007", category: "SAFE", label: "نطاق فرعي رسمي", url: "https://login.microsoft.com/", expected: "safe" },
    { id: "safe-008", category: "SAFE", label: "مسار payment طبيعي", url: "https://example.com/payment/status", expected: "safe" },

    { id: "suspicious-001", category: "SUSPICIOUS", label: "IPv4", url: "https://192.168.1.1/login", expected: "suspicious" },
    { id: "suspicious-002", category: "SUSPICIOUS", label: "IPv6", url: "https://[2001:db8::1]/login", expected: "suspicious" },
    { id: "suspicious-003", category: "SUSPICIOUS", label: "Punycode", url: "https://xn--pple-43d.com", expected: "suspicious" },
    { id: "suspicious-004", category: "SUSPICIOUS", label: "Username داخل URL", url: "https://user@example.com/login", expected: "suspicious" },
    { id: "suspicious-005", category: "SUSPICIOUS", label: "Password داخل URL", url: "https://user:pass@example.com", expected: "suspicious" },
    { id: "suspicious-006", category: "SUSPICIOUS", label: "رابط مختصر", url: "https://bit.ly/example", expected: "suspicious" },
    { id: "suspicious-007", category: "SUSPICIOUS", label: "Redirect parameter", url: "https://example.com/?redirect=https://example.com", expected: "suspicious" },
    { id: "suspicious-008", category: "SUSPICIOUS", label: "URL encoding", url: "https://example.com/%2F%40%3A%2E", expected: "suspicious" },
    { id: "suspicious-009", category: "SUSPICIOUS", label: "Subdomains كثيرة", url: "https://a.b.c.d.example.com/login", expected: "suspicious" },
    { id: "suspicious-010", category: "SUSPICIOUS", label: "Hostname طويل", url: "https://this-is-a-very-long-hostname-that-is-used-for-testing.example.com/login", expected: "suspicious" },
    { id: "suspicious-011", category: "SUSPICIOUS", label: "Unicode domain", url: "https://例子.example/login", expected: "suspicious" },
    { id: "suspicious-012", category: "SUSPICIOUS", label: "منفذ غير افتراضي", url: "https://example.com:9000/login", expected: "suspicious" },

    { id: "phishing-sim-001", category: "PHISHING_SIMULATION", label: "Google typo", url: "https://goog1e.com/login", expected: "phishing" },
    { id: "phishing-sim-002", category: "PHISHING_SIMULATION", label: "Microsoft typo", url: "https://micros0ft.com/verify", expected: "phishing" },
    { id: "phishing-sim-003", category: "PHISHING_SIMULATION", label: "PayPal typo", url: "https://paypa1.com/account/verify", expected: "phishing" },
    { id: "phishing-sim-004", category: "PHISHING_SIMULATION", label: "Apple typo", url: "https://app1e.com/account", expected: "phishing" },
    { id: "phishing-sim-005", category: "PHISHING_SIMULATION", label: "Amazon typo", url: "https://amaz0n.com/verify", expected: "phishing" },
    { id: "phishing-sim-006", category: "PHISHING_SIMULATION", label: "STC typo", url: "https://stc1.com/verify", expected: "phishing" },
    { id: "phishing-sim-007", category: "PHISHING_SIMULATION", label: "Alrajhi typo", url: "https://alrajh1.com/login", expected: "phishing" },
    { id: "phishing-sim-008", category: "PHISHING_SIMULATION", label: "Homoglyph-like simulation", url: "https://paypa5.com/confirm", expected: "phishing" },
    { id: "phishing-sim-009", category: "PHISHING_SIMULATION", label: "Credentials + brand typo", url: "https://user:pass@goog1e.com/login", expected: "phishing" },
    { id: "phishing-sim-010", category: "PHISHING_SIMULATION", label: "Brand typo + redirect", url: "https://micros0ft.com/login?redirect=https://example.com", expected: "phishing" }
  ];

  if (typeof module !== "undefined" && module.exports) module.exports = TEST_LINKS;
  if (typeof global !== "undefined") global.CyberLinkTestLinks = TEST_LINKS;
})(typeof window !== "undefined" ? window : globalThis);
