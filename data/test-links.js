(function (global) {
  "use strict";

  const TEST_LINKS = [
    {
      id: "safe-001",
      category: "SAFE",
      label: "رابط HTTPS طبيعي",
      url: "https://example.com",
      expected: "safe"
    },
    {
      id: "safe-002",
      category: "SAFE",
      label: "HTTP بسيط",
      url: "http://example.com",
      expected: "safe"
    },
    {
      id: "safe-003",
      category: "SAFE",
      label: "كلمة login داخل مسار طبيعي",
      url: "https://example.com/login",
      expected: "safe"
    },
    {
      id: "safe-004",
      category: "SAFE",
      label: "اسم علامة في نطاق فرعي فقط",
      url: "https://google.example.com",
      expected: "safe"
    },
    {
      id: "safe-005",
      category: "SAFE",
      label: "منفذ معروف",
      url: "https://example.com:8080/test",
      expected: "safe"
    },

    {
      id: "suspicious-001",
      category: "SUSPICIOUS",
      label: "عنوان IPv4",
      url: "https://192.168.1.1/login",
      expected: "suspicious"
    },
    {
      id: "suspicious-002",
      category: "SUSPICIOUS",
      label: "Punycode",
      url: "https://xn--pple-43d.com",
      expected: "suspicious"
    },
    {
      id: "suspicious-003",
      category: "SUSPICIOUS",
      label: "بيانات دخول داخل الرابط",
      url: "https://user:pass@example.com",
      expected: "suspicious"
    },
    {
      id: "suspicious-004",
      category: "SUSPICIOUS",
      label: "رابط مختصر",
      url: "https://bit.ly/example",
      expected: "suspicious"
    },
    {
      id: "suspicious-005",
      category: "SUSPICIOUS",
      label: "معامل إعادة توجيه",
      url: "https://example.com/?redirect=https://example.com",
      expected: "suspicious"
    },

    {
      id: "phishing-sim-001",
      category: "PHISHING_SIMULATION",
      label: "تشابه Google",
      url: "https://goog1e.com/login",
      expected: "phishing"
    },
    {
      id: "phishing-sim-002",
      category: "PHISHING_SIMULATION",
      label: "تشابه Microsoft",
      url: "https://micros0ft.com/verify",
      expected: "phishing"
    },
    {
      id: "phishing-sim-003",
      category: "PHISHING_SIMULATION",
      label: "تشابه PayPal",
      url: "https://paypa1.com/account/verify",
      expected: "phishing"
    },
    {
      id: "phishing-sim-004",
      category: "PHISHING_SIMULATION",
      label: "تشابه Apple",
      url: "https://app1e.com/account",
      expected: "phishing"
    }
  ];

  if (typeof module !== "undefined" && module.exports) {
    module.exports = TEST_LINKS;
  }

  if (typeof global !== "undefined") {
    global.CyberLinkTestLinks = TEST_LINKS;
  }
})(typeof window !== "undefined" ? window : globalThis);
