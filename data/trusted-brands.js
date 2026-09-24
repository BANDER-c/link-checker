(function (global) {
  "use strict";

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
    { name: "riyadbank", domains: ["riyadbank.com.sa"] },
    { name: "snb", domains: ["alahli.com"] },
    { name: "sab", domains: ["sab.com"] },
    { name: "nafath", domains: ["nafath.sa"] },
    { name: "absher", domains: ["absher.sa"] }
  ];

  if (typeof module !== "undefined" && module.exports) {
    module.exports = TRUSTED_BRANDS;
  }

  if (typeof global !== "undefined") {
    global.CyberLinkTrustedBrands = TRUSTED_BRANDS;
  }
})(typeof window !== "undefined" ? window : globalThis);
