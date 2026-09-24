(function (global) {
  "use strict";

  function safeNumber(value) { return Number.isFinite(Number(value)) ? Number(value) : 0; }

  function classifyResult(analysis, brandResult) {
    const score = safeNumber(analysis && analysis.score);
    const indicators = Array.isArray(analysis && analysis.indicators) ? analysis.indicators : [];
    const brandDetected = brandResult && brandResult.detected === true && brandResult.official !== true;
    if (brandDetected) return "phishing";

    const strongLocal = indicators.some(item => ["homoglyph"].includes(item.id));
    if (strongLocal && score >= 18) return "phishing";

    const suspiciousIds = new Set(["ipv4", "ipv6", "username", "password", "punycode", "unicode", "at-symbol", "shortener", "redirect-parameter", "encoded-characters", "hostname-length", "subdomains", "custom-port"]);
    if (indicators.some(item => suspiciousIds.has(item.id) && Number(item.weight || 0) >= 2) || score >= 12) return "suspicious";
    return "safe";
  }

  function calculateMetrics(results) {
    let TP = 0, TN = 0, FP = 0, FN = 0;
    results.forEach(item => {
      const expectedPositive = item.expected !== "safe";
      const detectedPositive = item.detected !== "safe";
      if (expectedPositive && detectedPositive) TP++;
      else if (!expectedPositive && !detectedPositive) TN++;
      else if (!expectedPositive && detectedPositive) FP++;
      else FN++;
    });
    const total = TP + TN + FP + FN;
    const accuracy = total ? (TP + TN) / total : 0;
    const precision = TP + FP ? TP / (TP + FP) : 0;
    const recall = TP + FN ? TP / (TP + FN) : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    return { TP, TN, FP, FN, total, accuracy, precision, recall, f1 };
  }

  function runTests(testLinks, analyzer, brandDetector) {
    if (!Array.isArray(testLinks)) throw new Error("قائمة الاختبارات غير صالحة.");
    if (!analyzer || typeof analyzer.analyzeURL !== "function") throw new Error("محلل الروابط غير متوفر.");
    if (!brandDetector || typeof brandDetector.detectBrandImpersonation !== "function") throw new Error("محلل انتحال العلامات غير متوفر.");

    const results = testLinks.map(test => {
      try {
        const analysis = analyzer.analyzeURL(test.url);
        const brandResult = brandDetector.detectBrandImpersonation(test.url);
        const detected = classifyResult(analysis, brandResult);
        return { ...test, detected, score: safeNumber(analysis.score), level: analysis.level, passed: detected === test.expected, error: null };
      } catch (error) {
        return { ...test, detected: "error", score: 0, level: "error", passed: false, error: error.message };
      }
    });

    const metrics = calculateMetrics(results.filter(item => item.detected !== "error"));
    const passed = results.filter(item => item.passed).length;
    return { results, metrics, passed, failed: results.length - passed, total: results.length, successRate: results.length ? passed / results.length : 0 };
  }

  const api = { runTests, calculateMetrics, classifyResult };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof global !== "undefined") global.CyberLinkTestSuite = api;
})(typeof window !== "undefined" ? window : globalThis);
