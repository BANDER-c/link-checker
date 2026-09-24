(function (global) {
  "use strict";

  function safeNumber(value) {
    return Number.isFinite(value) ? value : 0;
  }

  function classifyResult(analysis, brandResult) {
    const score = safeNumber(analysis && analysis.score);
    const indicators = Array.isArray(analysis && analysis.indicators)
      ? analysis.indicators
      : [];

    const brandDetected =
      brandResult &&
      brandResult.detected === true &&
      brandResult.official !== true;

    if (brandDetected || score >= 75) {
      return "phishing";
    }

    const importantIndicators = [
      "ipv4",
      "ipv6",
      "credentials",
      "punycode",
      "shortener",
      "redirect-parameter",
      "encoded-characters"
    ];

    const hasImportantIndicator = indicators.some((item) =>
      importantIndicators.includes(item.id)
    );

    if (hasImportantIndicator || score >= 6) {
      return "suspicious";
    }

    return "safe";
  }

  function calculateMetrics(results) {
    let TP = 0;
    let TN = 0;
    let FP = 0;
    let FN = 0;

    results.forEach((item) => {
      const expectedPositive =
        item.expected === "suspicious" ||
        item.expected === "phishing";

      const detectedPositive =
        item.detected === "suspicious" ||
        item.detected === "phishing";

      if (expectedPositive && detectedPositive) TP++;
      else if (!expectedPositive && !detectedPositive) TN++;
      else if (!expectedPositive && detectedPositive) FP++;
      else if (expectedPositive && !detectedPositive) FN++;
    });

    const total = TP + TN + FP + FN;

    const accuracy = total > 0 ? (TP + TN) / total : 0;
    const precision = TP + FP > 0 ? TP / (TP + FP) : 0;
    const recall = TP + FN > 0 ? TP / (TP + FN) : 0;

    const f1 =
      precision + recall > 0
        ? (2 * precision * recall) / (precision + recall)
        : 0;

    return {
      TP,
      TN,
      FP,
      FN,
      total,
      accuracy,
      precision,
      recall,
      f1
    };
  }

  function runTests(testLinks, analyzer, brandDetector) {
    if (!Array.isArray(testLinks)) {
      throw new Error("قائمة الاختبارات غير صالحة.");
    }

    if (!analyzer || typeof analyzer.analyzeURL !== "function") {
      throw new Error("محلل الروابط غير متوفر.");
    }

    if (
      !brandDetector ||
      typeof brandDetector.detectBrandImpersonation !== "function"
    ) {
      throw new Error("محلل انتحال العلامات غير متوفر.");
    }

    const results = testLinks.map((test) => {
      try {
        const analysis = analyzer.analyzeURL(test.url);
        const brandResult =
          brandDetector.detectBrandImpersonation(test.url);

        const detected = classifyResult(analysis, brandResult);

        return {
          id: test.id,
          category: test.category,
          label: test.label,
          url: test.url,
          expected: test.expected,
          detected,
          score: safeNumber(analysis.score),
          level: analysis.level || "unknown",
          passed: detected === test.expected,
          error: null
        };
      } catch (error) {
        return {
          id: test.id,
          category: test.category,
          label: test.label,
          url: test.url,
          expected: test.expected,
          detected: "error",
          score: 0,
          level: "error",
          passed: false,
          error: error.message
        };
      }
    });

    const validResults = results.filter(
      (item) => item.detected !== "error"
    );

    const metrics = calculateMetrics(validResults);

    const passed = results.filter((item) => item.passed).length;
    const failed = results.length - passed;

    return {
      results,
      metrics,
      passed,
      failed,
      total: results.length,
      successRate:
        results.length > 0 ? passed / results.length : 0
    };
  }

  const api = {
    runTests,
    calculateMetrics,
    classifyResult
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (typeof global !== "undefined") {
    global.CyberLinkTestSuite = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
