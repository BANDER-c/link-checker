const analyzer = require('./analyzer');
const brandDetector = require('./brand-detector');
const testLinks = require('./data/test-links');
const suite = require('./test-suite');
const qr = require('./qr-scanner');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const report = suite.runTests(testLinks, analyzer, brandDetector);
const extra = [
  ['IPv6', analyzer.analyzeURL('https://[2001:db8::1]/login').metadata.isIPv6],
  ['credentials', analyzer.analyzeURL('https://user:pass@example.com').metadata.hasCredentials],
  ['official Google', brandDetector.detectBrandImpersonation('https://www.google.com/login').official],
  ['Google typo', brandDetector.detectBrandImpersonation('https://goog1e.com/login').detected],
  ['QR URL extraction', qr.processQRContent('https://example.com').type === 'url'],
  ['QR text extraction', qr.processQRContent('hello world').type === 'text'],
  ['Risk 24 is low', analyzer.getRiskLevel(24) === 'low'],
  ['Risk 25 is medium', analyzer.getRiskLevel(25) === 'medium'],
  ['Risk 49 is medium', analyzer.getRiskLevel(49) === 'medium'],
  ['Risk 50 is high', analyzer.getRiskLevel(50) === 'high'],
  ['Risk 74 is high', analyzer.getRiskLevel(74) === 'high'],
  ['Risk 75 is critical', analyzer.getRiskLevel(75) === 'critical'],
  ['Safe login is not brand phishing', suite.classifyResult(analyzer.analyzeURL('https://example.com/login'), brandDetector.detectBrandImpersonation('https://example.com/login')) === 'safe'],
  ['Short URL is evidence', analyzer.analyzeURL('https://bit.ly/example').metadata.shortener === true],
  ['Redirect parameter is evidence', analyzer.analyzeURL('https://example.com/?redirect=https://example.com').metadata.redirectParameters.includes('redirect')],
  ['Brand in subdomain is not impersonation', brandDetector.detectBrandImpersonation('https://google.example.com').detected === false],
  ['Brand typo needs context in classifier', suite.classifyResult(analyzer.analyzeURL('https://goog1e.example'), brandDetector.detectBrandImpersonation('https://goog1e.example')) !== 'phishing']
];
extra.forEach(([name, ok]) => assert(ok, `فشل اختبار: ${name}`));

console.log(`Test cases: ${report.total}`);
console.log(`Passed: ${report.passed}`);
console.log(`Failed: ${report.failed}`);
console.log(`TP=${report.metrics.TP} TN=${report.metrics.TN} FP=${report.metrics.FP} FN=${report.metrics.FN}`);
console.log(`Accuracy=${(report.metrics.accuracy * 100).toFixed(2)}%`);
console.log(`Precision=${(report.metrics.precision * 100).toFixed(2)}%`);
console.log(`Recall=${(report.metrics.recall * 100).toFixed(2)}%`);
console.log(`F1=${(report.metrics.f1 * 100).toFixed(2)}%`);
if (process.argv.includes('--metrics')) console.table(report.results.map(x => ({ id: x.id, expected: x.expected, detected: x.detected, score: x.score, passed: x.passed })));

if (report.failed) process.exitCode = 1;
