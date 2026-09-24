const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_URL_LENGTH = 8192;
const ALLOWED_ORIGINS = new Set([
  "https://bander-c.github.io",
  "http://localhost:8080",
  "http://localhost:8081",
  "http://localhost:8082",
  "http://localhost:8083",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:8081",
  "http://127.0.0.1:8082",
  "http://127.0.0.1:8083"
]);

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json({ limit: "32kb", strict: true }));

function validateScanURL(value) {
  if (typeof value !== "string") return { valid: false, message: "الرابط يجب أن يكون نصًا." };
  const input = value.trim();
  if (!input || input.length > MAX_URL_LENGTH) return { valid: false, message: "الرابط فارغ أو طويل جدًا." };
  try {
    const parsed = new URL(input);
    if (!['http:', 'https:'].includes(parsed.protocol)) return { valid: false, message: "يسمح فقط بروابط HTTP وHTTPS." };
    if (!parsed.hostname) return { valid: false, message: "اسم النطاق غير موجود." };
    if (parsed.username || parsed.password) return { valid: false, message: "لأسباب الخصوصية لا يقبل التحقق الخارجي روابط تحتوي على بيانات userinfo." };
    return { valid: true, url: parsed.href };
  } catch (_) {
    return { valid: false, message: "الرابط غير صالح." };
  }
}

function sendError(res, status, message) { return res.status(status).json({ error: message }); }

const rateBuckets = new Map();
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const current = rateBuckets.get(key);
    if (!current || now - current.startedAt >= windowMs) {
      rateBuckets.set(key, { startedAt: now, count: 1 });
      return next();
    }
    current.count += 1;
    if (current.count > maxRequests) {
      res.setHeader("Retry-After", String(Math.ceil((windowMs - (now - current.startedAt)) / 1000)));
      return sendError(res, 429, "تم تجاوز حد الطلبات مؤقتًا. حاول مرة أخرى بعد قليل.");
    }
    return next();
  };
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "Cyber Link Analyzer Backend" }));

app.post("/scan", rateLimit(20, 60_000), async (req, res) => {
  try {
    const validation = validateScanURL(req.body && req.body.url);
    if (!validation.valid) return sendError(res, 400, validation.message);
    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) return sendError(res, 500, "مفتاح VirusTotal غير موجود في بيئة الخادم.");

    const canonicalUrl = new URL(validation.url).href;
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ url: canonicalUrl }).toString()
    });

    const data = await response.json().catch(() => ({}));

    // إذا رفض VirusTotal إنشاء تحليل بسبب canonicalization، جرّب جلب
    // سجل الرابط الموجود مسبقًا؛ هذا يفيد الروابط التي سبق لـ VirusTotal معرفتها.
    if (!response.ok) {
      const vtMessage =
        (data && data.error && typeof data.error.message === "string" && data.error.message.trim())
          ? data.error.message.trim()
          : (typeof data.message === "string" && data.message.trim() ? data.message.trim() : "تعذر بدء فحص VirusTotal.");
      if (response.status === 400 && vtMessage.toLowerCase().includes("unable to canonicalize url")) {
        const urlId = Buffer.from(canonicalUrl).toString("base64url");
        const known = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers: { "x-apikey": apiKey }
        });
        if (known.ok) return res.status(200).json(await known.json());
      }
      return res.status(response.status).json({
        error: vtMessage,
        source: "VirusTotal",
        status: response.status
      });
    }

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("SERVER ERROR:", error.message);
    return sendError(res, 502, "تعذر الاتصال بخدمة VirusTotal حاليًا.");
  }
});

app.get("/scan/:id", rateLimit(120, 60_000), async (req, res) => {
  try {
    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) return sendError(res, 500, "مفتاح VirusTotal غير موجود في بيئة الخادم.");
    const id = String(req.params.id || "");
    if (!/^[A-Za-z0-9_-]{1,200}$/.test(id)) return sendError(res, 400, "معرّف التحليل غير صالح.");

    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, {
      headers: { "x-apikey": apiKey }
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const vtMessage =
        (data && data.error && typeof data.error.message === "string" && data.error.message.trim())
          ? data.error.message.trim()
          : (typeof data.message === "string" && data.message.trim() ? data.message.trim() : "تعذر الحصول على نتيجة VirusTotal.");
      return res.status(response.status).json({
        error: vtMessage,
        source: "VirusTotal",
        status: response.status
      });
    }

    return res.status(response.status).json(data);
  } catch (error) {
    console.error("ANALYSIS ERROR:", error.message);
    return sendError(res, 502, "تعذر الحصول على نتيجة VirusTotal حاليًا.");
  }
});

app.use((error, _req, res, _next) => {
  if (error && error.message === "Origin not allowed") return sendError(res, 403, "المصدر غير مسموح به.");
  if (error && error.type === "entity.parse.failed") return sendError(res, 400, "بيانات الطلب ليست JSON صالحة.");
  console.error("REQUEST ERROR:", error && error.message ? error.message : error);
  return sendError(res, 500, "حدث خطأ غير متوقع في الخادم.");
});

app.listen(PORT, () => console.log(`Cyber Link Analyzer backend listening on ${PORT}`));

module.exports = { app, validateScanURL };
