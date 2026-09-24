(function (global) {
  "use strict";

  function isHttpUrl(value) {
    try {
      const url = new URL(String(value || "").trim());
      return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) { return false; }
  }

  function processQRContent(content) {
    const value = String(content || "").trim();
    if (!value) return { success: false, type: "empty", message: "تعذر اكتشاف QR في الصورة." };
    if (isHttpUrl(value)) return { success: true, type: "url", value, message: "تم استخراج الرابط من QR ولم يتم فتحه." };
    return { success: true, type: "text", value, message: "تم اكتشاف نص داخل QR وليس رابطًا." };
  }

  function qrCameraError(error) {
    if (error && ["NotAllowedError", "PermissionDeniedError"].includes(error.name)) return "تم رفض إذن الكاميرا. اسمح للمتصفح باستخدام الكاميرا ثم حاول مرة أخرى.";
    if (error && ["NotFoundError", "DevicesNotFoundError"].includes(error.name)) return "لم يتم العثور على كاميرا متاحة.";
    if (error && error.name === "NotReadableError") return "الكاميرا مستخدمة من تطبيق آخر أو غير متاحة حاليًا.";
    return "تعذر تشغيل الكاميرا. يمكنك تجربة رفع صورة QR بدلًا من ذلك.";
  }

  const api = { isHttpUrl, processQRContent, qrCameraError };
  if (typeof window !== "undefined") window.CyberLinkQRScanner = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
