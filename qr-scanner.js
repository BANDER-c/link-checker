/*
 * Cyber Link Analyzer
 * QR Scanner helper
 *
 * مهم:
 * هذا الملف لا يفتح الروابط المستخرجة ولا يعيد توجيه المستخدم إليها.
 * وظيفته استخراج محتوى QR فقط.
 */

function isHttpUrl(value) {
  try {
    const url = new URL(value.trim());
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function processQRContent(content) {
  const value = String(content || "").trim();

  if (!value) {
    return {
      success: false,
      type: "empty",
      message: "تعذر اكتشاف QR في الصورة."
    };
  }

  if (isHttpUrl(value)) {
    return {
      success: true,
      type: "url",
      value,
      message: "تم استخراج الرابط من QR ولم يتم فتحه."
    };
  }

  return {
    success: true,
    type: "text",
    value,
    message: "تم اكتشاف نص داخل QR وليس رابطًا."
  };
}

function qrCameraError(error) {
  if (
    error &&
    (
      error.name === "NotAllowedError" ||
      error.name === "PermissionDeniedError"
    )
  ) {
    return "تم رفض إذن الكاميرا. اسمح للمتصفح باستخدام الكاميرا ثم حاول مرة أخرى.";
  }

  if (
    error &&
    (
      error.name === "NotFoundError" ||
      error.name === "DevicesNotFoundError"
    )
  ) {
    return "لم يتم العثور على كاميرا متاحة.";
  }

  return "تعذر تشغيل الكاميرا. يمكنك تجربة رفع صورة QR بدلًا من ذلك.";
}

const CyberLinkQRScanner = {
  isHttpUrl,
  processQRContent,
  qrCameraError
};

if (typeof window !== "undefined") {
  window.CyberLinkQRScanner = CyberLinkQRScanner;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = CyberLinkQRScanner;
}
