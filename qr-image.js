(function () {
  "use strict";

  function initQR() {
    const input = document.getElementById("qrImageInput");
    const uploadButton = document.getElementById("qrUploadBtn");
    const cameraButton = document.getElementById("qrCameraBtn");
    const stopButton = document.getElementById("qrStopCameraBtn");
    const video = document.getElementById("qrVideo");
    const result = document.getElementById("qrResult");
    if (!input || !uploadButton || !cameraButton || !stopButton || !video || !result) return;

    let cameraReader = null;
    let cameraControls = null;
    let cameraRunning = false;

    function showMessage(title, message, type) {
      result.style.display = "block";
      result.className = "qr-result " + (type || "");
      while (result.firstChild) result.removeChild(result.firstChild);
      const h = document.createElement("h3"); h.textContent = title; result.appendChild(h);
      const p = document.createElement("p"); p.textContent = message; result.appendChild(p);
    }

    function analyzeExtracted(value) {
      const processed = window.CyberLinkQRScanner.processQRContent(value);
      if (!processed.success) { showMessage("❌ QR غير صالح", processed.message, "error"); return; }
      if (processed.type === "url") {
        const inputURL = document.getElementById("urlInput");
        if (inputURL) inputURL.value = processed.value;
        showMessage("🔗 تم استخراج رابط من QR", "تم استخراج الرابط ولم يتم فتحه تلقائيًا. سيتم تمريره إلى محلل LC.", "success");
        if (typeof window.analyzeURL === "function") setTimeout(window.analyzeURL, 80);
        return;
      }
      result.style.display = "block";
      result.className = "qr-result success";
      while (result.firstChild) result.removeChild(result.firstChild);
      const h = document.createElement("h3"); h.textContent = "📝 محتوى QR نصي"; result.appendChild(h);
      const pre = document.createElement("pre"); pre.textContent = processed.value; result.appendChild(pre);
      const p = document.createElement("p"); p.textContent = "لم يتم فتح أو تنفيذ المحتوى."; result.appendChild(p);
    }

    function displaySpecialContent(text) {
      const value = String(text || "").trim();
      if (/^WIFI:/i.test(value)) {
        showMessage("📶 QR لشبكة Wi-Fi", "تم استخراج بيانات الشبكة فقط. لم يتم الاتصال بها.", "success");
        const pre = document.createElement("pre"); pre.textContent = value; result.appendChild(pre); return;
      }
      if (/^tel:/i.test(value)) { showMessage("📞 QR يحتوي على رقم هاتف", value.slice(4), "success"); return; }
      if (/^mailto:/i.test(value)) { showMessage("✉️ QR يحتوي على بريد إلكتروني", value.slice(7), "success"); return; }
      if (/^BEGIN:VCARD/i.test(value) || /^MECARD:/i.test(value)) { showMessage("👤 QR يحتوي على جهة اتصال", value, "success"); return; }
      analyzeExtracted(value);
    }

    async function decodeImage(file) {
      showMessage("⏳ جاري قراءة رمز QR...", "انتظر لحظة.", "loading");
      const ZX = window.ZXingBrowser;
      if (!ZX || !ZX.BrowserQRCodeReader) { showMessage("❌ قارئ QR غير متاح", "لم يتم تحميل مكتبة قراءة QR.", "error"); return; }
      const imageURL = URL.createObjectURL(file);
      const image = new Image();
      image.onload = async function () {
        try {
          const reader = new ZX.BrowserQRCodeReader();
          const decoded = await reader.decodeFromImageElement(image);
          const text = decoded && typeof decoded.getText === "function" ? decoded.getText() : decoded && decoded.text;
          if (!text) throw new Error("no-qr");
          displaySpecialContent(text);
        } catch (_) {
          showMessage("❌ لم يتم التعرف على QR", "جرّب صورة أوضح ويكون رمز QR كاملًا ظاهرًا.", "error");
        } finally { URL.revokeObjectURL(imageURL); }
      };
      image.onerror = function () { URL.revokeObjectURL(imageURL); showMessage("❌ تعذر فتح الصورة", "اختر صورة QR صالحة.", "error"); };
      image.src = imageURL;
    }

    async function stopCamera() {
      if (cameraControls && typeof cameraControls.stop === "function") cameraControls.stop();
      cameraControls = null;
      cameraRunning = false;
      if (cameraReader && typeof cameraReader.reset === "function") cameraReader.reset();
      cameraReader = null;
      video.pause();
      video.srcObject = null;
      video.style.display = "none";
      stopButton.style.display = "none";
      cameraButton.style.display = "inline-flex";
    }

    async function startCamera() {
      const ZX = window.ZXingBrowser;
      if (!ZX || !ZX.BrowserQRCodeReader) { showMessage("❌ الكاميرا غير متاحة", "مكتبة QR غير محملة.", "error"); return; }
      await stopCamera();
      try {
        cameraReader = new ZX.BrowserQRCodeReader();
        video.style.display = "block";
        cameraButton.style.display = "none";
        stopButton.style.display = "inline-flex";
        cameraRunning = true;
        showMessage("📷 الكاميرا تعمل", "وجّه الكاميرا إلى QR. لن يتم فتح الرابط تلقائيًا.", "loading");
        cameraControls = await cameraReader.decodeFromConstraints(
          { video: { facingMode: { ideal: "environment" } }, audio: false },
          video,
          (decoded, error) => {
            if (!cameraRunning) return;
            if (decoded) {
              const text = typeof decoded.getText === "function" ? decoded.getText() : decoded.text;
              if (text) { stopCamera(); displaySpecialContent(text); }
            } else if (error && error.name && !["NotFoundException"].includes(error.name)) {
              console.debug("LC QR camera:", error);
            }
          }
        );
      } catch (error) {
        await stopCamera();
        showMessage("❌ تعذر تشغيل الكاميرا", window.CyberLinkQRScanner.qrCameraError(error), "error");
      }
    }

    uploadButton.addEventListener("click", () => input.click());
    input.addEventListener("change", () => { const file = input.files && input.files[0]; if (file) decodeImage(file); input.value = ""; });
    cameraButton.addEventListener("click", startCamera);
    stopButton.addEventListener("click", stopCamera);
    window.addEventListener("pagehide", stopCamera);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initQR);
  else initQR();
})();
