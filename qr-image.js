(function () {
  'use strict';

  function initQR() {

    const input = document.getElementById('qrImageInput');
    const button = document.getElementById('qrUploadBtn');
    const result = document.getElementById('qrResult');

    if (!input || !button || !result) {
      console.error('LC QR: عناصر QR غير موجودة');
      return;
    }

    function esc(value) {
      return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function show(html, type) {
      result.style.display = 'block';
      result.className = 'qr-result ' + (type || '');
      result.innerHTML = html;
    }

    function displayQR(text) {

      text = String(text || '').trim();

      if (!text) {
        show(
          '<h3>❌ لم يتم العثور على محتوى</h3>' +
          '<p>تعذر اكتشاف QR في الصورة.</p>',
          'error'
        );
        return;
      }

      /* Wi-Fi */
      if (/^WIFI:/i.test(text)) {

        const data = {};

        text.substring(5)
          .split(';')
          .forEach(function (part) {

            const i = part.indexOf(':');

            if (i !== -1) {
              data[part.substring(0, i)] =
                part.substring(i + 1);
            }

          });

        const network = data.S || 'غير محدد';
        const password = data.P || 'بدون كلمة مرور';
        const security = data.T || 'غير محدد';
        const hidden =
          data.H === 'true' || data.H === '1'
            ? 'نعم'
            : 'لا';

        show(
          '<h3>📶 رمز شبكة Wi-Fi</h3>' +

          '<div class="qr-info">' +

          '<div>' +
          '<strong>📡 اسم الشبكة</strong>' +
          '<span>' + esc(network) + '</span>' +
          '</div>' +

          '<div>' +
          '<strong>🔑 كلمة المرور</strong>' +
          '<span>' + esc(password) + '</span>' +
          '</div>' +

          '<div>' +
          '<strong>🔐 نوع الحماية</strong>' +
          '<span>' + esc(security) + '</span>' +
          '</div>' +

          '<div>' +
          '<strong>👁️ الشبكة مخفية</strong>' +
          '<span>' + hidden + '</span>' +
          '</div>' +

          '</div>' +

          '<p>⚠️ تم استخراج البيانات فقط ولم يتم الاتصال بالشبكة.</p>',
          'success'
        );

        return;
      }

      /* URL */
      if (/^https?:\/\//i.test(text)) {

        const urlInput =
          document.getElementById('urlInput');

        if (urlInput) {
          urlInput.value = text;
        }

        show(
          '<h3>🔗 تم استخراج رابط من QR</h3>' +
          '<div class="qr-link">' +
          esc(text) +
          '</div>' +
          '<p>🛡️ تم استخراج الرابط من QR ولم يتم فتحه.</p>' +
          '<p>⏳ سيتم تمرير الرابط إلى محلل LC.</p>',
          'success'
        );

        if (typeof window.analyzeURL === 'function') {
          setTimeout(function () {
            window.analyzeURL();
          }, 50);
        }

        return;
      }

      /* Phone */
      if (/^tel:/i.test(text)) {

        show(
          '<h3>📞 رمز QR يحتوي على رقم هاتف</h3>' +
          '<div class="qr-link">' +
          esc(text.replace(/^tel:/i, '')) +
          '</div>',
          'success'
        );

        return;
      }

      /* Email */
      if (/^mailto:/i.test(text)) {

        show(
          '<h3>✉️ رمز QR يحتوي على بريد إلكتروني</h3>' +
          '<div class="qr-link">' +
          esc(text.replace(/^mailto:/i, '')) +
          '</div>',
          'success'
        );

        return;
      }

      /* Contact */
      if (/^BEGIN:VCARD/i.test(text) || /^MECARD:/i.test(text)) {

        show(
          '<h3>👤 رمز QR يحتوي على جهة اتصال</h3>' +
          '<pre>' + esc(text) + '</pre>',
          'success'
        );

        return;
      }

      /* Text */
      show(
        '<h3>📝 رمز QR يحتوي على نص</h3>' +
        '<div class="qr-link">' +
        esc(text) +
        '</div>',
        'success'
      );
    }

    async function readImage(file) {

      show(
        '<h3>⏳ جاري قراءة رمز QR...</h3>' +
        '<p>انتظر لحظة...</p>',
        'loading'
      );

      const ZX = window.ZXingBrowser;

      if (!ZX || !ZX.BrowserQRCodeReader) {

        show(
          '<h3>❌ قارئ QR غير متاح</h3>' +
          '<p>لم يتم تحميل مكتبة قراءة QR.</p>',
          'error'
        );

        return;
      }

      const imageURL =
        URL.createObjectURL(file);

      const image = new Image();

      image.onload = async function () {

        try {

          const reader =
            new ZX.BrowserQRCodeReader();

          const result =
            await reader.decodeFromImageElement(image);

          let text = '';

          if (result) {

            if (typeof result.getText === 'function') {
              text = result.getText();
            } else if (result.text) {
              text = result.text;
            }

          }

          if (!text) {

            show(
              '<h3>❌ لم يتم التعرف على QR</h3>' +
              '<p>جرّب صورة أوضح ويكون رمز QR كاملًا ظاهرًا.</p>',
              'error'
            );

            return;
          }

          displayQR(text);

        } catch (error) {

          console.error('LC QR ERROR:', error);

          show(
            '<h3>❌ تعذر قراءة رمز QR</h3>' +
            '<p>تعذر قراءة QR. جرّب صورة أوضح.</p>',
            'error'
          );

        } finally {

          URL.revokeObjectURL(imageURL);

        }
      };

      image.onerror = function () {

        URL.revokeObjectURL(imageURL);

        show(
          '<h3>❌ تعذر فتح الصورة</h3>',
          'error'
        );

      };

      image.src = imageURL;
    }

    button.addEventListener('click', function () {
      input.click();
    });

    input.addEventListener('change', function () {

      const file =
        input.files && input.files[0];

      if (!file) return;

      readImage(file);

      input.value = '';

    });

    console.log('✅ LC QR Image Reader جاهز');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initQR);
  } else {
    initQR();
  }

})();
