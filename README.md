# Cyber Link Analyzer (LC) — V2.1

## Project Name
**Cyber Link Analyzer — محلل الروابط السيبراني**

أداة تعليمية متعددة المؤشرات لتحليل بنية الروابط واكتشاف مؤشرات التصيد وانتحال النطاقات وروابط QR المشبوهة قبل فتحها.

> This project is an educational security analysis tool and does not guarantee that a URL is safe or malicious.

## المشكلة
قد تحتوي الروابط على مؤشرات تستحق التحقق مثل استخدام IP، بيانات userinfo، Punycode/Unicode، تشابه أسماء النطاقات، معاملات إعادة التوجيه، الروابط المختصرة أو بنية URL غير معتادة.

## الحل
يحلل LC الرابط محليًا دون فتحه، ويحوّل الخصائص المكتشفة إلى Evidence بأوزان واضحة ضمن Risk Score من 0 إلى 100. ويمكن للمستخدم اختياريًا طلب سمعة خارجية عبر VirusTotal.

## Architecture
- `index.html` — واجهة RTL والأقسام الرئيسية.
- `styles.css` — تصميم الواجهة والاستجابة للهاتف.
- `app.js` — إدارة الفحص والنتائج والربط الاختياري مع Backend.
- `analyzer.js` — Local URL Analyzer وRisk Engine المحلي.
- `brand-detector.js` — Levenshtein وvisual substitutions وانتحال العلامات.
- `qr-scanner.js` — وظائف QR العامة ورسائل أخطاء الكاميرا.
- `qr-image.js` — قراءة QR من الكاميرا أو الصورة، دون فتح المحتوى.
- `test-suite.js` — تشغيل الاختبارات وحساب المقاييس.
- `data/test-links.js` — Dataset الاصطناعية القابلة للتوسعة.
- `data/trusted-brands.js` — قائمة العلامات والنطاقات الرسمية.
- `server.js` — Backend لتمرير طلبات VirusTotal مع إبقاء المفتاح في Environment Variable.
- `lc-check.js` — اختبارات Node الأساسية للتشغيل قبل النشر.

## Local URL Analyzer
يفحص LC:
1. HTTP مقابل HTTPS.
2. IPv4 وIPv6.
3. username/password داخل URL.
4. `@` داخل userinfo.
5. Punycode `xn--`.
6. Unicode في النطاق الأصلي.
7. مؤشرات الاستبدال البصري.
8. طول URL وhostname.
9. عدد subdomains.
10. كثرة الشرطات.
11. المنافذ غير الافتراضية.
12. URL encoding المتكرر.
13. redirect parameters.
14. الكلمات المرتبطة بتسجيل الدخول والتحقق والدفع.
15. Short URL domains.
16. Brand similarity.

وجود مؤشر واحد لا يعني أن الرابط خبيث.

## Risk Methodology
الدرجة المحلية من 0 إلى 100:
- 0–24: منخفض.
- 25–49: متوسط.
- 50–74: مرتفع.
- 75–100: حرج.

كل Evidence يحتوي على:
- `id`
- `name`
- `description`
- `detected`
- `weight`
- `severity`
- `evidence`

Risk Score ليس Probability ولا يجوز تفسير `80/100` على أنه احتمال 80% للتصيد.

## Brand Detection
يستخدم LC:
- Levenshtein Distance.
- استبدالات بصرية رقمية شائعة مثل `o→0`, `l→1`, `e→3`, `a→4`, `s→5`.
- قائمة علامات تشمل Google وMicrosoft وApple وAmazon وPayPal وNetflix وFacebook وInstagram وWhatsApp وTelegram وSTC وAlrajhi وRiyad Bank وSNB وSAB وNafath وAbsher.

النطاق الرسمي للعلامة مستثنى من تحذير التشابه، ووجود اسم العلامة في subdomain وحده لا يكفي للحكم على انتحال.

## QR Analysis
يدعم:
- Camera Scan.
- Image Upload.

المسار:
`QR → Extract Content → Validate URL → Local Analyzer → Risk Result`

لا يتم فتح الرابط المستخرج تلقائيًا. إذا كان المحتوى نصًا أو هاتفًا أو بريدًا أو Wi-Fi أو جهة اتصال، يعرض LC المحتوى دون تنفيذه.

## VirusTotal Integration
VirusTotal منفصل عن Local Risk Score.

- التحليل المحلي أولًا.
- التحقق الخارجي اختياري من خلال زر واضح.
- رابط المستخدم يرسل إلى Backend ثم إلى VirusTotal عند الاختيار فقط.
- API Key لا يوضع في JavaScript الخاص بالمتصفح.
- نتائج VirusTotal لا تتحول إلى Probability.

## Testing / Prototype Benchmark
Dataset الحالية تحتوي حالات من:
- `SAFE`
- `SUSPICIOUS`
- `PHISHING_SIMULATION`

لا تستخدم الاختبارات روابط تصيد حقيقية قابلة للضرر؛ الحالات المصممة تستخدم نطاقات اختبار أو أخطاء أسماء اصطناعية.

تشمل الاختبارات IP وIPv6 وPunycode وUnicode وuserinfo وshort URL وredirect وencoding وsubdomains وhostname length وbrand typo وhomoglyph-like simulations.

يتم حساب فعليًا:
- TP
- TN
- FP
- FN
- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix

الأرقام الناتجة هي **Prototype Benchmark** على Dataset المحددة فقط، وليست قياسًا شاملاً لأداء النظام على الإنترنت.

## Privacy
- التحليل المحلي يتم داخل المتصفح ولا يفتح الرابط الهدف.
- VirusTotal خدمة خارجية اختيارية.
- عند اختيارها، يرسل الرابط إلى Backend المشروع ثم إلى VirusTotal.
- لا يفتح LC الروابط تلقائيًا.
- لا يوجد API Key في Frontend.
- لا يدعي المشروع عدم التخزين أو عدم الاحتفاظ بالسجلات إلا وفق إعدادات خدمة Backend/الاستضافة الفعلية.

## Security Review
تمت مراجعة البنية للحد من:
- XSS عبر بيانات URL وQR ونتائج الاختبار باستخدام `textContent`/DOM APIs في الواجهة.
- كشف API Key في Frontend.
- فتح الروابط تلقائيًا.
- تمرير معرفات VirusTotal غير صالحة إلى Backend.
- أخطاء JSON والطلبات الخارجية.

## GitHub Pages
المشروع Frontend ثابت ويستخدم مسارات نسبية:
- `styles.css`
- `analyzer.js`
- `app.js`
- `brand-detector.js`
- `qr-scanner.js`
- `qr-image.js`
- `data/...`

لا تضع Backend أو `VT_API_KEY` داخل GitHub Pages.

## تشغيل محلي
### Frontend
يمكن تشغيل مجلد المشروع بخادم HTTP ثابت، مثل:
```bash
python -m http.server 8080
```
ثم فتح `http://127.0.0.1:8080/`.

### Backend
```bash
npm install
VT_API_KEY="ضع_المفتاح_في_بيئة_الخادم" npm start
```

> لا ترفع `.env` إلى GitHub.

## تشغيل الاختبارات
```bash
npm test
```
ولعرض جدول الحالات:
```bash
npm run test:metrics
```

## Limitations
- التحليل استدلالي وليس Antivirus.
- قد توجد روابط ضارة لا تحتوي على مؤشرات واضحة.
- قد تظهر مؤشرات في روابط سليمة.
- Punycode/Unicode ليسا دليلًا منفردًا على التصيد.
- Short URL ليس خبيثًا بحد ذاته.
- نتائج VirusTotal تتغير حسب الوقت ومصادر الخدمة.
- Prototype Benchmark لا يمثل الإنترنت بالكامل.

## Future Work
- توسيع Dataset المعلنة.
- إضافة اختبارات Browser آلية.
- تحسين تفسير Unicode/Homoglyph.
- إضافة مصادر سمعة أخرى مع Privacy واضحة.
- إضافة تقارير قابلة للتصدير عند الحاجة.

## الترخيص
مشروع تعليمي للأمن السيبراني.
