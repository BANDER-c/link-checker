function analyzeRisk(url) {
  try {
    if (
      typeof window !== "undefined" &&
      window.CyberLinkAnalyzer &&
      typeof window.CyberLinkAnalyzer.analyzeURL === "function"
    ) {
      const local = window.CyberLinkAnalyzer.analyzeURL(url);

      let brandResult = null;

      if (
        window.CyberLinkBrandDetector &&
        typeof window.CyberLinkBrandDetector.detectBrandImpersonation === "function"
      ) {
        brandResult =
          window.CyberLinkBrandDetector.detectBrandImpersonation(url);
      }

      const indicators = Array.isArray(local.indicators)
        ? [...local.indicators]
        : [];

      if (
        brandResult &&
        brandResult.detected &&
        !brandResult.official
      ) {
        indicators.push({
          id: "brand-similarity",
          title: "تشابه محتمل مع علامة معروفة",
          description: brandResult.message,
          weight: 25,
          severity: "high",
          detected: true,
          brand: brandResult.brand,
          similarity: brandResult.similarity
        });
      }

      const score = Math.min(
        indicators.reduce(
          (total, indicator) =>
            total + Number(indicator.weight || 0),
          0
        ),
        100
      );

      const reasons = indicators.map(indicator => {
        let text = indicator.description || indicator.title;

        if (indicator.weight) {
          text += " (+" + indicator.weight + ")";
        }

        return text;
      });

      return {
        ...local,
        score,
        reasons,
        indicators,
        brandResult
      };
    }
  } catch (error) {
    console.warn("V2 analyzer failed:", error);
  }

  // Fallback إلى المحلل القديم إذا تعذر تشغيل المحلل الجديد.
  return {
    score: 0,
    reasons: ["تعذر تشغيل محرك التحليل الجديد."],
    indicators: []
  };
}

function getRiskLevel(score) {
  if (score >= 75) {
    return {
      level: "critical",
      title: "🔴 درجة اشتباه حرجة",
      message: "تم اكتشاف عدة مؤشرات تستحق الحذر الشديد."
    };
  }

  if (score >= 50) {
    return {
      level: "high",
      title: "🟠 درجة اشتباه مرتفعة",
      message: "تم اكتشاف مؤشرات متعددة تستحق التحقق قبل فتح الرابط."
    };
  }

  if (score >= 25) {
    return {
      level: "medium",
      title: "🟡 درجة اشتباه متوسطة",
      message: "تم اكتشاف بعض المؤشرات التي تستحق المراجعة."
    };
  }

  return {
    level: "low",
    title: "🟢 درجة اشتباه منخفضة",
    message: "لم يتم اكتشاف مؤشرات محلية قوية في بنية الرابط."
  };
}

async function analyzeURL(){

  const input = document.getElementById("urlInput");
  const result = document.getElementById("result");

  let value = input.value.trim();

  if(!value){
    result.className = "result warning";
    result.style.display = "block";
    result.innerHTML =
      "<h2>⚠️ أدخل رابطًا أولًا</h2>" +
      "<p>ضع الرابط في الخانة ثم اضغط فحص الرابط.</p>";
    return;
  }

  let testURL = value;

  if(!/^https?:\/\//i.test(testURL)){
    testURL = "https://" + testURL;
  }

  try{
    new URL(testURL);
  }catch(e){
    result.className = "result danger";
    result.style.display = "block";
    result.innerHTML =
      "<h2>❌ الرابط غير صالح</h2>" +
      "<p>تأكد من كتابة الرابط بطريقة صحيحة.</p>";
    return;
  }

  // رقم فحص جديد لمنع نتيجة فحص قديم من تغيير الشاشة
  const scanId = Date.now() + Math.random();
  window.LCScanId = scanId;

  // التحليل المحلي يظهر فورًا
  const localRisk = analyzeRisk(testURL);
  const localLevel = getRiskLevel(localRisk.score);

  const localReasons =
    localRisk.reasons.length
      ? localRisk.reasons
          .map(reason => "<li>" + reason + "</li>")
          .join("")
      : "<li>لا توجد مؤشرات محلية واضحة.</li>";

  result.className =
    "result " + localLevel.level;

  result.style.display = "block";

  result.innerHTML =
    "<h2>" +
    (localRisk.score >= 40
      ? "🟡 توجد مؤشرات تستحق الحذر"
      : "🟢 التحليل المحلي مكتمل") +
    "</h2>" +

    "<p>تم تحليل خصائص الرابط بسرعة، ويجري الآن فحص VirusTotal في الخلفية.</p>" +

    "<div style='font-size:32px;font-weight:bold;margin:15px 0'>" +
    localRisk.score +
    "/100" +
    "</div>" +

    "<p><b>مستوى الخطورة: " +
    localLevel.title +
    "</b></p>" +

    "<hr>" +

    "<h3>🔎 أسباب درجة الخطورة</h3>" +

    "<ul>" +
    localReasons +
    "</ul>" +

    "<p style='font-size:13px;opacity:.8'>" +
    "⏳ يتم تحديث النتيجة تلقائيًا عند وصول نتيجة VirusTotal." +
    "</p>";

  // فحص VirusTotal في الخلفية بدون تعطيل النتيجة المحلية
  (async function(){

    try{

      const controller = new AbortController();

      const timeout = setTimeout(() => {
        controller.abort();
      }, 60000);

      const response = await fetch(
        "https://lc-backend-7viz.onrender.com/scan",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            url: testURL
          }),
          signal: controller.signal
        }
      );

      clearTimeout(timeout);

      const data = await response.json();

      if(!response.ok){
        throw new Error(
          data.error || "فشل إرسال الرابط للفحص"
        );
      }

      const analysisId =
        data.data && data.data.id;

      if(!analysisId){
        throw new Error("لم يتم الحصول على رقم التحليل");
      }

      let analysis = null;

      // الانتظار في الخلفية
      for(let i = 0; i < 90; i++){

        await new Promise(resolve =>
          setTimeout(resolve, 1000)
        );

        if(window.LCScanId !== scanId){
          return;
        }

        const check = await fetch(
          "https://lc-backend-7viz.onrender.com/scan/" +
          encodeURIComponent(analysisId)
        );

        const checkData = await check.json();

        if(!check.ok){
          throw new Error(
            checkData.error ||
            "تعذر الحصول على نتيجة التحليل"
          );
        }

        analysis = checkData.data;

        if(
          analysis &&
          analysis.attributes &&
          analysis.attributes.status === "completed"
        ){
          break;
        }
      }

      // إذا لم تكتمل VT خلال فترة الانتظار، نُبقي النتيجة المحلية
      // ونوضح أن الفحص الخارجي ما زال غير مكتمل بدل اعتباره فشلًا.
      if(
        !analysis ||
        !analysis.attributes ||
        analysis.attributes.status !== "completed"
      ){
        if(window.LCScanId === scanId){
          result.innerHTML +=
            "<p style='font-size:13px;opacity:.8'>" +
            "ℹ️ لم تكتمل نتيجة VirusTotal بعد. نتيجة التحليل المحلي ما زالت معروضة." +
            "</p>";
        }
        return;
      }

      if(window.LCScanId !== scanId){
        return;
      }

      const stats =
        analysis.attributes.stats || {};

      const malicious =
        Number(stats.malicious || 0);

      const suspicious =
        Number(stats.suspicious || 0);

      const harmless =
        Number(stats.harmless || 0);

      const undetected =
        Number(stats.undetected || 0);

      const detections =
        malicious + suspicious;

      const total =
        malicious +
        suspicious +
        harmless +
        undetected;

      const finalReasons = [...localRisk.reasons];

      const localScore = Math.min(
        100,
        Math.max(0, Number(localRisk.score) || 0)
      );

      const localLevel = getRiskLevel(localScore);

      let externalLevel = "غير متاح";
      let externalScore = 0;

      if (malicious > 0) {
        externalLevel = "ضار";
        externalScore = Math.min(
          100,
          60 + Math.min(malicious - 1, 4) * 10 +
          Math.min(suspicious, 4) * 5
        );

        finalReasons.push(
          "VirusTotal اكتشف مؤشرات ضارة"
        );

      } else if (suspicious > 0) {
        externalLevel = "مشبوه";
        externalScore = Math.min(
          70,
          30 + Math.min(suspicious - 1, 4) * 8
        );

        finalReasons.push(
          "VirusTotal اكتشف مؤشرات مشبوهة"
        );

      } else if (harmless > 0 || undetected > 0) {
        externalLevel = "لم تُكتشف مؤشرات ضارة";
        externalScore = 0;
      }

      let finalRiskScore;

      if (externalScore === 0) {
        // لا نخفض درجة التحليل المحلي إذا لم تضف VirusTotal مؤشرات ضارة.
        finalRiskScore = localScore;
      } else {
        // عند وجود نتيجة خارجية، ندمجها مع التحليل المحلي.
        finalRiskScore = Math.round(
          (localScore * 0.70) + (externalScore * 0.30)
        );
      }

      const finalLevel = getRiskLevel(finalRiskScore);

      const riskScore = finalRiskScore;
      const level = finalLevel;

      let title;
      let message;

      if(riskScore >= 75){

        title = "🔴 الرابط قد يكون خطيرًا";

        message =
          "درجة الخطورة النهائية مرتفعة وتستحق الحذر.";

      }else if(riskScore >= 50){

        title = "🟠 توجد مؤشرات خطورة مرتفعة";

        message =
          "درجة الخطورة النهائية مرتفعة وتوجد مؤشرات تستحق الحذر.";

      }else if(riskScore >= 25){

        title = "🟡 توجد مؤشرات تستحق الحذر";

        message =
          "درجة الخطورة النهائية متوسطة وتوجد مؤشرات تستحق الانتباه.";

      }else{

        title = "🟢 لم يتم اكتشاف تهديد";

        message =
          "لم تكتشف محركات الفحص المتاحة مؤشرات ضارة، ودرجة المؤشرات المحلية منخفضة.";

      }

      const reasonText =
        finalReasons.length
          ? finalReasons
              .map(reason => "<li>" + reason + "</li>")
              .join("")
          : "<li>لا توجد مؤشرات واضحة.</li>";

      result.className =
        "result " + level.level;

      result.innerHTML =
        "<h2>" + title + "</h2>" +
        "<p>" + message + "</p>" +

        "<div style='font-size:32px;font-weight:bold;margin:15px 0'>" +
        riskScore +
        "/100" +
        "</div>" +

        "<p><b>مستوى الخطورة النهائي: " +
        level.title +
        "</b></p>" +

        "<p><b>درجة التحليل المحلي: " +
        localScore +
        "/100</b></p>" +

        "<p><b>نتيجة VirusTotal الخارجية: " +
        externalLevel +
        "</b></p>" +

        "<p><b>الاكتشافات: " +
        detections +
        " من " +
        total +
        "</b></p>" +

        "<p>ضار: " +
        malicious +
        " | مشبوه: " +
        suspicious +
        " | سليم: " +
        harmless +
        " | غير مكتشف: " +
        undetected +
        "</p>" +

        "<hr>" +

        "<h3>🔎 أسباب درجة الخطورة</h3>" +

        "<ul>" +
        reasonText +
        "</ul>" +

        "<p style='font-size:13px;opacity:.8'>" +
        "درجة الخطورة تقديرية وتعتمد على مؤشرات الرابط ونتائج VirusTotal، ولا تُعد حكمًا نهائيًا على أمان الرابط." +
        "</p>";

    }catch(error){

      // لا نحذف النتيجة المحلية إذا تأخر أو تعذر VirusTotal
      if(window.LCScanId !== scanId){
        return;
      }

      result.innerHTML +=
        "<p style='font-size:13px;opacity:.8'>" +
        "ℹ️ تعذر الاتصال بخدمة VirusTotal حاليًا. نتيجة التحليل المحلي ما زالت ظاهرة." +
        "</p>";
    }

  })();

}
