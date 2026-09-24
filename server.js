const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());

app.use(express.json());
app.use(express.static(__dirname));

function validateScanURL(value) {
  if (typeof value !== "string") {
    return { valid: false, message: "الرابط يجب أن يكون نصًا." };
  }

  const input = value.trim();

  if (!input || input.length > 8192) {
    return { valid: false, message: "الرابط فارغ أو طويل جدًا." };
  }

  try {
    const parsed = new URL(input);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return {
        valid: false,
        message: "يسمح فقط بروابط HTTP وHTTPS."
      };
    }

    if (!parsed.hostname) {
      return {
        valid: false,
        message: "اسم النطاق غير موجود."
      };
    }

    return {
      valid: true,
      url: parsed.href
    };
  } catch {
    return {
      valid: false,
      message: "الرابط غير صالح."
    };
  }
}


app.post("/scan", async (req, res) => {
  try {
    const { url } = req.body;

    const validation = validateScanURL(url);

    if (!validation.valid) {
      return res.status(400).json({
        error: validation.message
      });
    }

    const safeURL = validation.url;

    const apiKey = process.env.VT_API_KEY || "";

    if (!apiKey) {
      return res.status(500).json({
        error: "مفتاح VirusTotal غير موجود"
      });
    }

    const response = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": apiKey,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url: safeURL })
      }
    );

    const data = await response.json();

    console.log("VirusTotal status:", response.status);

    res.status(response.status).json(data);

  } catch (error) {
    console.error("SERVER ERROR:", error);

    res.status(500).json({
      error: error.message
    });
  }
});


app.get("/scan/:id", async (req, res) => {
  try {
    const apiKey = process.env.VT_API_KEY || "";

    if (!apiKey) {
      return res.status(500).json({
        error: "مفتاح VirusTotal غير موجود"
      });
    }

    const response = await fetch(
      "https://www.virustotal.com/api/v3/analyses/" +
      encodeURIComponent(req.params.id),
      {
        headers: {
          "x-apikey": apiKey
        }
      }
    );

    const data = await response.json();

    console.log("VirusTotal analysis status:", response.status);

    res.status(response.status).json(data);

  } catch (error) {
    console.error("ANALYSIS ERROR:", error);

    res.status(500).json({
      error: error.message
    });
  }
});


app.listen(3000, () => {
  console.log("Server running on port 3000");
});
