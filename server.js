const express = require("express");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.static(__dirname));

app.post("/scan", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "الرابط مطلوب" });
    }

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
        body: new URLSearchParams({ url })
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
