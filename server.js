const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.API_KEY;

app.post("/check", async (req, res) => {
    const { url } = req.body;

    try {
        const response = await fetch(
             `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
            {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    client: {
                        clientId: "safe-check",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url }]
                    }
                })
            }
        );

        const data = await response.json();
        res.json({ safe: !data.matches });

    } catch {
        res.status(500).json({ error: "fail" });
    }
});

app.listen(10000, () => console.log("Server running"));
