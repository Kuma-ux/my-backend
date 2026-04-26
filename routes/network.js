const router = require("express").Router();

const wifiScanner = require("../services/wifiScanner");
const lanScanner = require("../services/lanScanner");
const pingService = require("../services/pingService");

// 🔍 Full scan (WiFi + LAN)
router.get("/scan", async (req, res) => {
    try {
        const wifi = await wifiScanner.scan();
        const devices = await lanScanner.scan();

        res.json({ wifi, devices });

    } catch (e) {
        res.json({
            error: "Network scan failed",
            details: e.message
        });
    }
});

// 📡 Ping device
router.post("/ping", async (req, res) => {
    const { ip } = req.body;

    const result = await pingService.ping(ip);
    res.json(result);
});

module.exports = router;