const router = require("express").Router();
const os = require("os");

// 🧠 Basic system health check
router.get("/", (req, res) => {
    res.json({
        status: "online",
        message: "HAQ-Core system module active"
    });
});

// 📊 System stats
router.get("/stats", (req, res) => {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();

    res.json({
        platform: os.platform(),
        cpuArch: os.arch(),
        uptimeSeconds: os.uptime(),
        memory: {
            totalMB: Math.round(totalMem / 1024 / 1024),
            freeMB: Math.round(freeMem / 1024 / 1024),
            usedMB: Math.round((totalMem - freeMem) / 1024 / 1024)
        },
        cpuCores: os.cpus().length
    });
});

// 🖥️ Host identity
router.get("/identity", (req, res) => {
    res.json({
        hostname: os.hostname(),
        user: os.userInfo().username
    });
});

module.exports = router;