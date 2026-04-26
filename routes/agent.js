const express = require("express");
const router = express.Router();
const os = require("os");
const { exec } = require("child_process");

const wifiScanner = require("../services/wifiScanner");
const lanScanner = require("../services/lanScanner");
const pingService = require("../services/pingService");

/* ==============================
   UTIL
============================== */
function runCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { maxBuffer: 1024 * 1024 }, (err, stdout) => {
            if (err) return reject(err.message);
            resolve(stdout);
        });
    });
}

/* ==============================
   PARSER
============================== */
function parseWindows(output) {
    return output
        .split("\n")
        .map(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 4) return null;

            return {
                protocol: parts[0],
                localAddress: parts[1],
                foreignAddress: parts[2],
                state: parts[3],
                pid: parts[4]
            };
        })
        .filter(Boolean);
}

/* ==============================
   PORT SCAN
============================== */
async function scanPorts() {
    const platform = os.platform();

    let cmd;
    let parser;

    if (platform === "win32") {
        cmd = "netstat -ano";
        parser = parseWindows;
    } else if (platform === "linux") {
        cmd = "ss -tulpen";
        parser = (out) => out.split("\n").map(line => ({ raw: line.trim() }));
    } else {
        cmd = "lsof -i -n -P";
        parser = (out) => out.split("\n").map(line => ({ raw: line.trim() }));
    }

    const raw = await runCommand(cmd);

    return {
        platform,
        timestamp: new Date().toISOString(),
        processes: parser(raw)
    };
}

/* ==============================
   ROUTES
============================== */

// WiFi + LAN
router.get("/scan", async (req, res) => {
    try {
        const wifi = await wifiScanner.scan();
        const devices = await lanScanner.scan();
        res.json({ wifi, devices });
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// Ping
router.post("/ping", async (req, res) => {
    try {
        const { ip } = req.body;
        const result = await pingService.ping(ip);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// Ports
router.get("/scan/ports", async (req, res) => {
    try {
        const data = await scanPorts();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.toString() });
    }
});

// Health
router.get("/health", (req, res) => {
    res.json({
        status: "online",
        scans: {
            wifi: true,
            lan: true,
            ports: true
        },
        platform: os.platform()
    });
});

// Hacked scan
router.get("/scan/hacked", async (req, res) => {
    const platform = os.platform();

    let report = {
        platform,
        timestamp: new Date().toISOString(),
        scanTriggered: false,
        scanType: "FullScan",
        notes: [],
        suspiciousProcesses: []
    };

    try {
        if (platform === "win32") {

            try {
                await runCommand(`powershell Start-MpScan -ScanType FullScan`);
                report.scanTriggered = true;
                report.notes.push("Full Defender scan started");
            } catch {
                report.notes.push("Failed to start Defender scan");
            }

            try {
                const status = await runCommand(
                    `powershell Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled`
                );
                report.antivirus = status;
            } catch {
                report.notes.push("Could not read Defender status");
            }

            const tasks = await runCommand("tasklist");
            const suspiciousList = ["mimikatz", "meterpreter", "nc.exe"];

            report.suspiciousProcesses = suspiciousList.filter(name =>
                tasks.toLowerCase().includes(name)
            );
        }

        res.json(report);

    } catch (err) {
        res.status(500).json({
            error: "Scan failed",
            details: err.toString()
        });
    }
});

module.exports = router;