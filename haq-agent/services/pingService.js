const { exec } = require("child_process");

function ping(ip) {
    return new Promise((resolve) => {

        const cmd = process.platform === "win32"
            ? `ping -n 1 ${ip}`
            : `ping -c 1 ${ip}`;

        exec(cmd, (err, stdout) => {
            if (err) {
                return resolve({
                    status: "offline",
                    latency: null
                });
            }

            const match = stdout.match(/time[=<](\d+\.?\d*) ?ms/);

            resolve({
                status: "online",
                latency: match ? match[1] : "unknown"
            });
        });
    });
}

module.exports = { ping };