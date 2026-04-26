const { exec } = require("child_process");

function scan() {
    return new Promise((resolve) => {
        exec("arp -a", (err, stdout) => {
            if (err) return resolve([]);

            const lines = stdout.split("\n");

            const devices = lines
                .filter(l => l.includes("dynamic") || l.includes("interface"))
                .map(l => {
                    const parts = l.trim().split(/\s+/);

                    return {
                        ip: parts[0],
                        mac: parts[1],
                        type: parts[2] || "unknown"
                    };
                });

            resolve(devices);
        });
    });
}

module.exports = { scan };