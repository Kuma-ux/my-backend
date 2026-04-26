const wifi = require("node-wifi");

wifi.init({
    iface: null
});

async function scan() {
    try {
        const networks = await wifi.scan();

        return networks.map(n => ({
            ssid: n.ssid,
            signal: n.signal_level,
            security: n.security
        }));
    } catch (e) {
        return [];
    }
}

module.exports = { scan };