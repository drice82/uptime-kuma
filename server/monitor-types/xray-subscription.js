const { MonitorType } = require("./monitor-type");
const { UP } = require("../../src/util");
const axios = require("axios");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { spawn } = require("child_process");
const net = require("net");
const fs = require("fs");
const os = require("os");
const path = require("path");

/**
 * Xray Subscription Monitor Type
 *
 * Fetches an xray/v2ray subscription link, parses all proxy nodes
 * (vmess, vless, trojan, ss), then for each node:
 *   1. Generates an xray config with a local SOCKS inbound
 *   2. Starts an xray process
 *   3. Attempts to access Google through the local SOCKS proxy
 *   4. Kills the xray process
 *
 * If all nodes can access Google  -> heartbeat UP
 * If any nodes fail               -> throw Error (framework sets DOWN)
 */
class XraySubscriptionMonitorType extends MonitorType {
    name = "xray-subscription";

    /** URL used to verify a node can actually reach the open internet */
    static TEST_URL = "https://www.google.com/generate_204";

    /** Max concurrent xray processes */
    static CONCURRENCY = 5;

    /**
     * @inheritdoc
     */
    async check(monitor, heartbeat, _server) {
        const subscriptionUrl = monitor.url;
        if (!subscriptionUrl) {
            throw new Error("Subscription URL is required");
        }

        // Fetch subscription content
        let response;
        try {
            response = await axios.get(subscriptionUrl, {
                timeout: (monitor.timeout || 30) * 1000,
                headers: {
                    "User-Agent": "v2rayN/6.45",
                },
                responseType: "text",
            });
        } catch (e) {
            throw new Error(`Failed to fetch subscription: ${e.message}`);
        }

        // Parse nodes
        const nodes = this.parseSubscriptionContent(response.data);
        if (nodes.length === 0) {
            throw new Error("No nodes found in subscription");
        }

        // Test each node via xray with concurrency limit
        const perNodeTimeout = Math.min((monitor.timeout || 10) * 1000, 15000);
        const results = await this.testNodesConcurrently(
            nodes,
            XraySubscriptionMonitorType.TEST_URL,
            perNodeTimeout,
            XraySubscriptionMonitorType.CONCURRENCY,
        );

        // Analyse results – throw on failure so the framework sets DOWN
        const failedNodes = results.filter((r) => !r.ok);

        if (failedNodes.length === 0) {
            heartbeat.status = UP;
            heartbeat.msg = `All ${results.length} nodes can access Google normally`;
        } else {
            const failedList = failedNodes
                .map((r) => `  - ${r.name} (${r.protocol} ${r.server}:${r.port}) - ${r.error}`)
                .join("\n");
            throw new Error(
                `${failedNodes.length}/${results.length} nodes cannot access Google:\n${failedList}`,
            );
        }
    }

    // ── Subscription parsing ─────────────────────────────────────────────

    /**
     * Parse subscription content – handles base64-encoded and plain-text.
     * @param {string} content Raw subscription body
     * @returns {object[]} Array of node objects
     */
    parseSubscriptionContent(content) {
        content = content.trim();

        let decoded = content;
        if (!content.includes("://")) {
            try {
                decoded = Buffer.from(content, "base64").toString("utf-8").trim();
            } catch (e) {
                // keep original if base64 decode fails
            }
        }

        const lines = decoded.split(/[\n\r]+/).filter((line) => line.trim());
        const nodes = [];

        for (const line of lines) {
            try {
                const node = this.parseProxyUri(line.trim());
                if (node) {
                    nodes.push(node);
                }
            } catch (e) {
                // skip unparseable lines
            }
        }
        return nodes;
    }

    /**
     * Dispatch to the correct protocol parser.
     * @param {string} uri Proxy URI
     * @returns {object|null} Node object or null if unsupported
     */
    parseProxyUri(uri) {
        if (uri.startsWith("vmess://")) {
            return this.parseVmess(uri);
        } else if (uri.startsWith("vless://")) {
            return this.parseVless(uri);
        } else if (uri.startsWith("trojan://")) {
            return this.parseTrojan(uri);
        } else if (uri.startsWith("ss://")) {
            return this.parseShadowsocks(uri);
        }
        return null;
    }

    /**
     * Parse vmess:// URI (base64-encoded JSON).
     * @param {string} uri vmess proxy URI
     * @returns {object} Node object
     */
    parseVmess(uri) {
        const b64 = uri.substring("vmess://".length);
        const json = JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
        return {
            protocol: "vmess",
            name: json.ps || `${json.add}:${json.port}`,
            server: json.add,
            port: parseInt(json.port, 10),
            uuid: json.id,
            alterId: parseInt(json.aid || "0", 10),
            security: json.scy || "auto",
            network: json.net || "tcp",
            headerType: json.type || "none",
            host: json.host || "",
            path: json.path || "/",
            tls: json.tls === "tls",
            sni: json.sni || json.host || "",
            alpn: json.alpn || "",
            pinnedPeerCertSha256: json.pcs || json.hpkp || "",
        };
    }

    /**
     * Parse vless:// URI.
     * @param {string} uri vless proxy URI
     * @returns {object} Node object
     */
    parseVless(uri) {
        const url = new URL(uri);
        const p = url.searchParams;
        const security = p.get("security") || "none";
        return {
            protocol: "vless",
            name: decodeURIComponent(url.hash.substring(1)) || `${url.hostname}:${url.port}`,
            server: url.hostname,
            port: parseInt(url.port, 10),
            uuid: url.username,
            encryption: p.get("encryption") || "none",
            flow: p.get("flow") || "",
            network: p.get("type") || "tcp",
            headerType: p.get("headerType") || "none",
            host: p.get("host") || "",
            path: p.get("path") || "/",
            tls: security === "tls" || security === "xtls" || security === "reality",
            securityType: security,
            sni: p.get("sni") || p.get("host") || "",
            alpn: p.get("alpn") || "",
            fingerprint: p.get("fp") || "chrome",
            publicKey: p.get("pbk") || "",
            shortId: p.get("sid") || "",
            pinnedPeerCertSha256: p.get("pcs") || p.get("hpkp") || "",
        };
    }

    /**
     * Parse trojan:// URI.
     * @param {string} uri trojan proxy URI
     * @returns {object} Node object
     */
    parseTrojan(uri) {
        const url = new URL(uri);
        const p = url.searchParams;
        const security = p.get("security") || "tls";
        return {
            protocol: "trojan",
            name: decodeURIComponent(url.hash.substring(1)) || `${url.hostname}:${url.port}`,
            server: url.hostname,
            port: parseInt(url.port, 10),
            password: decodeURIComponent(url.username),
            flow: p.get("flow") || "",
            network: p.get("type") || "tcp",
            headerType: p.get("headerType") || "none",
            host: p.get("host") || "",
            path: p.get("path") || "/",
            tls: security !== "none",
            securityType: security,
            sni: p.get("sni") || p.get("host") || "",
            alpn: p.get("alpn") || "",
            fingerprint: p.get("fp") || "chrome",
            pinnedPeerCertSha256: p.get("pcs") || p.get("hpkp") || "",
        };
    }

    /**
     * Parse ss:// (Shadowsocks) URI.
     * Supports both formats:
     *   ss://base64(method:password)@server:port#name
     *   ss://base64(method:password@server:port)#name
     * @param {string} uri Shadowsocks proxy URI
     * @returns {object|null} Node object or null if unparseable
     */
    parseShadowsocks(uri) {
        const rest = uri.substring("ss://".length);

        let name = "";
        const hashIdx = rest.indexOf("#");
        if (hashIdx !== -1) {
            name = decodeURIComponent(rest.substring(hashIdx + 1));
        }
        const main = hashIdx !== -1 ? rest.substring(0, hashIdx) : rest;

        // Format 1: base64(method:password)@server:port
        const atIdx = main.lastIndexOf("@");
        if (atIdx !== -1) {
            const serverPart = main.substring(atIdx + 1);
            const colonIdx = serverPart.lastIndexOf(":");
            if (colonIdx === -1) {
                return null;
            }
            const server = serverPart.substring(0, colonIdx);
            const port = serverPart.substring(colonIdx + 1);
            const credential = Buffer.from(main.substring(0, atIdx), "base64").toString("utf-8");
            const credColon = credential.indexOf(":");
            return {
                protocol: "ss",
                name: name || `${server}:${port}`,
                server: server,
                port: parseInt(port, 10),
                method: credential.substring(0, credColon),
                password: credential.substring(credColon + 1),
            };
        }

        // Format 2: base64(method:password@server:port)
        try {
            const decoded = Buffer.from(main, "base64").toString("utf-8");
            const atPos = decoded.lastIndexOf("@");
            if (atPos === -1) {
                return null;
            }
            const serverPart = decoded.substring(atPos + 1);
            const colonIdx = serverPart.lastIndexOf(":");
            if (colonIdx === -1) {
                return null;
            }
            const server = serverPart.substring(0, colonIdx);
            const port = serverPart.substring(colonIdx + 1);
            const credential = decoded.substring(0, atPos);
            const credColon = credential.indexOf(":");
            return {
                protocol: "ss",
                name: name || `${server}:${port}`,
                server: server,
                port: parseInt(port, 10),
                method: credential.substring(0, credColon),
                password: credential.substring(credColon + 1),
            };
        } catch (e) {
            return null;
        }
    }

    // ── Xray config generation ───────────────────────────────────────────

    /**
     * Build a complete xray JSON config for a node.
     * @param {object} node Parsed node
     * @param {number} localPort Local SOCKS port
     * @returns {object} Xray config object
     */
    generateXrayConfig(node, localPort) {
        return {
            log: { loglevel: "error" },
            inbounds: [
                {
                    port: localPort,
                    listen: "127.0.0.1",
                    protocol: "socks",
                    settings: { udp: false },
                },
            ],
            outbounds: [this.generateOutbound(node)],
        };
    }

    /**
     * Generate the outbound section for a node based on its protocol.
     * @param {object} node Parsed node
     * @returns {object} Xray outbound config
     * @throws {Error} If the protocol is not supported
     */
    generateOutbound(node) {
        switch (node.protocol) {
            case "vmess":
                return this.generateVmessOutbound(node);
            case "vless":
                return this.generateVlessOutbound(node);
            case "trojan":
                return this.generateTrojanOutbound(node);
            case "ss":
                return this.generateShadowsocksOutbound(node);
            default:
                throw new Error(`Unsupported protocol: ${node.protocol}`);
        }
    }

    /**
     * Generate vmess outbound config.
     * @param {object} node Parsed node
     * @returns {object} Xray outbound config
     */
    generateVmessOutbound(node) {
        const outbound = {
            protocol: "vmess",
            settings: {
                vnext: [
                    {
                        address: node.server,
                        port: node.port,
                        users: [
                            {
                                id: node.uuid,
                                alterId: node.alterId || 0,
                                security: node.security || "auto",
                            },
                        ],
                    },
                ],
            },
        };
        this.applyStreamSettings(outbound, node);
        return outbound;
    }

    /**
     * Generate vless outbound config.
     * @param {object} node Parsed node
     * @returns {object} Xray outbound config
     */
    generateVlessOutbound(node) {
        const user = {
            id: node.uuid,
            encryption: node.encryption || "none",
        };
        if (node.flow) {
            user.flow = node.flow;
        }
        const outbound = {
            protocol: "vless",
            settings: {
                vnext: [
                    {
                        address: node.server,
                        port: node.port,
                        users: [user],
                    },
                ],
            },
        };
        this.applyStreamSettings(outbound, node);
        return outbound;
    }

    /**
     * Generate trojan outbound config.
     * @param {object} node Parsed node
     * @returns {object} Xray outbound config
     */
    generateTrojanOutbound(node) {
        const outbound = {
            protocol: "trojan",
            settings: {
                servers: [
                    {
                        address: node.server,
                        port: node.port,
                        password: node.password,
                    },
                ],
            },
        };
        this.applyStreamSettings(outbound, node);
        return outbound;
    }

    /**
     * Generate shadowsocks outbound config.
     * @param {object} node Parsed node
     * @returns {object} Xray outbound config
     */
    generateShadowsocksOutbound(node) {
        return {
            protocol: "shadowsocks",
            settings: {
                servers: [
                    {
                        address: node.server,
                        port: node.port,
                        method: node.method,
                        password: node.password,
                    },
                ],
            },
        };
    }

    /**
     * Apply stream settings (network type, TLS, Reality, WS, gRPC, etc.)
     * to an outbound config object.
     * @param {object} outbound Outbound config to modify
     * @param {object} node Parsed node
     * @returns {void}
     */
    applyStreamSettings(outbound, node) {
        const network = node.network || "tcp";
        const security = node.securityType || (node.tls ? "tls" : "none");

        const stream = { network, security };

        // Security settings
        if (security === "tls") {
            stream.tlsSettings = {
                serverName: node.sni || node.server,
            };
            if (node.pinnedPeerCertSha256) {
                stream.tlsSettings.pinnedPeerCertSha256 = node.pinnedPeerCertSha256;
            } else {
                stream.tlsSettings.insecure = true;
            }
            if (node.alpn) {
                stream.tlsSettings.alpn = node.alpn.split(",");
            }
        } else if (security === "reality") {
            stream.realitySettings = {
                serverName: node.sni || node.server,
                fingerprint: node.fingerprint || "chrome",
                publicKey: node.publicKey || "",
                shortId: node.shortId || "",
            };
        } else if (security === "xtls") {
            stream.xtlsSettings = {
                serverName: node.sni || node.server,
            };
            if (node.pinnedPeerCertSha256) {
                stream.xtlsSettings.pinnedPeerCertSha256 = node.pinnedPeerCertSha256;
            } else {
                stream.xtlsSettings.insecure = true;
            }
        }

        // Transport settings
        if (network === "ws") {
            stream.wsSettings = {
                path: node.path || "/",
                headers: node.host ? { Host: node.host } : {},
            };
        } else if (network === "grpc") {
            stream.grpcSettings = {
                serviceName: node.path || "",
            };
        } else if (network === "http" || network === "h2") {
            stream.network = "http";
            stream.httpSettings = {
                path: node.path || "/",
                host: node.host ? [node.host] : [node.server],
            };
        } else if (network === "tcp" && node.headerType === "http") {
            stream.tcpSettings = {
                header: {
                    type: "http",
                    request: {
                        path: [node.path || "/"],
                        headers: { Host: [node.host || node.server] },
                    },
                },
            };
        }

        outbound.streamSettings = stream;
    }

    // ── Node testing via xray ────────────────────────────────────────────

    /**
     * Test multiple nodes with a concurrency limit.
     * @param {object[]} nodes Parsed nodes
     * @param {string} testUrl URL to test
     * @param {number} timeout Per-node timeout in ms
     * @param {number} concurrency Max parallel xray processes
     * @returns {Promise<object[]>} Array of result objects
     */
    async testNodesConcurrently(nodes, testUrl, timeout, concurrency) {
        const results = [];
        let index = 0;

        const worker = async () => {
            while (index < nodes.length) {
                const current = index++;
                const result = await this.testNode(nodes[current], testUrl, timeout);
                results[current] = result;
            }
        };

        const workers = [];
        for (let i = 0; i < Math.min(concurrency, nodes.length); i++) {
            workers.push(worker());
        }
        await Promise.all(workers);
        return results;
    }

    /**
     * Test a single node: start xray, access Google through it, kill xray.
     * @param {object} node Parsed node
     * @param {string} testUrl URL to test
     * @param {number} timeout Timeout in ms
     * @returns {Promise<object>} Result { ok, error, ...node }
     */
    async testNode(node, testUrl, timeout) {
        if (!node.server || !node.port || isNaN(node.port)) {
            return { ...node, ok: false, error: "Invalid server or port" };
        }

        const localPort = await this.findFreePort();
        const config = this.generateXrayConfig(node, localPort);
        const configPath = path.join(os.tmpdir(), `xray-monitor-${localPort}.json`);
        fs.writeFileSync(configPath, JSON.stringify(config));

        let xrayProc = null;
        let stderrBuffer = "";
        try {
            xrayProc = spawn("xray", ["run", "-c", configPath], {
                stdio: ["ignore", "pipe", "pipe"],
            });

            xrayProc.stderr.on("data", (data) => {
                stderrBuffer += data.toString();
            });

            // Also detect early exit
            const exitPromise = new Promise((resolve) => {
                xrayProc.on("exit", (code) => resolve(code));
            });

            // Wait for the local SOCKS port to become available or xray to exit
            const ready = await Promise.race([
                this.waitForPort(localPort, 5000),
                exitPromise.then(() => false),
            ]);
            if (!ready) {
                const errMsg = stderrBuffer.trim().split("\n").pop() || "xray exited unexpectedly";
                return { ...node, ok: false, error: `Xray failed to start: ${errMsg}` };
            }

            // Access Google through the SOCKS proxy
            const agent = new SocksProxyAgent(`socks5://127.0.0.1:${localPort}`);
            try {
                await axios.get(testUrl, {
                    httpAgent: agent,
                    httpsAgent: agent,
                    timeout: timeout,
                    validateStatus: (status) => status >= 200 && status < 400,
                    maxRedirects: 3,
                });
                return { ...node, ok: true };
            } catch (e) {
                return { ...node, ok: false, error: this.describeError(e) };
            }
        } catch (e) {
            return { ...node, ok: false, error: `Xray error: ${e.message}` };
        } finally {
            if (xrayProc) {
                try {
                    xrayProc.kill("SIGKILL");
                } catch (e) {
                    // best effort
                }
            }
            try {
                fs.unlinkSync(configPath);
            } catch (e) {
                // best effort
            }
        }
    }

    /**
     * Convert an axios error to a concise human-readable string.
     * @param {Error} e Axios error
     * @returns {string} Human-readable error description
     */
    describeError(e) {
        if (e.code) {
            return e.code;
        }
        if (e.response) {
            return `HTTP ${e.response.status}`;
        }
        return e.message;
    }

    /**
     * Find a free TCP port on localhost.
     * @returns {Promise<number>} The free port number
     */
    findFreePort() {
        return new Promise((resolve, reject) => {
            const srv = net.createServer();
            srv.unref();
            srv.on("error", reject);
            srv.listen(0, "127.0.0.1", () => {
                const port = srv.address().port;
                srv.close(() => resolve(port));
            });
        });
    }

    /**
     * Poll a local port until it accepts a connection or times out.
     * @param {number} port Port to check
     * @param {number} timeoutMs Total wait time in ms
     * @returns {Promise<boolean>} true if port became available
     */
    waitForPort(port, timeoutMs) {
        return new Promise((resolve) => {
            const deadline = Date.now() + timeoutMs;
            const tryConnect = () => {
                const socket = new net.Socket();
                socket.setTimeout(1000);
                socket.on("connect", () => {
                    socket.destroy();
                    resolve(true);
                });
                socket.on("error", () => {
                    socket.destroy();
                    if (Date.now() > deadline) {
                        resolve(false);
                    } else {
                        setTimeout(tryConnect, 200);
                    }
                });
                socket.on("timeout", () => {
                    socket.destroy();
                    if (Date.now() > deadline) {
                        resolve(false);
                    } else {
                        setTimeout(tryConnect, 200);
                    }
                });
                socket.connect(port, "127.0.0.1");
            };
            tryConnect();
        });
    }
}

module.exports = { XraySubscriptionMonitorType };
