import tls from 'node:tls';
import net from 'node:net';
import VoidSocket from 'voidsocket';
import fs from 'node:fs';

const TOKEN = "srbrb";
const GUILD_ID = '1544968686291652608';
const DISCORD_HOST = 'canary.discord.com';
const EDGE_IPS = ['162.159.135.232', '162.159.128.233', '162.159.130.233'];
let DISCORD_IP = EDGE_IPS[0];
const SESSION_COUNT = 5;
const WEBHOOK_URL = ""; // buraya Discord webhook URL'ini yapistir

let isSniped = false;
let snipeAttemptCode = null;
let logCount = 0;
let bestIpMs = 0;
const activeSockets = [];
const vanityPayloads = new Map();
const vanityList = [];
const bufferPool = [];
let wsConnectedCount = 0;

const GUILD_UPDATE_BUF = Buffer.from('"t":"GUILD_UPDATE"');
const VANITY_NULL_BUF = Buffer.from('"vanity_url_code":null');
const READY_BUF = Buffer.from('"t":"READY"');
const OP10_BUF = Buffer.from('"op":10');
const OP7_BUF = Buffer.from('"op":7');

const H2_INIT_BUFFER = Buffer.concat([
    Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
    Buffer.from([0, 0, 0, 4, 0, 0, 0, 0, 0])
]);
const H2_PING_FRAME = Buffer.from([0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const IDENTIFY_PAYLOAD = JSON.stringify({ op: 2, d: { token: TOKEN, intents: 1, properties: { os: 'Windows', browser: 'Chrome' } } });
const HEARTBEAT_PAYLOAD = '{"op":1,"d":null}';

const TLS_SECURE_CONTEXT = tls.createSecureContext({
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ciphers: 'TLS_AES_128_GCM_SHA256'
});
const tlsSessions = [];

let currentMfa = '';
function loadMfa() {
    try { currentMfa = fs.readFileSync('mfa.txt').toString().trim(); } catch { currentMfa = ''; }
}

loadMfa();
fs.watch('mfa.txt', (eventType) => {
    if (eventType !== 'change') return;
    const oldMfa = currentMfa;
    loadMfa();
    if (oldMfa !== currentMfa) {
        console.log("mfa ok");
        for (const [guildId, payloadData] of vanityPayloads) {
            const rebuilt = buildHttp2Request(payloadData.code);
            rebuilt.guildIdBuf = payloadData.guildIdBuf;
            vanityPayloads.set(guildId, rebuilt);
        }
        vanityList.length = 0;
        for (const v of vanityPayloads.values()) vanityList.push(v);
    }
});

function pingIp(ip) {
    return new Promise((resolve) => {
        const start = performance.now();
        const s = net.connect({ host: ip, port: 443 });
        let done = false;
        const finish = (ms) => { if (done) return; done = true; try { s.destroy(); } catch { } resolve(ms); };
        s.setTimeout(2000);
        s.once('connect', () => finish(performance.now() - start));
        s.once('timeout', () => finish(Infinity));
        s.once('error', () => finish(Infinity));
    });
}

async function selectFastestIp() {
    const results = await Promise.all(EDGE_IPS.map(async (ip) => {
        let best = Infinity;
        for (let i = 0; i < 3; i++) {
            const ms = await pingIp(ip);
            if (ms < best) best = ms;
        }
        return { ip, ms: best };
    }));
    results.sort((a, b) => a.ms - b.ms);
    if (results[0] && results[0].ms !== Infinity) {
        DISCORD_IP = results[0].ip;
        bestIpMs = results[0].ms;
    }
}

function sendWebhook(content) {
    if (!WEBHOOK_URL) return;
    try {
        fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ content })
        }).catch(() => { });
    } catch { }
}

function allocateBuffer(size) {
    for (let i = bufferPool.length - 1; i >= 0; i--) {
        if (bufferPool[i].length >= size) {
            return bufferPool.splice(i, 1)[0].subarray(0, size);
        }
    }
    return Buffer.allocUnsafe(size);
}

function releaseBuffer(buf) {
    if (bufferPool.length < 50) bufferPool.push(buf);
}

function closeSocket(sock) {
    try {
        if (typeof sock.terminate === 'function') sock.terminate();
        else if (typeof sock.close === 'function') sock.close();
        else if (typeof sock.destroy === 'function') sock.destroy();
    } catch { }
}

function encodeHpackHeader(name, value) {
    const nameLen = Buffer.byteLength(name);
    const valLen = Buffer.byteLength(value);

    let valLenSize = 1;
    if (valLen >= 127) {
        let l = valLen - 127;
        while (l >= 128) { valLenSize++; l = Math.floor(l / 128); }
        valLenSize++;
    }

    const buf = allocateBuffer(2 + nameLen + valLenSize + valLen);
    let offset = 0;

    buf[offset++] = 0;
    buf[offset++] = nameLen;
    offset += buf.write(name, offset);

    if (valLen < 127) {
        buf[offset++] = valLen;
    } else {
        buf[offset++] = 127;
        let l = valLen - 127;
        while (l >= 128) {
            buf[offset++] = (l % 128) | 128;
            l = Math.floor(l / 128);
        }
        buf[offset++] = l;
    }
    buf.write(value, offset);

    return buf;
}

function buildHttp2Request(code) {
    const headerList = [
        [':method', 'PATCH'],
        [':path', `/api/v10/guilds/${GUILD_ID}/vanity-url`],
        [':authority', DISCORD_HOST],
        [':scheme', 'https'],
        ['authorization', TOKEN],
        ['x-discord-mfa-authorization', currentMfa],
        ['content-type', 'application/json'],
        ['user-agent', 'Mozilla/5.0'],
        ['x-super-properties', 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQ1Njc4LCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUifQ==']
    ];

    const hpackBuffers = headerList.map(([k, v]) => encodeHpackHeader(k, v));
    const hpackLen = hpackBuffers.reduce((acc, b) => acc + b.length, 0);
    const hpackBuf = allocateBuffer(hpackLen);
    let hOffset = 0;
    for (const b of hpackBuffers) {
        b.copy(hpackBuf, hOffset);
        hOffset += b.length;
    }

    const codeLen = Buffer.byteLength(code);
    const bodyLen = 11 + codeLen;

    const totalFrameLen = 18 + hpackLen + bodyLen;
    const buffer = allocateBuffer(totalFrameLen);

    buffer.writeUIntBE(hpackLen, 0, 3);
    buffer[3] = 1;
    buffer[4] = 4;
    buffer.writeUInt32BE(1, 5);

    hpackBuf.copy(buffer, 9);

    const dataOffset = 9 + hpackLen;
    buffer.writeUIntBE(bodyLen, dataOffset, 3);
    buffer[dataOffset + 3] = 0;
    buffer[dataOffset + 4] = 1;
    buffer.writeUInt32BE(1, dataOffset + 5);

    const bodyOffset = dataOffset + 9;
    buffer.write('{"code":"', bodyOffset);
    buffer.write(code, bodyOffset + 9);
    buffer.write('"}', bodyOffset + 9 + codeLen);

    releaseBuffer(hpackBuf);

    return { code, buffer, codeQuoteBuf: Buffer.from(`"${code}"`) };
}

function createTlsSocket(index) {
    if (activeSockets[index]) {
        try { activeSockets[index].destroy(); } catch { }
    }

    const socket = tls.connect({
        host: DISCORD_IP,
        port: 443,
        servername: DISCORD_HOST,
        ALPNProtocols: ['h2'],
        secureContext: TLS_SECURE_CONTEXT,
        session: tlsSessions[index],
        rejectUnauthorized: false
    });

    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.setKeepAlive(true, 3000);
    socket.isWaitingForSnipeResponse = false;
    socket.snipeSentAt = 0;

    socket.on('session', (s) => { tlsSessions[index] = s; });

    socket.on('secureConnect', () => {
        socket.write(H2_INIT_BUFFER);
        activeSockets[index] = socket;
    });

    socket.on('data', (chunk) => {
        if (!socket.isWaitingForSnipeResponse) return;
        const recvAt = performance.now();

        let offset = 0;
        while (offset + 9 <= chunk.length) {
            const length = chunk.readUIntBE(offset, 3);
            const type = chunk[offset + 3];
            const streamId = chunk.readUInt32BE(offset + 5) & 0x7fffffff;

            if (streamId === 1) {
                if (type === 0) {
                    const payload = chunk.subarray(offset + 9, offset + 9 + length);
                    const ms = socket.snipeSentAt ? recvAt - socket.snipeSentAt : 0;
                    if (logCount < 2) {
                        logCount++;
                        const body = payload.toString().substring(0, 500);
                        console.log(`Result for \x1b[32m${snipeAttemptCode}\x1b[0m: ${body} ${ms.toFixed(3)}ms`);
                        sendWebhook(`Result for ${snipeAttemptCode}: ${body} ${ms.toFixed(3)}ms`);
                    }
                    socket.isWaitingForSnipeResponse = false;
                } else if (type === 1 && (chunk[offset + 4] & 1)) {
                    const ms = socket.snipeSentAt ? recvAt - socket.snipeSentAt : 0;
                    if (logCount < 2) {
                        logCount++;
                        console.log(`siz yokken athena vardi kimse sk gelionuz \x1b[32m${snipeAttemptCode}\x1b[0m [HEADERS END_STREAM] ${ms.toFixed(3)}ms`);
                        sendWebhook(`siz yokken athena vardi kime sik gelionuz${snipeAttemptCode} [HEADERS END_STREAM] ${ms.toFixed(3)}ms`);
                    }
                    socket.isWaitingForSnipeResponse = false;
                }
            }
            offset += 9 + length;
        }
    });

    socket.on('error', () => {
        setTimeout(() => createTlsSocket(index), 50);
    });

    socket.on('close', () => {
        setTimeout(() => createTlsSocket(index), 50);
    });
}

selectFastestIp().then(() => {
    console.log("baglandik", DISCORD_IP, bestIpMs.toFixed(1) + "ms");
    for (let i = 0; i < SESSION_COUNT; i++) createTlsSocket(i);
});

setInterval(async () => {
    const prev = DISCORD_IP;
    await selectFastestIp();
    console.log("baglandik", DISCORD_IP, bestIpMs.toFixed(1) + "ms");
    if (DISCORD_IP !== prev) {
        for (const socket of activeSockets) {
            try { socket.destroy(); } catch { }
        }
    }
}, 5 * 60 * 1000);

function startGatewayConnection(wsIndex, gatewayUrl) {
    const ws = new VoidSocket(gatewayUrl, {
        skipUTF8Validation: true,
        perMessageDeflate: false
    });
    let heartbeatInterval;

    ws.on('open', () => {
        wsConnectedCount++;
        console.log("ws ok");
        if (ws._socket) {
            ws._socket.setNoDelay(true);
            ws._socket.setTimeout(0);
            ws._socket.setKeepAlive(true, 3000);
        }
    });

    ws.on('message', (data) => {
        if (data.includes(GUILD_UPDATE_BUF)) {
            if (isSniped) return;
            for (let vi = 0; vi < vanityList.length; vi++) {
                const cached = vanityList[vi];
                if (data.includes(cached.guildIdBuf) && (data.includes(VANITY_NULL_BUF) || !data.includes(cached.codeQuoteBuf))) {
                    isSniped = true;
                    snipeAttemptCode = cached.code;
                    const snipeBuffer = cached.buffer;
                    const sentAt = performance.now();
                    for (let i = 0; i < SESSION_COUNT; i++) {
                        const socket = activeSockets[i];
                        if (socket && !socket.destroyed) {
                            socket.isWaitingForSnipeResponse = true;
                            socket.snipeSentAt = sentAt;
                            socket.write(snipeBuffer);
                        }
                    }
                    return;
                }
            }
            return;
        }

        if (!data.includes(READY_BUF) && !data.includes(OP10_BUF) && !data.includes(OP7_BUF)) return;

        try {
            const message = JSON.parse(data);

            if (message.t === 'READY') {
                console.log("req", SESSION_COUNT);
                vanityPayloads.clear();
                vanityList.length = 0;
                for (const guild of message.d.guilds || []) {
                    if (guild.vanity_url_code) {
                        const payload = buildHttp2Request(guild.vanity_url_code);
                        payload.guildIdBuf = Buffer.from(guild.id);
                        vanityPayloads.set(guild.id, payload);
                        vanityList.push(payload);
                    }
                }
            } else if (message.op === 10) {
                console.log("orda her kiminleysen");
                ws.send(IDENTIFY_PAYLOAD);
                heartbeatInterval = setInterval(() => ws.send(HEARTBEAT_PAYLOAD), message.d.heartbeat_interval);
            } else if (message.op === 7) {
                closeSocket(ws);
            }
        } catch { }
    });

    ws.on('close', () => {
        wsConnectedCount--;
        clearInterval(heartbeatInterval);
        setTimeout(() => startGatewayConnection(wsIndex, gatewayUrl), 50);
    });
    ws.on('error', () => closeSocket(ws));
}

setInterval(() => {
    for (const socket of activeSockets) {
        if (socket && !socket.destroyed) {
            socket.write(H2_PING_FRAME);
        }
    }
}, 5000);

startGatewayConnection(0, 'wss://gateway.discord.gg/?v=10&encoding=json');
startGatewayConnection(1, 'wss://us-east1-c.gateway.discord.gg/?v=10&encoding=json');
startGatewayConnection(2, 'wss://eu-west1.gateway.discord.gg/?v=10&encoding=json');
startGatewayConnection(3, 'wss://ap-southeast1.gateway.discord.gg/?v=10&encoding=json');
