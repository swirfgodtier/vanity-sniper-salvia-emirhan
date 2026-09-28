import http2 from 'http2';
import https from 'https';
import tls from 'tls';
import WebSocket from 'ws';

const TOKEN = "";
const PASSWORD = "";
const SERVER = "";
const API_HOST = "canary.discord.com";
const API_IP = "162.159.135.232";
const REQ = 1; // her H2 baglantisindan REQ istek → toplam REQ*2
const REFRESH_INTERVAL = 240_000;
const RETRY_INTERVAL = 5_000;

let mfaToken = '';

// Pre-computed strings — her gonderimde allokasyon yok
const HB_STR = '{"op":1,"d":null}';
const IDENTIFY_STR = `{"op":2,"d":{"token":"${TOKEN}","intents":1,"properties":{"os":"linux","browser":"firefox","device":"kaka"}}}`;

const MFA_HEADERS = {
    'User-Agent': 'Chrome/124',
    'X-Super-Properties': 'eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==',
    'X-Discord-Timezone': 'Europe/Istanbul',
    'X-Discord-Locale': 'en-US',
    'X-Debug-Options': 'bugReporterEnabled',
    'Content-Type': 'application/json',
};

const httpRequest = (method, path, body) => new Promise((resolve, reject) => {
    const bodyBuf = Buffer.from(body);
    const req = https.request({
        hostname: API_HOST,
        path,
        method,
        headers: {
            ...MFA_HEADERS,
            'Authorization': TOKEN,
            'Content-Length': bodyBuf.length,
        },
        rejectUnauthorized: false,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    }, res => {
        let buf = null;
        res.on('data', c => { buf = buf ? Buffer.concat([buf, c]) : c; });
        res.on('end', () => resolve({ status: res.statusCode, body: buf ? buf.toString() : '' }));
    });
    req.on('error', reject);
    req.end(bodyBuf);
});

const refreshMfa = async () => {
    try {
        const ticketRes = await httpRequest('PATCH', '/api/v7/guilds/0/vanity-url', JSON.stringify({ code: 'xherz' }));
        if (ticketRes.status !== 401) {
            console.log(`mfa ticket alinamadi, status=${ticketRes.status}`);
            return false;
        }

        const ticket = JSON.parse(ticketRes.body)?.mfa?.ticket;
        if (!ticket) {
            console.log('mfa ticket yok response icinde');
            return false;
        }

        const mfaRes = await httpRequest('POST', '/api/v7/mfa/finish', JSON.stringify({ ticket, mfa_type: 'password', data: PASSWORD }));
        if (mfaRes.status === 200) {
            const token = JSON.parse(mfaRes.body)?.token;
            if (token) {
                mfaToken = token;
                console.log(`mfa alındı`);
                return true;
            }
        }

        console.log(`mfa finish basarisiz, status=${mfaRes.status} body=${mfaRes.body}`);
        return false;
    } catch (err) {
        console.log(`mfa hata: ${err.message}`);
        return false;
    }
};

const startMfaLoop = async () => {
    while (true) {
        const ok = await refreshMfa();
        await new Promise(r => setTimeout(r, ok ? REFRESH_INTERVAL : RETRY_INTERVAL));
    }
};

const BASE_HEADERS = {
    ':method': 'PATCH',
    ':authority': API_HOST,
    ':scheme': 'https',
    ':path': `/api/v9/guilds/${SERVER}/vanity-url`,
    'authorization': TOKEN,
    'content-type': 'application/json',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'x-super-properties': 'eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMi4wLjAuMCBTYWZhcmkvNTM3LjM2Iiwib3NfdmVyc2lvbiI6IjEwIn0='
};

// Patch body cache — her code icin Buffer bir kez olusturulur
const bodyCache = new Map();
const getBody = code => {
    if (!bodyCache.has(code)) bodyCache.set(code, Buffer.from(`{"code":"${code}"}`));
    return bodyCache.get(code);
};

// TLS session cache — yeniden baglanmada handshake atlanir
const sessA = { ref: undefined };
const sessB = { ref: undefined };

const makeSock = (sess) => {
    const sock = tls.connect({
        host: API_IP,
        port: 443,
        servername: API_HOST,
        ALPNProtocols: ['h2'],
        session: sess.ref,
    });
    sock.once('session', s => { sess.ref = s; });
    return sock;
};

// Iki ayri H2 baglantisi — REQ istek her birinden = REQ*2 paralel istek
let h2A, h2B;

const connectH2A = () => {
    const conn = http2.connect(`https://${API_HOST}`, { createConnection: () => makeSock(sessA) });
    let done = false;
    const retry = () => { if (!done) { done = true; conn.destroy(); setTimeout(connectH2A, 800); } };
    conn.on('error', retry);
    conn.on('close', retry);
    h2A = conn;
};

const connectH2B = () => {
    const conn = http2.connect(`https://${API_HOST}`, { createConnection: () => makeSock(sessB) });
    let done = false;
    const retry = () => { if (!done) { done = true; conn.destroy(); setTimeout(connectH2B, 800); } };
    conn.on('error', retry);
    conn.on('close', retry);
    h2B = conn;
};

const patch = code => {
    const body = getBody(code);
    const headers = { ...BASE_HEADERS, 'content-length': String(body.length) };
    if (mfaToken) headers['x-discord-mfa-authorization'] = mfaToken;

    for (let i = 0; i < REQ; i++) {
        const rA = h2A.request(headers);
        rA.on('data', chunk => console.log(chunk.toString()));
        rA.on('error', () => {});
        rA.end(body);

        const rB = h2B.request(headers);
        rB.on('data', chunk => console.log(chunk.toString()));
        rB.on('error', () => {});
        rB.end(body);
    }
};

const vanities = new Map();

const connectGateway = () => {
    const ws = new WebSocket('wss://gateway.discord.gg');

    ws.on('message', data => {
        const msg = JSON.parse(data);

        if (msg.op === 10) {
            setInterval(() => { if (ws.readyState === 1) ws.send(HB_STR); }, msg.d.heartbeat_interval);
            ws.send(IDENTIFY_STR);
        }

        if (msg.t === 'READY') {
            const guilds = msg.d?.guilds;
            if (guilds) {
                for (const guild of guilds) {
                    if (guild.id && typeof guild.vanity_url_code === 'string') {
                        vanities.set(guild.id, guild.vanity_url_code);
                        console.log(`{ server: \x1b[32m'${guild.id}'\x1b[0m, vanity: \x1b[32m'${guild.vanity_url_code}'\x1b[0m },`);
                    }
                }
            }
        }

        if (msg.t === 'GUILD_UPDATE') {
            const old = vanities.get(msg.d.id);
            if (old && old !== msg.d.vanity_url_code) {
                patch(old);
            }
        }
    });

    ws.on('error', () => setImmediate(connectGateway));
    ws.on('close', () => setImmediate(connectGateway));
};

startMfaLoop();
connectH2A();
connectH2B();
connectGateway();

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
