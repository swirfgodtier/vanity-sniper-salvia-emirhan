"use strict";

process.env.UV_THREADPOOL_SIZE = "128";
process.env.NODE_NO_WARNINGS = "1";

const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');
const tls = require('node:tls');
const fs = require('node:fs');
const crypto = require('node:crypto');
const http2 = require('node:http2');
const os = require('node:os');

const TOKEN = 'qe';
const GUILD = '1544968686291652608';
const REQ = 6;
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36';
const SP = 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MiLCJvc192ZXJzaW9uIjoiIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQ1Njc4fQ==';

const IDENTIFY = JSON.stringify({
    op: 2,
    d: {
        token: TOKEN,
        intents: 1,
        properties: { os: 'Windows', browser: 'Chrome', device: 'shy' }
    }
});
const IDENTIFY_BUF = Buffer.from(IDENTIFY);

const SAB_SIZE = 7 * 1024 * 1024;
const sabGlobal = new SharedArrayBuffer(SAB_SIZE);
const sabState = new SharedArrayBuffer(16);
const stateInt32 = new Int32Array(sabState);
const sharedPayloadBuffer = Buffer.from(sabGlobal);

const GUILD_UPDATE_BUF = Buffer.from('"t":"GUILD_UPDATE"');
const VANITY_NULL_BUF = Buffer.from('"vanity_url_code":null');
const READY_BUF = Buffer.from('"t":"READY"');
const OP10_BUF = Buffer.from('"op":10');
const OP7_BUF = Buffer.from('"op":7');
const GUILD_UPDATE = GUILD_UPDATE_BUF;
const ID_STR = Buffer.from('"id":"');
const HTTP_OK = 200;

class CacheEntry {
    constructor(id, code, mfa) {
        this.id = id;
        this.idBuf = Buffer.from(id);
        this.idLen = this.idBuf.length;
        this.c = code;
        this.v = Buffer.from(`"vanity_url_code":"${code}"`);
        this.build(mfa);
    }

    build(mfa) {
        const h = {
            ':method': 'PATCH',
            ':path': `/api/v9/guilds/${GUILD}/vanity-url`,
            ':authority': 'canary.discord.com',
            ':scheme': 'https',
            'authorization': TOKEN,
            'content-type': 'application/json',
            'user-agent': USER_AGENT,
            'x-super-properties': SP
        };
        if (mfa) h['x-discord-mfa-authorization'] = mfa;
        this.headers = h;
        this.body = Buffer.from(`{"code":"${this.c}"}`);
        this.bodyLen = this.body.length;
    }

    rebuild(mfa) {
        this.build(mfa);
    }
}

class LatencySmoother {
    constructor(alpha = 0.2) {
        this.alpha = alpha;
        this.value = null;
        this.samples = 0;
        this.warmup = 3;
    }
    push(ms) {
        this.samples++;
        if (this.samples <= this.warmup) {
            this.value = this.value === null ? ms : (this.value + ms) / 2;
            return this.value;
        }
        const expected = this.value;
        const dev = Math.abs(ms - expected);
        if (dev > expected * 2.5 && expected > 0) {
            this.value = expected + (ms - expected) * 0.05;
        } else {
            this.value = expected + (ms - expected) * this.alpha;
        }
        return this.value;
    }
}

if (isMainThread) {
    console.log('ayni klasmanda bile takilmiyoruz :)');

    try {
        if (process.platform === "win32") {
            require("child_process").exec(
                `powershell -Command "[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime"`,
                () => {}
            );
        } else if (typeof os.setPriority === "function") {
            try { os.setPriority(process.pid, -20); } catch (e) {}
        }
    } catch (e) {}

    let mfa = '';
    try {
        mfa = fs.readFileSync('mfa.txt', 'utf8').trim();
        if (mfa) console.log('mfa ok');
    } catch (e) {}

    let mfaDebounce = null;
    fs.watch('mfa.txt', () => {
        clearTimeout(mfaDebounce);
        mfaDebounce = setTimeout(() => {
            try {
                mfa = fs.readFileSync('mfa.txt', 'utf8').trim();
                for (const entry of cacheList) entry.rebuild(mfa);
                if (mfa) console.log('mfa ok');
            } catch (e) {}
        }, 200);
    });

    let cacheList = [];
    const cacheMap = Object.create(null);
    let sniped = false;
    let claimed = false;

    const h2Sessions = new Array(REQ).fill(null);
    let h2RotateIndex = 0;
    const latSmoother = new LatencySmoother();

    function connectH2(idx) {
        if (sniped) return;
        const old = h2Sessions[idx];
        if (old) {
            try { old.destroy(); } catch (e) {}
        }

        const tlsSock = tls.connect({
            host: 'canary.discord.com',
            port: 443,
            servername: 'canary.discord.com',
            rejectUnauthorized: false,
            ALPNProtocols: ['h2'],
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            ciphers: 'TLS_AES_128_GCM_SHA256',
            ecdhCurve: 'X25519',
            noDelay: true,
            keepAlive: true,
            keepAliveInitialDelay: 1000
        });

        tlsSock.setNoDelay(true);
        tlsSock.setKeepAlive(true, 1000);

        tlsSock.on('secureConnect', () => {
            if (tlsSock.alpnProtocol !== 'h2') {
                try { tlsSock.destroy(); } catch (e) {}
                setTimeout(() => connectH2(idx), 1000);
                return;
            }

            const session = http2.connect('https://canary.discord.com', {
                createConnection: () => tlsSock,
                settings: {
                    enablePush: false,
                    initialWindowSize: 1 << 24,
                    maxConcurrentStreams: 256,
                    maxFrameSize: 1 << 14,
                    maxHeaderListSize: 1 << 16
                },
                maxSessionMemory: 100,
                peerMaxConcurrentStreams: 256
            });

            session.setTimeout(0);
            session.setLocalWindowSize(1 << 24);

            session.on('error', () => {
                if (h2Sessions[idx] === session) h2Sessions[idx] = null;
            });
            session.on('close', () => {
                if (h2Sessions[idx] === session) h2Sessions[idx] = null;
            });
            session.on('goaway', () => {
                try { session.close(); } catch (e) {}
                if (!sniped) setTimeout(() => connectH2(idx), 500);
            });

            const prewarmHeaders = {
                ':method': 'PATCH',
                ':path': `/api/v9/guilds/${GUILD}/vanity-url`,
                ':authority': 'canary.discord.com',
                ':scheme': 'https',
                'authorization': TOKEN,
                'content-type': 'application/json',
                'user-agent': USER_AGENT,
                'x-super-properties': SP
            };
            if (mfa) prewarmHeaders['x-discord-mfa-authorization'] = mfa;

            const prewarmStream = session.request(prewarmHeaders);
            prewarmStream.on('error', () => {});
            prewarmStream.on('response', () => { try { prewarmStream.destroy(); } catch (e) {} });
            prewarmStream.end('{"code":"__prewarm__"}');

            const warmHead = session.request({
                ':method': 'HEAD',
                ':path': '/api/v9/gateway',
                'user-agent': USER_AGENT
            });
            warmHead.on('error', () => {});
            warmHead.on('response', () => { try { warmHead.destroy(); } catch (e) {} });
            warmHead.end();

            h2Sessions[idx] = session;
        });

        tlsSock.on('error', () => {
            if (!sniped) setTimeout(() => connectH2(idx), 500);
        });
    }

    for (let i = 0; i < REQ; i++) connectH2(i);

    setInterval(() => {
        if (sniped) return;
        connectH2(h2RotateIndex);
        h2RotateIndex = (h2RotateIndex + 1) % REQ;
    }, 20000);

    setInterval(() => {
        if (sniped) return;
        for (const s of h2Sessions) {
            if (s && !s.closed && !s.destroyed) {
                try { s.ping(() => {}); } catch (e) {}
            }
        }
    }, 8000);

    function fireH2(entry) {
        const headers = entry.headers;
        const body = entry.body;
        const code = entry.c;

        for (let i = 0; i < REQ; i++) {
            const session = h2Sessions[i];
            if (!session || session.closed || session.destroyed) continue;

            const streamT0 = process.hrtime.bigint();

            try {
                const stream = session.request(headers);
                const chunks = [];
                let status = 0;

                stream.on('response', (resHeaders) => {
                    status = resHeaders[':status'];
                });
                stream.on('data', (chunk) => { chunks.push(chunk); });
                stream.on('error', () => {});
                stream.on('end', () => {
                    const ms = Number(process.hrtime.bigint() - streamT0) / 1e6;
                    const smoothMs = latSmoother.push(ms);

                    const bodyBuf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
                    let bodyOut;
                    try {
                        bodyOut = bodyBuf.length ? JSON.parse(bodyBuf.toString('utf8')) : {};
                    } catch (e) {
                        bodyOut = { raw: bodyBuf.toString('utf8', 0, Math.min(300, bodyBuf.length)) };
                    }

                    console.log(JSON.stringify({
                        req: code,
                        ms: Number(smoothMs.toFixed(1)),
                        status: status,
                        body: bodyOut
                    }));

                    if (status === HTTP_OK && bodyOut &&
                        (bodyOut.code === code || bodyOut.vanity_url_code === code) &&
                        !claimed) {
                        claimed = true;
                    }
                });
                stream.end(body);
            } catch (e) {}
        }
    }

    function handleSnipeFastLane(r) {
        if (sniped) return;

        const updateIdx = r.indexOf(GUILD_UPDATE_BUF);
        if (updateIdx === -1) return;

        const idx = r.indexOf(ID_STR, updateIdx + 14);
        if (idx === -1) return;

        const startIdx = idx + 6;
        const end = r.indexOf(34, startIdx);
        const idLen = end - startIdx;
        const targetIdBuf = r.subarray(startIdx, end);

        let targetEntry = null;
        for (let i = 0; i < cacheList.length; i++) {
            if (cacheList[i].idLen === idLen && targetIdBuf.equals(cacheList[i].idBuf)) {
                targetEntry = cacheList[i];
                break;
            }
        }

        if (!targetEntry) return;
        if (r.indexOf(targetEntry.v, end) !== -1) return;

        const isVanityNull = r.indexOf(VANITY_NULL_BUF, end) !== -1;
        if (!isVanityNull && r.indexOf(targetEntry.v, end) !== -1) return;

        sniped = true;
        fireH2(targetEntry);
    }

    function parseREADY(r) {
        try {
            const startJson = r.indexOf(123);
            if (startJson === -1) return;
            const readyData = JSON.parse(r.toString('utf8', startJson));
            const guilds = readyData.d?.guilds || [];

            const newList = [];
            for (const g of guilds) {
                if (g.vanity_url_code) {
                    const existing = cacheMap[g.id];
                    if (existing && existing.c === g.vanity_url_code) {
                        newList.push(existing);
                    } else {
                        const entry = new CacheEntry(g.id, g.vanity_url_code, mfa);
                        cacheMap[g.id] = entry;
                        newList.push(entry);
                    }
                }
            }
            cacheList = newList;
        } catch (e) {}
    }

    const gwWorker = new Worker(__filename, {
        workerData: { TOKEN, USER_AGENT, sabGlobal, sabState, IDENTIFY_BUF }
    });

    gwWorker.on('message', (msg) => {
        if (msg === 2) {
            handleSnipeFastLane(sharedPayloadBuffer.subarray(0, Atomics.load(stateInt32, 0)));
            Atomics.store(stateInt32, 1, 0);
        } else if (msg === 1) {
            const buf = sharedPayloadBuffer.subarray(0, Atomics.load(stateInt32, 0));
            if (buf.indexOf(READY_BUF) !== -1) {
                parseREADY(buf);
                console.log('ws ok');
            }
            Atomics.store(stateInt32, 1, 0);
        } else if (msg.type === 'HEARTBEAT_INTERVAL') {
            gwWorker.postMessage({ type: 'HEARTBEAT_INTERVAL', interval: msg.interval });
        }
    });

    process.on('SIGINT', () => {
        sniped = true;
        for (const s of h2Sessions) { try { s?.destroy(); } catch (e) {} }
        process.exit(0);
    });

} else {
    const { TOKEN, USER_AGENT, sabGlobal, sabState, IDENTIFY_BUF } = workerData;
    const workerStateInt32 = new Int32Array(sabState);
    const workerPayloadBuffer = Buffer.from(sabGlobal);

    let gatewaySessionCache = null;
    let gatewaySessionTime = 0;
    const SESSION_TTL = 7200000;
    let activeTlsSocket = null;
    let hbInterval = null;
    let prewarmInterval = null;
    let keepaliveInterval = null;
    let reconnectAttempts = 0;

    const PING_BUF = Buffer.from('{"op":1,"d":null}');
    const KEEPALIVE_PING = Buffer.from('{"op":11,"d":{}}');

    const sharedGwCtx = tls.createSecureContext({
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3'
    });

    const handshakeBuf = Buffer.allocUnsafe(4096);

    function sendWsFrame(socket, rawBuffer, opcodeNumber) {
        const op = opcodeNumber & 0x0F;
        const len = rawBuffer.length;
        const maskKey = Buffer.allocUnsafe(4);
        crypto.randomFillSync(maskKey);

        let headerOffset, frameSize;
        if (len < 126) { headerOffset = 2; frameSize = len + 6; }
        else if (len < 65536) { headerOffset = 4; frameSize = len + 8; }
        else { headerOffset = 10; frameSize = len + 14; }

        const frameBuffer = Buffer.allocUnsafe(frameSize);
        frameBuffer[0] = 0x80 | op;

        if (len < 126) {
            frameBuffer[1] = 0x80 | len;
        } else if (len < 65536) {
            frameBuffer[1] = 0x80 | 126;
            frameBuffer.writeUInt16BE(len, 2);
        } else {
            frameBuffer[1] = 0x80 | 127;
            frameBuffer.writeBigUInt64BE(BigInt(len), 2);
        }

        frameBuffer[headerOffset] = maskKey[0];
        frameBuffer[headerOffset + 1] = maskKey[1];
        frameBuffer[headerOffset + 2] = maskKey[2];
        frameBuffer[headerOffset + 3] = maskKey[3];

        const payloadStart = headerOffset + 4;
        for (let i = 0; i < len; i++) {
            frameBuffer[payloadStart + i] = rawBuffer[i] ^ maskKey[i & 3];
        }
        socket.write(frameBuffer);
    }

    function startPrewarm() {
        if (prewarmInterval) clearInterval(prewarmInterval);
        prewarmInterval = setInterval(() => {
            if (activeTlsSocket && activeTlsSocket.writable) {
                try {
                    sendWsFrame(activeTlsSocket, PING_BUF, 1);
                    sendWsFrame(activeTlsSocket, KEEPALIVE_PING, 11);
                } catch (e) {}
            }
        }, 15000);
    }

    function startKeepalive() {
        if (keepaliveInterval) clearInterval(keepaliveInterval);
        keepaliveInterval = setInterval(() => {
            if (activeTlsSocket && activeTlsSocket.writable) {
                try { sendWsFrame(activeTlsSocket, PING_BUF, 1); } catch (e) {}
            }
            parentPort.postMessage({ type: 'KEEPALIVE_RESPONSE', timestamp: Date.now() });
        }, 25000);
    }

    class ParserState {
        constructor() {
            this.stage = 0;
            this.opcode = 0;
            this.isMasked = 0;
            this.maskOffset = 0;
            this.payloadLen = 0;
            this.extendedLenBytes = 0;
            this.extendedLenRead = 0;
            this.payloadOffset = 0;
            this.fragmentedOpcode = 0;
            this.maskKey = Buffer.allocUnsafe(4);
            this.extendedLenBuf = Buffer.allocUnsafe(8);
        }
    }

    const FRAGMENT_POOL_INIT = 256 * 1024;

    function nativeWsStreamParser(socket) {
        const state = new ParserState();
        let chunkLen = 0, chunkOffset = 0, needed = 0, available = 0, toRead = 0;
        let b = 0, basicLen = 0, isFin = false;

        let fragmentPool = Buffer.allocUnsafe(FRAGMENT_POOL_INIT);
        let fragmentPoolSize = FRAGMENT_POOL_INIT;
        let fragmentedTotal = 0;
        let fragmentedOpcode = 0;
        let fragmentedIsText = false;
        let fragmentedMaskKey = null;
        let fragmentedIsMasked = 0;
        let isFragmented = false;

        const ensureFragmentCapacity = (required) => {
            if (required <= fragmentPoolSize) return;
            let newSize = fragmentPoolSize;
            while (newSize < required) newSize *= 2;
            if (newSize > SAB_SIZE) newSize = SAB_SIZE;
            const grown = Buffer.allocUnsafe(newSize);
            fragmentPool.copy(grown, 0, 0, fragmentedTotal);
            fragmentPool = grown;
            fragmentPoolSize = newSize;
        };

        const local_maskKey = state.maskKey;
        const local_extendedLenBuf = state.extendedLenBuf;

        socket.on('data', (chunk) => {
            chunkLen = chunk.length;
            chunkOffset = 0;

            if (state.stage === 0 && chunkLen >= 2 && !isFragmented) {
                const b0 = chunk[0];
                const b1 = chunk[1];
                if (b0 === 0x81 && (b1 & 0x80) === 0) {
                    let headerLen = 2;
                    let payloadLen = b1 & 0x7F;
                    if (payloadLen === 126 && chunkLen >= 4) {
                        headerLen = 4;
                        payloadLen = (chunk[2] << 8) | chunk[3];
                    }
                    if (payloadLen < 126 || (payloadLen >= 126 && payloadLen < 65536 && chunkLen === headerLen + payloadLen)) {
                        if (chunkLen === headerLen + payloadLen) {
                            chunk.copy(workerPayloadBuffer, 0, headerLen, chunkLen);
                            if (Atomics.load(workerStateInt32, 1) === 0) {
                                Atomics.store(workerStateInt32, 0, payloadLen);
                                Atomics.store(workerStateInt32, 1, 1);
                                if (workerPayloadBuffer.subarray(0, payloadLen).indexOf(GUILD_UPDATE_BUF) !== -1) {
                                    parentPort.postMessage(2);
                                } else {
                                    parentPort.postMessage(1);
                                }
                            }
                            return;
                        }
                    }
                }
            }

            let s_stage = state.stage;
            let s_opcode = state.opcode;
            let s_isMasked = state.isMasked;
            let s_maskOffset = state.maskOffset;
            let s_payloadLen = state.payloadLen;
            let s_extendedLenBytes = state.extendedLenBytes;
            let s_extendedLenRead = state.extendedLenRead;
            let s_payloadOffset = state.payloadOffset;
            let s_fragmentedOpcode = state.fragmentedOpcode;

            while (chunkOffset < chunkLen) {
                if (s_stage === 0) {
                    b = chunk[chunkOffset];
                    isFin = (b & 0x80) === 0x80;
                    s_opcode = b & 0x0F;
                    s_opcode = (s_opcode === 0 && s_fragmentedOpcode !== 0) ? s_fragmentedOpcode : s_opcode;
                    s_fragmentedOpcode = (!isFin && s_opcode > 0 && s_opcode < 8) ? s_opcode : s_fragmentedOpcode;
                    chunkOffset++;
                    s_stage = 1;
                    if (chunkOffset >= chunkLen) break;
                }
                if (s_stage === 1) {
                    b = chunk[chunkOffset];
                    chunkOffset++;
                    s_isMasked = ((b & 0x80) === 0x80) ? 1 : 0;
                    basicLen = b & 0x7F;
                    if (basicLen === 126) {
                        s_stage = 2; s_extendedLenBytes = 2; s_extendedLenRead = 0;
                    } else if (basicLen === 127) {
                        s_stage = 2; s_extendedLenBytes = 8; s_extendedLenRead = 0;
                    } else {
                        s_payloadLen = basicLen;
                        s_stage = (s_isMasked === 1) ? 3 : 4;
                        s_maskOffset = 0; s_payloadOffset = 0;
                    }
                    if (chunkOffset >= chunkLen) break;
                }
                if (s_stage === 2) {
                    needed = s_extendedLenBytes - s_extendedLenRead;
                    available = chunkLen - chunkOffset;
                    toRead = available < needed ? available : needed;
                    chunk.copy(local_extendedLenBuf, s_extendedLenRead, chunkOffset, chunkOffset + toRead);
                    s_extendedLenRead += toRead;
                    chunkOffset += toRead;
                    if (s_extendedLenRead === s_extendedLenBytes) {
                        s_payloadLen = (s_extendedLenBytes === 2)
                            ? local_extendedLenBuf.readUInt16BE(0)
                            : Number(local_extendedLenBuf.readBigUInt64BE(0));
                        s_stage = (s_isMasked === 1) ? 3 : 4;
                        s_maskOffset = 0; s_payloadOffset = 0;
                    }
                    if (chunkOffset >= chunkLen) break;
                }
                if (s_stage === 3) {
                    needed = 4 - s_maskOffset;
                    available = chunkLen - chunkOffset;
                    toRead = available < needed ? available : needed;
                    chunk.copy(local_maskKey, s_maskOffset, chunkOffset, chunkOffset + toRead);
                    s_maskOffset += toRead;
                    chunkOffset += toRead;
                    if (s_maskOffset === 4) s_stage = 4;
                    if (chunkOffset >= chunkLen) break;
                }
                if (s_stage === 4) {
                    needed = s_payloadLen - s_payloadOffset;
                    available = chunkLen - chunkOffset;
                    toRead = available < needed ? available : needed;

                    const isFirstFragment = (!isFragmented && !isFin && s_opcode !== 0);
                    const isContinuingFragment = isFragmented;

                    if (isFirstFragment) {
                        fragmentedOpcode = s_opcode;
                        fragmentedIsText = (fragmentedOpcode === 1);
                        fragmentedTotal = 0;
                        isFragmented = true;
                        fragmentedIsMasked = s_isMasked;
                        if (s_isMasked === 1) {
                            fragmentedMaskKey = Buffer.allocUnsafe(4);
                            local_maskKey.copy(fragmentedMaskKey, 0, 0, 4);
                        }
                    }

                    if (isFirstFragment || isContinuingFragment) {
                        ensureFragmentCapacity(fragmentedTotal + toRead);
                        chunk.copy(fragmentPool, fragmentedTotal, chunkOffset, chunkOffset + toRead);
                        fragmentedTotal += toRead;
                    } else {
                        chunk.copy(workerPayloadBuffer, s_payloadOffset, chunkOffset, chunkOffset + toRead);
                    }

                    s_payloadOffset += toRead;
                    chunkOffset += toRead;

                    if (s_payloadOffset === s_payloadLen) {
                        let finalPayload = null;
                        let finalLen = 0;
                        let wasFragmented = false;

                        if (isFin && isFragmented) {
                            wasFragmented = true;
                            finalPayload = fragmentPool;
                            finalLen = fragmentedTotal;
                            isFragmented = false;
                            fragmentedTotal = 0;
                        } else if (isFin && !isFragmented) {
                            finalPayload = workerPayloadBuffer;
                            finalLen = s_payloadLen;
                        }

                        if (finalPayload !== null && finalLen > 0) {
                            const shouldUnmask = wasFragmented ? (fragmentedIsMasked === 1) : (s_isMasked === 1);
                            if (shouldUnmask) {
                                const maskSrc = wasFragmented ? fragmentedMaskKey : local_maskKey;
                                for (let i = 0; i < finalLen; i++) {
                                    finalPayload[i] ^= maskSrc[i & 3];
                                }
                            }
                            if (wasFragmented && finalPayload !== workerPayloadBuffer) {
                                finalPayload.copy(workerPayloadBuffer, 0, 0, finalLen);
                            }
                        }

                        if (s_opcode === 8) {
                            parentPort.postMessage({ type: 'TERMINATE' });
                        }

                        if (s_opcode === 1 || s_opcode === 2 || (wasFragmented && fragmentedIsText)) {
                            if (isFin && !isFragmented && Atomics.load(workerStateInt32, 1) === 0) {
                                const msgLen = wasFragmented ? finalLen : s_payloadLen;
                                Atomics.store(workerStateInt32, 0, msgLen);
                                Atomics.store(workerStateInt32, 1, 1);
                                const view = workerPayloadBuffer.subarray(0, msgLen);

                                if (view.indexOf(OP7_BUF) !== -1) {
                                    parentPort.postMessage({ type: 'RECONNECT' });
                                } else if (view.indexOf(GUILD_UPDATE_BUF) !== -1) {
                                    parentPort.postMessage(2);
                                } else {
                                    parentPort.postMessage(1);
                                }
                            }
                        }

                        if (wasFragmented) fragmentedMaskKey = null;
                        s_stage = 0;
                    }
                }
            }

            state.stage = s_stage;
            state.opcode = s_opcode;
            state.isMasked = s_isMasked;
            state.maskOffset = s_maskOffset;
            state.payloadLen = s_payloadLen;
            state.extendedLenBytes = s_extendedLenBytes;
            state.extendedLenRead = s_extendedLenRead;
            state.payloadOffset = s_payloadOffset;
            state.fragmentedOpcode = s_fragmentedOpcode;
        });
    }

    function connectGateway() {
        if (activeTlsSocket) {
            try { activeTlsSocket.destroy(); } catch (e) {}
            activeTlsSocket = null;
        }
        if (hbInterval) { clearInterval(hbInterval); hbInterval = null; }
        if (prewarmInterval) { clearInterval(prewarmInterval); prewarmInterval = null; }
        if (keepaliveInterval) { clearInterval(keepaliveInterval); keepaliveInterval = null; }

        const tlsSock = tls.connect({
            host: 'gateway.discord.gg',
            port: 443,
            servername: 'gateway.discord.gg',
            rejectUnauthorized: false,
            secureContext: sharedGwCtx,
            session: (gatewaySessionCache && (Date.now() - gatewaySessionTime) < SESSION_TTL) ? gatewaySessionCache : null,
            noDelay: true,
            keepAlive: true,
            checkServerIdentity: () => {},
            ALPNProtocols: ['http/1.1']
        });

        tlsSock.setNoDelay(true);
        tlsSock.setKeepAlive(true, 1000);

        tlsSock.on('secureConnect', () => {
            activeTlsSocket = tlsSock;
            tlsSock.resume();

            const nonce = crypto.randomBytes(16).toString('base64');
            const upgradeReq =
                `GET /?v=9&encoding=json HTTP/1.1\r\n` +
                `Host: gateway.discord.gg\r\n` +
                `Upgrade: websocket\r\n` +
                `Connection: Upgrade\r\n` +
                `Sec-WebSocket-Key: ${nonce}\r\n` +
                `Sec-WebSocket-Version: 13\r\n` +
                `User-Agent: ${USER_AGENT}\r\n\r\n`;
            tlsSock.write(upgradeReq);

            let handshakeLen = 0;
            const onHandshakeData = (chunk) => {
                const copyLen = Math.min(chunk.length, handshakeBuf.length - handshakeLen);
                chunk.copy(handshakeBuf, handshakeLen, 0, copyLen);
                handshakeLen += copyLen;

                const headerEnd = handshakeBuf.indexOf('\r\n\r\n', 0);
                if (headerEnd !== -1 && headerEnd < handshakeLen) {
                    const remainingChunk = handshakeBuf.subarray(headerEnd + 4, handshakeLen);
                    if (handshakeBuf.indexOf('HTTP/1.1 101') !== -1) {
                        tlsSock.removeListener('data', onHandshakeData);
                        nativeWsStreamParser(tlsSock);
                        tlsSock.cork();
                        sendWsFrame(tlsSock, IDENTIFY_BUF, 1);
                        tlsSock.uncork();
                        startPrewarm();
                        startKeepalive();
                        if (remainingChunk.length > 0) {
                            tlsSock.emit('data', Buffer.from(remainingChunk));
                        }
                        reconnectAttempts = 0;

                        const op10Idx = remainingChunk.indexOf(OP10_BUF);
                        if (op10Idx !== -1) {
                            try {
                                const parsed = JSON.parse(remainingChunk.toString());
                                if (parsed.op === 10) {
                                    parentPort.postMessage({ type: 'HEARTBEAT_INTERVAL', interval: parsed.d.heartbeat_interval });
                                }
                            } catch (e) {}
                        }
                    } else if (handshakeLen > 2048) {
                        tlsSock.destroy();
                    }
                }
            };
            tlsSock.on('data', onHandshakeData);
        });

        tlsSock.on('session', (ticket) => {
            if (ticket && ticket.length > 0) {
                gatewaySessionCache = ticket;
                gatewaySessionTime = Date.now();
            }
        });

        const cleanup = () => {
            if (hbInterval) { clearInterval(hbInterval); hbInterval = null; }
            if (prewarmInterval) { clearInterval(prewarmInterval); prewarmInterval = null; }
            if (keepaliveInterval) { clearInterval(keepaliveInterval); keepaliveInterval = null; }

            const delay = Math.min(250 * Math.pow(1.5, reconnectAttempts), 10000);
            reconnectAttempts++;
            setTimeout(connectGateway, delay);
        };

        tlsSock.on('close', cleanup);
        tlsSock.on('error', cleanup);
        tlsSock.on('timeout', () => {
            try { tlsSock.destroy(); } catch (e) {}
            cleanup();
        });
    }

    parentPort.on('message', (msg) => {
        if (msg.type === 'HEARTBEAT_INTERVAL') {
            const interval = msg.interval;
            if (hbInterval) clearInterval(hbInterval);
            hbInterval = setInterval(() => {
                if (activeTlsSocket && activeTlsSocket.writable) {
                    sendWsFrame(activeTlsSocket, PING_BUF, 1);
                }
            }, interval);
        } else if (msg.type === 'KEEPALIVE') {
            parentPort.postMessage({ type: 'KEEPALIVE_RESPONSE', timestamp: msg.timestamp });
        } else if (msg.type === 'TERMINATE') {
            if (hbInterval) clearInterval(hbInterval);
            if (prewarmInterval) clearInterval(prewarmInterval);
            if (keepaliveInterval) clearInterval(keepaliveInterval);
            try { if (activeTlsSocket) activeTlsSocket.destroy(); } catch (e) {}
            process.exit(0);
        }
    });

    connectGateway();
}
