'use strict';

const net    = require('net');
const tls    = require('tls');
const dns    = require('dns');
const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

process.env.UV_THREADPOOL_SIZE = '64';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
Buffer.poolSize = 1000;

const NOOP = () => {};
try { os.setPriority(process.pid, -20); } catch {}
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['1.1.1.1', '1.0.0.1']);
try { net.setDefaultAutoSelectFamily(false); } catch {}

// ═══════════════════════════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════════════════════════
const TOKEN    = '';
const GUILD_ID = '';
const API_HOST = 'canary.discord.com';
const MFA_FILE = path.join(__dirname, 'mfa.txt');

// TLS bağlantı sayısı — her IP'ye ayrı slot
const TLS_COUNT = 8;

// Gateway endpoint'leri — tümüne paralel bağlan
const GW_URLS = [
    'wss://gateway.discord.gg/?v=10&encoding=etf',
    'wss://gateway-us-east1-b.discord.gg/?v=10&encoding=etf',
    'wss://gateway-us-east1-c.discord.gg/?v=10&encoding=etf',
];

// ═══════════════════════════════════════════════════════════
//  COLORS & LOG
// ═══════════════════════════════════════════════════════════
const C = {
    reset: '\x1b[0m', white: '\x1b[37m', bold: '\x1b[1m',
    green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m'
};
function log(msg) { process.stdout.write(`${C.white}${C.bold}${msg}${C.reset}\n`); }

// ═══════════════════════════════════════════════════════════
//  SHARED MEMORY ARENA — 64KB
// ═══════════════════════════════════════════════════════════
const ARENA_SIZE = 1 << 16;
const _arena     = new SharedArrayBuffer(ARENA_SIZE);
const ARENA      = new Uint8Array(_arena);

const SL = Object.freeze({
    FIRE    : 0,   // Int32[4]  — active, won, status, pad
    PRNG    : 16,  // Uint32[4] — xorshift128+ state
    WS_MASK : 32,  // 4B        — mask bytes
    FIRE_CODE: 36, // 32B       — vanity code buffer
    SEQ     : 68,  // Int32[2]  — seq, hasSeq
});

const FSTATE   = new Int32Array(_arena, SL.FIRE, 4);
const PRNG_S   = new Uint32Array(_arena, SL.PRNG, 4);
const SEQSTATE = new Int32Array(_arena, SL.SEQ, 2);
const FS_ACTIVE = 0, FS_WON = 1, FS_STATUS = 2;
const SS_SEQ = 0, SS_HAS = 1;

// PRNG seed
{ const s = new Uint32Array(4); crypto.randomFillSync(new Uint8Array(s.buffer)); PRNG_S[0]=s[0]||1; PRNG_S[1]=s[1]||2; PRNG_S[2]=s[2]||3; PRNG_S[3]=s[3]||4; }

// ═══════════════════════════════════════════════════════════
//  xorshift128+ PRNG — WS masking
// ═══════════════════════════════════════════════════════════
function fastMask4() {
    let s1 = PRNG_S[0], s0 = PRNG_S[1];
    PRNG_S[0] = s0;
    s1 ^= (s1 << 23); s1 ^= (s1 >>> 17); s1 ^= s0; s1 ^= (s0 >>> 26);
    PRNG_S[1] = s1;
    const r = (s0 + s1) | 0;
    ARENA[SL.WS_MASK]     = r & 0xFF;
    ARENA[SL.WS_MASK + 1] = (r >>> 8)  & 0xFF;
    ARENA[SL.WS_MASK + 2] = (r >>> 16) & 0xFF;
    ARENA[SL.WS_MASK + 3] = (r >>> 24) & 0xFF;
}

// ═══════════════════════════════════════════════════════════
//  FIRE CODE BUFFER
// ═══════════════════════════════════════════════════════════
const fireCodeView = Buffer.from(_arena, SL.FIRE_CODE, 32);
function strToFireBuf(str) {
    const len = Math.min(str.length, 32);
    for (let i = 0; i < len; i++) ARENA[SL.FIRE_CODE + i] = str.charCodeAt(i);
    return fireCodeView.subarray(0, len);
}

// ═══════════════════════════════════════════════════════════
//  ETF CODEC
// ═══════════════════════════════════════════════════════════
const ETF_VER = 131;
let _etfOff = 0;

function etfDecode(buf) {
    if (!buf || buf.length < 2 || buf[0] !== ETF_VER) return null;
    _etfOff = 1;
    try { return _etfRead(buf); } catch { return null; }
}

function _etfRead(buf) {
    const tag = buf[_etfOff++];
    switch (tag) {
        case 97:  return buf[_etfOff++];
        case 98:  { const v = buf.readInt32BE(_etfOff); _etfOff += 4; return v; }
        case 70:  { const v = buf.readDoubleBE(_etfOff); _etfOff += 8; return v; }
        case 100: { const l=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; const s=buf.toString('latin1',_etfOff,_etfOff+l); _etfOff+=l; if(s==='nil'||s==='null') return null; if(s==='true') return true; if(s==='false') return false; return s; }
        case 115: { const l=buf[_etfOff++]; const s=buf.toString('latin1',_etfOff,_etfOff+l); _etfOff+=l; if(s==='nil'||s==='null') return null; if(s==='true') return true; if(s==='false') return false; return s; }
        case 118: { const l=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; const s=buf.toString('utf8',_etfOff,_etfOff+l); _etfOff+=l; if(s==='nil'||s==='null') return null; if(s==='true') return true; if(s==='false') return false; return s; }
        case 119: { const l=buf[_etfOff++]; const s=buf.toString('utf8',_etfOff,_etfOff+l); _etfOff+=l; if(s==='nil'||s==='null') return null; if(s==='true') return true; if(s==='false') return false; return s; }
        case 109: { const l=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; const s=buf.toString('utf8',_etfOff,_etfOff+l); _etfOff+=l; return s; }
        case 107: { const l=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; const a=new Array(l); for(let i=0;i<l;i++) a[i]=buf[_etfOff++]; return a; }
        case 106: return [];
        case 108: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; const a=new Array(n); for(let i=0;i<n;i++) a[i]=_etfRead(buf); _etfRead(buf); return a; }
        case 116: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; const o=Object.create(null); for(let i=0;i<n;i++){const k=_etfRead(buf); o[k]=_etfRead(buf);} return o; }
        case 104: { const n=buf[_etfOff++]; const a=new Array(n); for(let i=0;i<n;i++) a[i]=_etfRead(buf); return a; }
        case 105: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; const a=new Array(n); for(let i=0;i<n;i++) a[i]=_etfRead(buf); return a; }
        case 110: { const n=buf[_etfOff++]; const sg=buf[_etfOff++]; let v=0; for(let i=0;i<n;i++) v+=buf[_etfOff+i]*(2**(i*8)); _etfOff+=n; return String(sg?-v:v); }
        case 111: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; const sg=buf[_etfOff++]; let v=0n; for(let i=0;i<n;i++) v|=BigInt(buf[_etfOff+i])<<BigInt(i*8); _etfOff+=n; return (sg?-v:v).toString(); }
        default: return null;
    }
}

function _etfSkip(buf) {
    const tag = buf[_etfOff++];
    switch(tag) {
        case 97: _etfOff++; return;
        case 98: _etfOff+=4; return;
        case 70: _etfOff+=8; return;
        case 100: _etfOff+=2+((buf[_etfOff]<<8)|buf[_etfOff+1]); return;
        case 115: _etfOff+=1+buf[_etfOff]; return;
        case 118: _etfOff+=2+((buf[_etfOff]<<8)|buf[_etfOff+1]); return;
        case 119: _etfOff+=1+buf[_etfOff]; return;
        case 109: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4+n; return; }
        case 107: _etfOff+=2+((buf[_etfOff]<<8)|buf[_etfOff+1]); return;
        case 106: return;
        case 108: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; for(let i=0;i<n;i++) _etfSkip(buf); _etfSkip(buf); return; }
        case 116: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; for(let i=0;i<n*2;i++) _etfSkip(buf); return; }
        case 104: { const n=buf[_etfOff++]; for(let i=0;i<n;i++) _etfSkip(buf); return; }
        case 105: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; for(let i=0;i<n;i++) _etfSkip(buf); return; }
        case 110: _etfOff+=2+buf[_etfOff]; return;
        case 111: { const n=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=5+n; return; }
    }
}

function etfPack(val) {
    const buf = Buffer.allocUnsafe(2048);
    buf[0] = ETF_VER;
    const len = _etfWrite(buf, 1, val);
    return Buffer.from(buf.subarray(0, len));
}

function _etfWrite(buf, off, val) {
    if (val === null || val === undefined) { buf[off++]=119; buf[off++]=3; buf[off++]=110; buf[off++]=105; buf[off++]=108; return off; }
    if (typeof val === 'boolean') { const s=val?'true':'false'; buf[off++]=119; buf[off++]=s.length; off+=buf.write(s,off,'utf8'); return off; }
    if (typeof val === 'number') {
        if (Number.isInteger(val)&&val>=0&&val<=255) { buf[off++]=97; buf[off++]=val; return off; }
        if (Number.isInteger(val)&&val>=-2147483648&&val<=2147483647) { buf[off++]=98; buf.writeInt32BE(val,off); return off+4; }
        buf[off++]=70; buf.writeDoubleBE(val,off); return off+8;
    }
    if (typeof val === 'string') { const sl=Buffer.byteLength(val,'utf8'); buf[off++]=109; buf[off++]=(sl>>24)&0xFF; buf[off++]=(sl>>16)&0xFF; buf[off++]=(sl>>8)&0xFF; buf[off++]=sl&0xFF; off+=buf.write(val,off,'utf8'); return off; }
    if (Array.isArray(val)) { if(!val.length){buf[off++]=106;return off;} buf[off++]=108; buf[off++]=(val.length>>24)&0xFF; buf[off++]=(val.length>>16)&0xFF; buf[off++]=(val.length>>8)&0xFF; buf[off++]=val.length&0xFF; for(let i=0;i<val.length;i++) off=_etfWrite(buf,off,val[i]); buf[off++]=106; return off; }
    if (typeof val === 'object') { const keys=Object.keys(val); buf[off++]=116; buf[off++]=(keys.length>>24)&0xFF; buf[off++]=(keys.length>>16)&0xFF; buf[off++]=(keys.length>>8)&0xFF; buf[off++]=keys.length&0xFF; for(const k of keys){off=_etfWrite(buf,off,k); off=_etfWrite(buf,off,val[k]);} return off; }
    return off;
}

// ═══════════════════════════════════════════════════════════
//  FAST SCANNER — GUILD_UPDATE / GUILD_DELETE
// ═══════════════════════════════════════════════════════════
const _IXOT_GU = Buffer.from([71,85,73,76,68,95,85,80,68,65,84,69]);
const _IXOT_GD = Buffer.from([71,85,73,76,68,95,68,69,76,69,84,69]);

function indexot(buf) {
    if (buf.indexOf(_IXOT_GU) !== -1) return 1;
    if (buf.indexOf(_IXOT_GD) !== -1) return 2;
    return 0;
}

let _scanType = 0, _scanId = null, _scanVanity = undefined, _scanTier = -1;

function fastScanGuildEvent(buf) {
    _scanType=0; _scanId=null; _scanVanity=undefined; _scanTier=-1;
    if (!buf || buf.length < 10 || buf[0] !== ETF_VER) return false;
    _etfOff = 1;
    if (buf[_etfOff++] !== 116) return false;
    const arity = (buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4;
    let dOffset = -1, seq = -1;
    for (let i = 0; i < arity; i++) {
        const kt = buf[_etfOff++]; let kLen, kOff;
        if (kt===109){kLen=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; kOff=_etfOff; _etfOff+=kLen;}
        else if(kt===119||kt===115){kLen=buf[_etfOff++]; kOff=_etfOff; _etfOff+=kLen;}
        else if(kt===118||kt===100){kLen=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; kOff=_etfOff; _etfOff+=kLen;}
        else return false;
        if (kLen===1) {
            const kb=buf[kOff];
            if (kb===116) { // "t"
                const vt=buf[_etfOff++]; let vLen,vOff;
                if(vt===109){vLen=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; vOff=_etfOff; _etfOff+=vLen;}
                else if(vt===119||vt===115){vLen=buf[_etfOff++]; vOff=_etfOff; _etfOff+=vLen;}
                else if(vt===118||vt===100){vLen=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; vOff=_etfOff; _etfOff+=vLen;}
                else{_etfOff--; _etfSkip(buf); continue;}
                if(vLen===12&&buf[vOff]===71&&buf[vOff+1]===85&&buf[vOff+2]===73&&buf[vOff+3]===76&&buf[vOff+4]===68&&buf[vOff+5]===95){
                    if(buf[vOff+6]===85&&buf[vOff+7]===80&&buf[vOff+8]===68&&buf[vOff+9]===65&&buf[vOff+10]===84&&buf[vOff+11]===69) _scanType=1;
                    else if(buf[vOff+6]===68&&buf[vOff+7]===69&&buf[vOff+8]===76&&buf[vOff+9]===69&&buf[vOff+10]===84&&buf[vOff+11]===69) _scanType=2;
                }
            } else if(kb===115) { // "s"
                const st=buf[_etfOff];
                if(st===97){seq=buf[_etfOff+1]; _etfOff+=2;}
                else if(st===98){seq=(buf[_etfOff+1]<<24)|(buf[_etfOff+2]<<16)|(buf[_etfOff+3]<<8)|buf[_etfOff+4]; _etfOff+=5;}
                else _etfSkip(buf);
            } else if(kb===100){dOffset=_etfOff; _etfSkip(buf);}
            else _etfSkip(buf);
        } else _etfSkip(buf);
    }
    if (_scanType===0||dOffset<0) return false;
    if (seq>=0){SEQSTATE[SS_SEQ]=seq; SEQSTATE[SS_HAS]=1;}
    _etfOff=dOffset;
    if (buf[_etfOff++]!==116) return false;
    const dArity=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4;
    let found=0;
    for (let i=0;i<dArity;i++){
        const ft=buf[_etfOff++]; let fkLen,fkOff;
        if(ft===109){fkLen=(buf[_etfOff]<<24)|(buf[_etfOff+1]<<16)|(buf[_etfOff+2]<<8)|buf[_etfOff+3]; _etfOff+=4; fkOff=_etfOff; _etfOff+=fkLen;}
        else if(ft===119||ft===115){fkLen=buf[_etfOff++]; fkOff=_etfOff; _etfOff+=fkLen;}
        else if(ft===118||ft===100){fkLen=(buf[_etfOff]<<8)|buf[_etfOff+1]; _etfOff+=2; fkOff=_etfOff; _etfOff+=fkLen;}
        else{_etfOff--; _etfSkip(buf); _etfSkip(buf); continue;}
        if(fkLen===2&&buf[fkOff]===105&&buf[fkOff+1]===100){ // "id"
            _scanId=_etfRead(buf); if(_scanId!=null) _scanId=String(_scanId); if((found|=1)===7) break;
        } else if(fkLen===15&&buf[fkOff]===118&&buf[fkOff+1]===97&&buf[fkOff+2]===110&&buf[fkOff+3]===105&&buf[fkOff+4]===116&&buf[fkOff+5]===121&&buf[fkOff+6]===95&&buf[fkOff+7]===117&&buf[fkOff+8]===114&&buf[fkOff+9]===108&&buf[fkOff+10]===95&&buf[fkOff+11]===99&&buf[fkOff+12]===111&&buf[fkOff+13]===100&&buf[fkOff+14]===101){ // "vanity_url_code"
            _scanVanity=_etfRead(buf); if((found|=2)===7) break;
        } else if(fkLen===12&&buf[fkOff]===112&&buf[fkOff+1]===114&&buf[fkOff+2]===101&&buf[fkOff+3]===109&&buf[fkOff+4]===105&&buf[fkOff+5]===117&&buf[fkOff+6]===109&&buf[fkOff+7]===95&&buf[fkOff+8]===116&&buf[fkOff+9]===105&&buf[fkOff+10]===101&&buf[fkOff+11]===114){ // "premium_tier"
            const pt=buf[_etfOff]; if(pt===97){_scanTier=buf[_etfOff+1]; _etfOff+=2;} else if(pt===98){_scanTier=(buf[_etfOff+1]<<24)|(buf[_etfOff+2]<<16)|(buf[_etfOff+3]<<8)|buf[_etfOff+4]; _etfOff+=5;} else{const v=_etfRead(buf); if(typeof v==='number') _scanTier=v;}
            if((found|=4)===7) break;
        } else _etfSkip(buf);
    }
    return true;
}

// ═══════════════════════════════════════════════════════════
//  VANITY MAP — guildId → vanityCode (plain Map, hızlı)
// ═══════════════════════════════════════════════════════════
const vanityMap = new Map(); // guildId → vanityCode string

// ═══════════════════════════════════════════════════════════
//  WS FRAME SENDER — masked, binary
// ═══════════════════════════════════════════════════════════
function sendWsFrame(socket, data) {
    const len = data.length;
    fastMask4();
    const m0=ARENA[SL.WS_MASK], m1=ARENA[SL.WS_MASK+1], m2=ARENA[SL.WS_MASK+2], m3=ARENA[SL.WS_MASK+3];
    let hdrOff, frameSize;
    if (len<126){hdrOff=2; frameSize=len+6;}
    else if(len<65536){hdrOff=4; frameSize=len+8;}
    else{hdrOff=10; frameSize=len+14;}
    const frame = Buffer.allocUnsafe(frameSize);
    frame[0] = 0x82;
    if(len<126){frame[1]=0x80|len;}
    else if(len<65536){frame[1]=0x80|126; frame.writeUInt16BE(len,2);}
    else{frame[1]=0x80|127; frame.writeBigUInt64BE(BigInt(len),2);}
    frame[hdrOff]=m0; frame[hdrOff+1]=m1; frame[hdrOff+2]=m2; frame[hdrOff+3]=m3;
    const ps = hdrOff+4;
    let i=0;
    const ul = len>=16 ? len-16 : 0;
    while(i<ul){
        frame[ps+i]=data[i]^m0; frame[ps+i+1]=data[i+1]^m1; frame[ps+i+2]=data[i+2]^m2; frame[ps+i+3]=data[i+3]^m3;
        frame[ps+i+4]=data[i+4]^m0; frame[ps+i+5]=data[i+5]^m1; frame[ps+i+6]=data[i+6]^m2; frame[ps+i+7]=data[i+7]^m3;
        frame[ps+i+8]=data[i+8]^m0; frame[ps+i+9]=data[i+9]^m1; frame[ps+i+10]=data[i+10]^m2; frame[ps+i+11]=data[i+11]^m3;
        frame[ps+i+12]=data[i+12]^m0; frame[ps+i+13]=data[i+13]^m1; frame[ps+i+14]=data[i+14]^m2; frame[ps+i+15]=data[i+15]^m3;
        i+=16;
    }
    while(i<len){ const mi=i&3; frame[ps+i]=data[i]^(mi===0?m0:mi===1?m1:mi===2?m2:m3); i++; }
    socket.write(frame);
}

// ═══════════════════════════════════════════════════════════
//  RAW WS — zero-dep, sliding window parser (16MB pool)
// ═══════════════════════════════════════════════════════════
class ParserState {
    constructor() {
        this.stage=0; this.opcode=0; this.isMasked=0; this.maskOffset=0;
        this.payloadLen=0; this.extendedLenBytes=0; this.extendedLenRead=0;
        this.payloadOffset=0; this.fragmentedOpcode=0;
        this.maskKey=Buffer.allocUnsafe(4);
        this.extendedLenBuf=Buffer.allocUnsafe(8);
    }
}

class RawWS {
    constructor(url, ip) {
        this._url = new URL(url);
        this._ip  = ip || null;
        this._socket = null; this._raw = null;
        this.readyState = 0;
        this._onmsg = null; this._onopen = null; this._onclose = null; this._onerr = null;
        this._connect();
    }
    on(ev, fn) {
        if(ev==='message') this._onmsg=fn;
        if(ev==='open')    this._onopen=fn;
        if(ev==='close')   this._onclose=fn;
        if(ev==='error')   this._onerr=fn;
        return this;
    }
    send(data) {
        if(this.readyState!==1||!this._socket||this._socket.destroyed) return;
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        sendWsFrame(this._socket, buf);
    }
    close() { try{this._socket?.destroy();}catch{} try{this._raw?.destroy();}catch{} this.readyState=3; }
    _connect() {
        const host = this._url.hostname;
        const port = +(this._url.port || 443);
        const reqPath = this._url.pathname + this._url.search;
        const raw = net.connect({ host: this._ip||host, port, noDelay: true, highWaterMark: 0 });
        raw.setKeepAlive(true, 0);
        this._raw = raw;
        const sock = tls.connect({
            socket: raw, servername: host, rejectUnauthorized: false,
            ALPNProtocols: ['http/1.1'],
            minVersion: 'TLSv1.2',
            ecdhCurve: 'X25519:P-256:P-384'
        });
        sock.setNoDelay(true); sock.setKeepAlive(true, 0);
        this._socket = sock;
        const key = crypto.randomBytes(16).toString('base64');
        const hs  = `GET ${reqPath} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`;
        sock.on('secureConnect', () => sock.write(hs));
        let hsBuf = Buffer.alloc(0);
        const onHsData = (chunk) => {
            hsBuf = Buffer.concat([hsBuf, chunk]);
            const end = hsBuf.indexOf('\r\n\r\n');
            if (end === -1) return;
            const remaining = hsBuf.subarray(end+4);
            if (hsBuf.indexOf('101') !== -1) {
                sock.removeListener('data', onHsData);
                this.readyState = 1;
                this._setupParser(sock);
                if (this._onopen) this._onopen();
                if (remaining.length > 0) sock.emit('data', remaining);
            } else if (hsBuf.length > 2048) sock.destroy();
        };
        sock.on('data', onHsData);
        sock.on('error', e => { if(this._onerr) this._onerr(e); });
        sock.on('close', () => { this.readyState=3; if(this._onclose) this._onclose(1006); });
        raw.on('error', NOOP);
    }
    _setupParser(socket) {
        const self = this;
        const state = new ParserState();
        const fragmentPool = Buffer.allocUnsafe(16*1024*1024);
        const payloadPool  = Buffer.allocUnsafe(16*1024*1024);
        let fragmentedTotal=0, fragmentedOpcode=0, fragmentedIsMasked=0, fragmentedMaskKey=null, isFragmented=false, isFin=false;
        const lmk = state.maskKey, leb = state.extendedLenBuf;
        socket.on('data', (chunk) => {
            let cl=chunk.length, co=0;
            let ss=state.stage, so=state.opcode, sim=state.isMasked, smo=state.maskOffset;
            let spl=state.payloadLen, selb=state.extendedLenBytes, selr=state.extendedLenRead, spo=state.payloadOffset, sfo=state.fragmentedOpcode;
            while(co<cl){
                if(ss===0){const b=chunk[co]; isFin=(b&0x80)===0x80; so=(b&0x0F); so=(so===0&&sfo!==0)?sfo:so; sfo=(!isFin&&so>0&&so<8)?so:sfo; co++; ss=1; if(co>=cl) break;}
                if(ss===1){const b=chunk[co]; co++; sim=((b&0x80)===0x80)?1:0; const bl=b&0x7F; if(bl===126){ss=2;selb=2;selr=0;}else if(bl===127){ss=2;selb=8;selr=0;}else{spl=bl;ss=sim===1?3:4;smo=0;spo=0;} if(co>=cl) break;}
                if(ss===2){const needed=selb-selr, avail=cl-co, tr=avail<needed?avail:needed; chunk.copy(leb,selr,co,co+tr); selr+=tr; co+=tr; if(selr===selb){spl=selb===2?leb.readUInt16BE(0):Number(leb.readBigUInt64BE(0)); ss=sim===1?3:4;smo=0;spo=0;} if(co>=cl) break;}
                if(ss===3){const needed=4-smo, avail=cl-co, tr=avail<needed?avail:needed; chunk.copy(lmk,smo,co,co+tr); smo+=tr; co+=tr; if(smo===4){ss=4;spo=0;} if(co>=cl) break;}
                if(ss===4){
                    if(spl===0){if(so===8){self.readyState=3;if(self._onclose)self._onclose(1000);return;}if(so===9)self._sendRaw(0x8A,null);ss=0;continue;}
                    const needed=spl-spo, avail=cl-co, tr=avail<needed?avail:needed;
                    const isFirst=(!isFragmented&&!isFin&&so!==0);
                    const isCont=isFragmented;
                    if(isFirst){fragmentedOpcode=so;fragmentedTotal=0;isFragmented=true;fragmentedIsMasked=sim;if(sim===1){fragmentedMaskKey=Buffer.allocUnsafe(4);lmk.copy(fragmentedMaskKey,0,0,4);}}
                    if(isFirst||isCont){chunk.copy(fragmentPool,fragmentedTotal,co,co+tr);fragmentedTotal+=tr;}
                    else{chunk.copy(payloadPool,spo,co,co+tr);}
                    spo+=tr; co+=tr;
                    if(spo===spl){
                        let fp=null, fl=0, wasFragmented=false;
                        if(isFin&&isFragmented){wasFragmented=true;fp=fragmentPool;fl=fragmentedTotal;isFragmented=false;fragmentedTotal=0;}
                        else if(isFin&&!isFragmented){fp=payloadPool;fl=spl;}
                        if(fp!==null&&fl>0){
                            const shouldUnmask=wasFragmented?(fragmentedIsMasked===1):(sim===1);
                            if(shouldUnmask){
                                const ms=wasFragmented?fragmentedMaskKey:lmk;
                                const u0=ms[0],u1=ms[1],u2=ms[2],u3=ms[3];
                                let ui=0; const ul2=fl>=16?fl-15:0;
                                while(ui<ul2){fp[ui]^=u0;fp[ui+1]^=u1;fp[ui+2]^=u2;fp[ui+3]^=u3;fp[ui+4]^=u0;fp[ui+5]^=u1;fp[ui+6]^=u2;fp[ui+7]^=u3;fp[ui+8]^=u0;fp[ui+9]^=u1;fp[ui+10]^=u2;fp[ui+11]^=u3;fp[ui+12]^=u0;fp[ui+13]^=u1;fp[ui+14]^=u2;fp[ui+15]^=u3;ui+=16;}
                                while(ui<fl){fp[ui]^=ms[ui&3];ui++;}
                            }
                        }
                        if(so===8){let cc=1000;if(fp&&fl>=2)cc=(fp[0]<<8)|fp[1];self.readyState=3;if(self._onclose)self._onclose(cc);return;}
                        if(so===9){self._sendRaw(0x8A,fp?fp.subarray(0,fl):null);}
                        if((so===1||so===2)&&fp&&fl>0){if(self._onmsg)self._onmsg(fp.subarray(0,fl));}
                        if(wasFragmented) fragmentedMaskKey=null;
                        ss=0;
                    }
                }
            }
            state.stage=ss; state.opcode=so; state.isMasked=sim; state.maskOffset=smo;
            state.payloadLen=spl; state.extendedLenBytes=selb; state.extendedLenRead=selr;
            state.payloadOffset=spo; state.fragmentedOpcode=sfo;
        });
    }
    _sendRaw(firstByte, payload) {
        if(!this._socket||this._socket.destroyed) return;
        const len=payload?payload.length:0;
        if(len===0){const f=Buffer.allocUnsafe(2);f[0]=firstByte;f[1]=0;this._socket.write(f);return;}
        const f=len<126?Buffer.allocUnsafe(2+len):Buffer.allocUnsafe(4+len);
        f[0]=firstByte; if(len<126){f[1]=len;payload.copy(f,2);}else{f[1]=126;f[2]=(len>>8)&0xFF;f[3]=len&0xFF;payload.copy(f,4);}
        this._socket.write(f);
    }
}

// ═══════════════════════════════════════════════════════════
//  DNS RANKING
// ═══════════════════════════════════════════════════════════
let rankedIPs = [];

function measureRTT(ip) {
    return new Promise(resolve => {
        const start = process.hrtime.bigint();
        const s = net.connect({ host: ip, port: 443, noDelay: true }, () => {
            const rtt = Number(process.hrtime.bigint() - start) / 1_000_000;
            try { s.destroy(); } catch {}
            resolve({ ip, rtt });
        });
        s.on('error', () => { try{s.destroy();}catch{} resolve({ ip, rtt: Infinity }); });
        setTimeout(() => { try{s.destroy();}catch{} resolve({ ip, rtt: Infinity }); }, 1500);
    });
}

async function rankIPs() {
    return new Promise(resolve => {
        dns.resolve4(API_HOST, async (err, addrs) => {
            if (err || !addrs?.length) { resolve([]); return; }
            const allRes = new Map();
            for (let round = 0; round < 4; round++) {
                const results = await Promise.all(addrs.map(measureRTT));
                for (const r of results) {
                    const prev = allRes.get(r.ip);
                    if (!prev || r.rtt < prev.rtt) allRes.set(r.ip, r);
                }
            }
            const sorted = [...allRes.values()].sort((a,b)=>a.rtt-b.rtt);
            rankedIPs = sorted.filter(r=>r.rtt<Infinity).map(r=>r.ip);
            log(API_HOST + ':');
            sorted.forEach((r,i) => log('  ' + (i+1) + '. ' + r.ip + ': ' + r.rtt.toFixed(1) + 'ms'));
            resolve(rankedIPs);
        });
    });
}

// ═══════════════════════════════════════════════════════════
//  TLS POOL — 8 connections, zero-GC request build
// ═══════════════════════════════════════════════════════════
const _tlsSessCache = Object.create(null);
const _conns = new Array(TLS_COUNT).fill(null);
let _rrIdx = 0;

function getIP() {
    if (!rankedIPs.length) return API_HOST;
    const ip = rankedIPs[_rrIdx % rankedIPs.length];
    _rrIdx = (_rrIdx + 1) % rankedIPs.length;
    return ip;
}

// Pre-built request template
const _reqBuf     = Buffer.allocUnsafe(4096);
const _fireBuf    = Buffer.allocUnsafe(4096);
let   _templateLen = 0;
let   _fireSlice   = null;
let   _mfaToken    = '';

const BD1 = Buffer.from('{"code":"');
const BD2 = Buffer.from('"}');
const SUFFIX_CACHE = new Array(33);
for (let i=0;i<=32;i++) SUFFIX_CACHE[i]=Buffer.from(`Content-Length: ${BD1.length+BD2.length+i}\r\n\r\n{"code":"`);

function rebuildTemplate() {
    let hdr =
        `PATCH /api/v9/guilds/${GUILD_ID}/vanity-url HTTP/1.1\r\n` +
        `Host: ${API_HOST}\r\n` +
        `Authorization: ${TOKEN}\r\n` +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36\r\n` +
        `X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDUiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJoYXNfY2xpZW50X21vZHMiOmZhbHNlLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNTU2MjQsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9\r\n` +
        `X-Discord-Timezone: Europe/Istanbul\r\n` +
        `X-Discord-Locale: tr\r\n` +
        `Origin: https://canary.discord.com\r\n` +
        `Referer: https://canary.discord.com/channels/@me\r\n` +
        `Content-Type: application/json\r\n` +
        `Connection: keep-alive\r\n`;
    if (_mfaToken) {
        hdr += `X-Discord-MFA-Authorization: ${_mfaToken}\r\n`;
        hdr += `Cookie: __Secure-recent_mfa=${_mfaToken}\r\n`;
    }
    _templateLen = _reqBuf.write(hdr, 0, 'utf8');
}

function buildFireReq(codeBuf) {
    const suffix = SUFFIX_CACHE[codeBuf.length];
    let off = _templateLen;
    suffix.copy(_reqBuf, off); off += suffix.length;
    codeBuf.copy(_reqBuf, off); off += codeBuf.length;
    BD2.copy(_reqBuf, off); off += BD2.length;
    _reqBuf.copy(_fireBuf, 0, 0, off);
    _fireSlice = _fireBuf.subarray(0, off);
}

function createTlsConn(ip, slot) {
    const raw = net.connect({ host: ip, port: 443, noDelay: true, highWaterMark: 0 });
    raw.setKeepAlive(true, 10000);
    const conn = tls.connect({
        socket: raw, servername: API_HOST,
        ALPNProtocols: ['http/1.1'], rejectUnauthorized: false,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256',
        ecdhCurve: 'X25519:P-256:P-384',
        session: _tlsSessCache[ip] || null,
        checkServerIdentity: NOOP, highWaterMark: 0
    });
    conn.setNoDelay(true); conn.setKeepAlive(true, 10000);
    conn._ip = ip; conn._slot = slot; conn._warm = true;
    conn.on('session', s => { _tlsSessCache[ip] = s; });
    const kaReq = Buffer.from(`GET /api/v9/gateway HTTP/1.1\r\nHost: ${API_HOST}\r\nAuthorization: ${TOKEN}\r\nConnection: keep-alive\r\n\r\n`);
    conn.on('secureConnect', () => { _conns[slot] = conn; conn.write(kaReq); });
    conn.on('data', chunk => {
        if (conn._warm) { conn._warm = false; return; }
        // fire response
        if (!FSTATE[FS_ACTIVE] || FSTATE[FS_WON]) return;
        if (chunk.length >= 12 && chunk[0] === 72 && chunk[4] === 47) {
            const status = (chunk[9]-48)*100 + (chunk[10]-48)*10 + (chunk[11]-48);
            if (!FSTATE[FS_STATUS]) FSTATE[FS_STATUS] = status;
            if (status === 200) onFireWin();
        }
    });
    const cleanup = () => {
        _conns[slot] = null;
        try{raw.destroy();}catch{} try{conn.destroy();}catch{}
        queueMicrotask(() => createTlsConn(ip, slot));
    };
    conn.on('error', cleanup); conn.on('end', cleanup); raw.on('error', cleanup);
}

// keep-alive ping her 12s
const _kaReqBuf = Buffer.from(`GET /api/v9/gateway HTTP/1.1\r\nHost: ${API_HOST}\r\nAuthorization: ${TOKEN}\r\nConnection: keep-alive\r\n\r\n`);
setInterval(() => {
    for (let i=0;i<TLS_COUNT;i++){
        const c=_conns[i];
        if(c&&c.writable&&!c.destroyed&&!c._warm){ c._warm=true; c.write(_kaReqBuf); }
    }
}, 12000);

// ═══════════════════════════════════════════════════════════
//  FIRE ENGINE
// ═══════════════════════════════════════════════════════════
let fireT0 = 0, fireCode = null, fireTimeout = null;

function onFireWin() {
    FSTATE[FS_WON] = 1;
    const code = fireCode ? fireCode.toString('utf8') : '?';
    const ms   = (performance.now() - fireT0).toFixed(2);
    const st   = FSTATE[FS_STATUS] || '???';
    log(`"Status": "${st}", "Vanity": "${code}" | ${ms}ms`);
}

function fire(codeBuf) {
    if (FSTATE[FS_ACTIVE]) return;
    FSTATE[FS_ACTIVE] = 1; FSTATE[FS_WON] = 0; FSTATE[FS_STATUS] = 0;
    fireT0   = performance.now();
    fireCode = codeBuf;
    buildFireReq(codeBuf);

    // Wave 1 — tüm TLS bağlantıları aynı anda
    _sendWave();

    // Wave 2 — T+40ms
    const saved = _fireSlice;
    setTimeout(() => { if(!FSTATE[FS_WON]){ _fireSlice=saved; _sendWave(); } }, 40);

    // Wave 3 — T+80ms
    setTimeout(() => { if(!FSTATE[FS_WON]){ _fireSlice=saved; _sendWave(); } }, 80);

    if (fireTimeout) clearTimeout(fireTimeout);
    fireTimeout = setTimeout(() => {
        if (!FSTATE[FS_WON]) {
            const code = fireCode ? fireCode.toString('utf8') : '?';
            log(`miss: discord.gg/${code}`);
        }
        FSTATE[FS_ACTIVE] = 0;
    }, 3000);
}

function _sendWave() {
    const req = _fireSlice;
    if (!req) return;
    for (let i=0;i<TLS_COUNT;i++){
        const c=_conns[i];
        if(c&&c.writable&&!c.destroyed){ c._warm=false; c.write(req); }
    }
}

// ═══════════════════════════════════════════════════════════
//  MFA FILE WATCHER
// ═══════════════════════════════════════════════════════════
function loadMfa() {
    try {
        const t = fs.readFileSync(MFA_FILE, 'utf8').trim();
        if (t && t !== _mfaToken) {
            _mfaToken = t;
            rebuildTemplate();
            log('mfa loaded');
        }
    } catch {}
}

fs.watchFile(MFA_FILE, { interval: 1000 }, () => {
    loadMfa();
});

// ═══════════════════════════════════════════════════════════
//  GATEWAY — ETF, 3 parallel connections
// ═══════════════════════════════════════════════════════════
const IDENTIFY_BUF = etfPack({
    op: 2, d: {
        token: TOKEN, intents: 1,
        properties: { os: 'Windows', browser: 'Chrome', device: '' },
        large_threshold: 1
    }
});

// heartbeat template
const HB_HDR = Buffer.from([131,116,0,0,0,2,109,0,0,0,2,111,112,97,1,109,0,0,0,1,100]);
const HB_BUF = Buffer.allocUnsafe(64);

function sendHeartbeat(ws) {
    if (ws.readyState !== 1) return;
    HB_HDR.copy(HB_BUF, 0);
    let off = HB_HDR.length;
    if (!SEQSTATE[SS_HAS]) {
        HB_BUF[off++]=119; HB_BUF[off++]=3; HB_BUF[off++]=110; HB_BUF[off++]=105; HB_BUF[off++]=108;
    } else {
        const seq = SEQSTATE[SS_SEQ];
        if (seq>=0&&seq<=255){HB_BUF[off++]=97;HB_BUF[off++]=seq;}
        else{HB_BUF[off++]=98;HB_BUF[off++]=(seq>>24)&0xFF;HB_BUF[off++]=(seq>>16)&0xFF;HB_BUF[off++]=(seq>>8)&0xFF;HB_BUF[off++]=seq&0xFF;}
    }
    ws.send(HB_BUF.subarray(0, off));
}

function handleMsg(buf) {
    if (!buf || buf.length < 6 || buf[0] !== 131) return;

    // fast path — GUILD_UPDATE / GUILD_DELETE
    const ixType = indexot(buf);
    if (ixType) {
        if (fastScanGuildEvent(buf)) {
            if (_scanType === 1) { handleGuildUpdate(); return; }
            if (_scanType === 2) { handleGuildDelete(); return; }
        }
    }

    // slow path
    const msg = etfDecode(buf);
    if (!msg) return;
    const { t, s, op, d } = msg;
    if (typeof s === 'number' && s >= 0) { SEQSTATE[SS_SEQ]=s; SEQSTATE[SS_HAS]=1; }

    if (op === 10 && d) return; // HELLO — heartbeat her GW instance'ında ayrı handle ediliyor

    if (t === 'GUILD_UPDATE' && d) {
        const id = String(d.id || '');
        if (!id) return;
        const oldVanity = vanityMap.get(id);
        const newVanity = d.vanity_url_code || null;
        if (oldVanity && oldVanity !== newVanity) {
            vanityMap.set(id, newVanity || '');
            const cb = strToFireBuf(oldVanity);
            log('vanity free: discord.gg/' + oldVanity);
            process.nextTick(() => fire(cb));
        } else if (!oldVanity && newVanity) {
            vanityMap.set(id, newVanity);
        }
        return;
    }

    if (t === 'GUILD_DELETE' && d) {
        const id = String(d.id || '');
        const v  = vanityMap.get(id);
        if (v) { vanityMap.delete(id); const cb=strToFireBuf(v); log('guild delete: discord.gg/'+v); process.nextTick(()=>fire(cb)); }
        return;
    }

    if (t === 'GUILD_CREATE' && d) {
        const id = String(d.id || '');
        if (id && d.vanity_url_code) vanityMap.set(id, String(d.vanity_url_code));
        return;
    }

    if (t === 'READY' && d) {
        vanityMap.clear();
        let cnt = 0;
        for (const g of (d.guilds || [])) {
            if (g.vanity_url_code) { vanityMap.set(String(g.id), String(g.vanity_url_code)); cnt++; log(g.vanity_url_code); }
        }
        log(''); log('ready — ' + cnt + ' vanity'); log('');
        return;
    }

    if (t === 'RESUMED') { log('gateway resumed'); return; }
}

function handleGuildUpdate() {
    const id = _scanId; if (!id) return;
    const oldVanity = vanityMap.get(id);
    const newVanity = typeof _scanVanity === 'string' ? _scanVanity : null;
    if (oldVanity && oldVanity !== newVanity) {
        vanityMap.set(id, newVanity || '');
        const cb = strToFireBuf(oldVanity);
        log('vanity free: discord.gg/' + oldVanity);
        process.nextTick(() => fire(cb));
    } else if (!oldVanity && newVanity) {
        vanityMap.set(id, newVanity);
    }
}

function handleGuildDelete() {
    const id = _scanId; if (!id) return;
    const v = vanityMap.get(id);
    if (v) { vanityMap.delete(id); const cb=strToFireBuf(v); log('guild delete: discord.gg/'+v); process.nextTick(()=>fire(cb)); }
}

// GW instance per URL
let gwRankedIPs = [];

async function rankGatewayIPs() {
    return new Promise(resolve => {
        dns.resolve4('gateway.discord.gg', async (err, addrs) => {
            if (err || !addrs?.length) { resolve([]); return; }
            const allRes = new Map();
            for (let r = 0; r < 3; r++) {
                const results = await Promise.all(addrs.map(measureRTT));
                for (const x of results) { const p=allRes.get(x.ip); if(!p||x.rtt<p.rtt) allRes.set(x.ip,x); }
            }
            gwRankedIPs = [...allRes.values()].sort((a,b)=>a.rtt-b.rtt).filter(r=>r.rtt<Infinity).map(r=>r.ip);
            if (gwRankedIPs.length) log('gw best: ' + gwRankedIPs[0]);
            resolve(gwRankedIPs);
        });
    });
}

function connectGateway(urlStr, label) {
    const gwIP = gwRankedIPs[0] || null;
    const ws = new RawWS(urlStr, gwIP);
    let hbTimer = null;

    ws.on('open', () => {
        ws.send(IDENTIFY_BUF);
        if (label !== 'GW1') log(label + ' connected');
    });

    ws.on('message', (buf) => {
        // sequence update için ortak handleMsg
        handleMsg(buf);

        // HELLO — bu instance'a özel heartbeat
        if (buf.length < 100 && buf[0] === 131) {
            const msg = etfDecode(buf);
            if (msg && msg.op === 10 && msg.d) {
                const hbi = msg.d.heartbeat_interval || 41250;
                if (hbTimer) clearInterval(hbTimer);
                const jitter = (Math.random() * 100 | 0) - 50;
                hbTimer = setInterval(() => sendHeartbeat(ws), ((hbi * 0.9) | 0) + jitter);
            }
        }
    });

    ws.on('close', code => {
        if (hbTimer) { clearInterval(hbTimer); hbTimer = null; }
        if (code === 4004) { log(label + ' INVALID TOKEN'); return; }
        setTimeout(() => connectGateway(urlStr, label), 150);
    });

    ws.on('error', NOOP);
    return ws;
}

// ═══════════════════════════════════════════════════════════
//  JIT WARMUP
// ═══════════════════════════════════════════════════════════
setTimeout(() => {
    const fake = etfPack({ op:0, t:'GUILD_UPDATE', s:1, d:{ id:'123456789012345678', vanity_url_code:'test', premium_tier:3 } });
    for (let i=0;i<3000;i++) { etfDecode(fake); fastScanGuildEvent(fake); indexot(fake); }
    const fc = strToFireBuf('warmup');
    for (let i=0;i<3000;i++) buildFireReq(fc);
    _fireSlice = null;
    for (let i=0;i<3000;i++) fastMask4();
    const fb = Buffer.from('HTTP/1.1 404 Not Found');
    FSTATE[FS_ACTIVE]=1;
    for (let i=0;i<3000;i++){
        if(fb.length>=12&&fb[0]===72&&fb[4]===47){const s=(fb[9]-48)*100+(fb[10]-48)*10+(fb[11]-48);if(s===200)onFireWin();}
    }
    FSTATE[FS_ACTIVE]=0;
    if (global.gc) global.gc();
    log('Jıt Done.');
}, 100);

// ═══════════════════════════════════════════════════════════
//  DNS RE-RANK her 30s
// ═══════════════════════════════════════════════════════════
setInterval(async () => { await rankIPs(); await rankGatewayIPs(); }, 30000);

// ═══════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════
process.on('warning', NOOP);
process.on('uncaughtException', NOOP);
process.on('unhandledRejection', NOOP);

console.log('');
log('starting...');
console.log('');

async function start() {
    // MFA yükle
    loadMfa();

    // Template oluştur
    rebuildTemplate();

    // DNS ranking
    await rankIPs();
    await rankGatewayIPs();

    // TLS pool — en iyi IP'lere dağıt
    for (let i = 0; i < TLS_COUNT; i++) {
        const ip = rankedIPs[i % (rankedIPs.length || 1)] || API_HOST;
        createTlsConn(ip, i);
    }

    // Pre-warm — 5s boyunca bağlantıları ısıt
    let warmCount = 0;
    const warmInterval = setInterval(() => {
        for (let i=0;i<TLS_COUNT;i++){
            const c=_conns[i]; if(c&&c.writable&&!c.destroyed){c._warm=true;c.write(_kaReqBuf);}
        }
        if (++warmCount >= 10) {
            clearInterval(warmInterval);
            log('done' + TLS_COUNT + ' tls');
        }
    }, 500);

    // 3 gateway bağlantısı
    GW_URLS.forEach((url, i) => {
        setTimeout(() => connectGateway(url, 'GW' + (i+1)), i * 200);
    });
}

start();
