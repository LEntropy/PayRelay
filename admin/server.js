'use strict';
// PayRelay admin console: transaction monitoring, security events, bans, reconciliation
// against the VAN settlement file, and a test terminal. Node.js standard library + mysql2.
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const mysql = require('mysql2/promise');
const tg = require('./lib/telegram');

const env = (k, d) => process.env[k] || d;
const PORT = Number(env('PORT', 8090));
const GATEWAY = env('GATEWAY_HOST', 'gateway');
const CONTROL_TOKEN = env('CONTROL_TOKEN', '');
const ADMIN_PASSWORD = env('ADMIN_PASSWORD', '');
const ATTACKER_URL = env('ATTACKER_URL', 'http://attacker:7000');
const SETTLE_DIR = env('SETTLE_DIR', '/data/settle');
// The address this console's test terminal connects from, so the UI can point out when the
// console itself has been banned (e.g. after sending forged telegrams on purpose).
const CONSOLE_IP = Object.values(require('os').networkInterfaces()).flat()
  .find((i) => i && i.family === 'IPv4' && !i.internal)?.address || '';

const pool = mysql.createPool({
  host: env('DB_HOST', 'mysql'), user: env('DB_USER', 'admin_ro'), password: env('DB_PASSWORD', ''),
  database: 'payrelay', connectionLimit: 5, dateStrings: true, timezone: '+09:00',
});

// Demo merchant keys for the test terminal (a real admin console would never hold these).
const MERCHANT_KEYS = {
  M000000001: Buffer.from('6d65726368616e742d312d64656d6f2d6b65792d303030303030303030303030', 'hex'),
  M000000002: Buffer.from('6d65726368616e742d322d64656d6f2d6b65792d303030303030303030303030', 'hex'),
  M000000009: Buffer.from('6d65726368616e742d392d6c6f61642d6b65792d303030303030303030303030', 'hex'),
  M000000003: Buffer.from('6d65726368616e742d332d64656d6f2d6b65792d303030303030303030303030', 'hex'),
};

// ---- sessions, CSRF, login throttling ---------------------------------------------------

const sessions = new Map();   // sid -> { csrf, expires }
const SESSION_MS = 30 * 60 * 1000;
let loginFailures = 0;
let loginLockedUntil = 0;

function cookie(req, name) {
  const m = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? m[1] : null;
}

function session(req) {
  const sid = cookie(req, 'pr_sid');
  const s = sid && sessions.get(sid);
  if (!s || s.expires < Date.now()) { if (sid) sessions.delete(sid); return null; }
  s.expires = Date.now() + SESSION_MS;
  return s;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---- helpers ----------------------------------------------------------------------------

function send(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 16384) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error('bad json')); } });
  });
}

// Talks to the gateway's internal control port (line protocol, one JSON line per answer).
function control(command) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: GATEWAY, port: 9190 });
    let buf = '';
    const lines = [];
    sock.setTimeout(3000, () => { sock.destroy(); resolve({ error: 'control timeout' }); });
    sock.on('connect', () => sock.write(`AUTH ${CONTROL_TOKEN}\n${command}\n`));
    sock.on('data', (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); }
      if (lines.length >= 2) {
        sock.end();
        try { resolve(JSON.parse(lines[1])); } catch { resolve({ error: 'bad control answer' }); }
      }
    });
    sock.on('error', (e) => resolve({ error: `control: ${e.code}` }));
  });
}

const today = () => new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);

// ---- API --------------------------------------------------------------------------------

async function summary() {
  const [rows] = await pool.query(
    `SELECT status, COUNT(*) AS n, COALESCE(SUM(amount),0) AS amount
       FROM transactions WHERE requested_at >= CURDATE() GROUP BY status`);
  const [perMin] = await pool.query(
    `SELECT DATE_FORMAT(requested_at, '%H:%i') AS t, COUNT(*) AS n, SUM(status='APPROVED') AS ok
       FROM transactions WHERE requested_at >= NOW() - INTERVAL 15 MINUTE GROUP BY t ORDER BY t`);
  const [sec] = await pool.query(
    `SELECT event, COUNT(*) AS n FROM security_events WHERE created_at >= NOW() - INTERVAL 1 HOUR GROUP BY event`);
  const [merchants] = await pool.query(
    `SELECT m.merchant_id, m.name, m.status, m.tps_limit,
            COALESCE(d.tx_count,0) AS tx_count, COALESCE(d.approved_count,0) AS approved_count,
            COALESCE(d.net_amount,0) AS net_amount
       FROM merchants m LEFT JOIN v_daily_merchant d ON d.merchant_id = m.merchant_id AND d.biz_date = CURDATE()
      ORDER BY m.merchant_id`);
  const [stats, bans] = await Promise.all([control('STATS'), control('BANS')]);
  return { date: today(), byStatus: rows, perMinute: perMin, security: sec, merchants, gateway: stats, bans, consoleIp: CONSOLE_IP };
}

async function transactions(q) {
  const where = [];
  const args = [];
  if (q.status) { where.push('status = ?'); args.push(q.status); }
  if (q.q) { where.push('(order_no LIKE ? OR pg_tx_id LIKE ?)'); args.push(`${q.q}%`, `${q.q}%`); }
  const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 500);
  const [rows] = await pool.query(
    `SELECT pg_tx_id, merchant_id, order_no, amount, CONCAT(card_bin, '******', card_last4) AS card,
            status, resp_code, approval_no, cancel_approval, van_latency_ms, client_ip,
            requested_at, responded_at, canceled_at
       FROM transactions ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY id DESC LIMIT ${limit}`, args);
  return rows.map((r) => ({ ...r, resp_text: tg.RESPONSE_TEXT[r.resp_code] || '' }));
}

async function txEvents(id) {
  const [rows] = await pool.query('SELECT event, detail, created_at FROM tx_events WHERE pg_tx_id = ? ORDER BY id', [id]);
  return rows;
}

async function security(limit) {
  const [rows] = await pool.query(
    `SELECT client_ip, event, merchant_id, detail, created_at FROM security_events ORDER BY id DESC LIMIT ?`,
    [Math.min(Number(limit) || 100, 500)]);
  return rows;
}

// Reconciliation (대사): what the VAN booked (settlement file) vs what the PG believes.
async function reconcile(date) {
  if (!/^\d{8}$/.test(date)) throw new Error('date must be YYYYMMDD');
  const file = path.join(SETTLE_DIR, `VAN_${date}.txt`);
  const van = new Map();   // pg_tx_id -> { net, lines }
  let lines = 0;
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'ascii').split('\n')) {
      const [type, id, amount] = line.split('|');
      if (!id) continue;
      lines++;
      const e = van.get(id) || { net: 0, events: [] };
      const a = Number(amount);
      e.net += type === 'A' ? a : -a;
      e.events.push(type);
      van.set(id, e);
    }
  }
  const iso = `${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6)}`;
  const [pg] = await pool.query(
    'SELECT pg_tx_id, merchant_id, order_no, amount, status, net_amount FROM v_settlement WHERE biz_date = ?', [iso]);
  const pgMap = new Map(pg.map((r) => [r.pg_tx_id, r]));
  const mismatches = [];
  let vanTotal = 0;
  let pgTotal = 0;
  for (const r of pg) pgTotal += Number(r.net_amount);
  for (const [id, e] of van) {
    vanTotal += e.net;
    const p = pgMap.get(id);
    const pgNet = p ? Number(p.net_amount) : 0;
    if (pgNet !== e.net) {
      mismatches.push({
        pg_tx_id: id, order_no: p?.order_no || '-', merchant_id: p?.merchant_id || '-', pg_status: p?.status || '기록 없음',
        pg_net: pgNet, van_net: e.net, van_events: e.events.join(','),
        action: p?.status === 'REVERSAL_FAILED'
          ? 'VAN에는 승인으로 남아 있음: 망취소 재시도 또는 취소 처리 필요'
          : 'PG와 VAN 기록 불일치: 원인 조사 필요',
      });
    }
  }
  for (const r of pg) {
    if (Number(r.net_amount) !== 0 && !van.has(r.pg_tx_id)) {
      mismatches.push({ pg_tx_id: r.pg_tx_id, order_no: r.order_no, merchant_id: r.merchant_id, pg_status: r.status,
        pg_net: Number(r.net_amount), van_net: 0, van_events: '-', action: 'PG에만 승인 기록: VAN 매입 누락 확인 필요' });
    }
  }
  return { date, file: path.basename(file), file_exists: fs.existsSync(file), van_lines: lines,
    pg_rows: pg.length, van_total: vanTotal, pg_total: pgTotal, matched: mismatches.length === 0, mismatches };
}

async function posSend(b) {
  const key = MERCHANT_KEYS[b.merchant_id];
  if (!key) throw new Error('unknown merchant');
  const type = b.msg_type;
  if (!['0200', '0400', '0800'].includes(type)) throw new Error('msg_type must be 0200, 0400 or 0800');
  const msg = {
    msg_type: type, merchant_id: b.merchant_id, terminal_id: 'WEBPOS01',
    trace_no: String(Math.floor(Math.random() * 1e6)).padStart(6, '0'), tx_datetime: tg.now14(),
    order_no: b.order_no, card_no: b.card_no, expiry: b.expiry, amount: Number(b.amount) || 0,
    installment: b.installment || '00', currency: 'KRW', pg_tx_id: b.pg_tx_id, reason: '01',
  };
  // Lets the console demonstrate a forged MAC on purpose.
  const signKey = b.tamper === 'bad_mac' ? Buffer.from('wrong-key-wrong-key-wrong-key-00') : key;
  const frame = tg.encode(msg, signKey);
  return tg.send(GATEWAY, 9100, frame, key, 12000);
}

// ---- HTTP server ------------------------------------------------------------------------

const STATIC = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
};

const server = http.createServer(async (req, res) => {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (!p.startsWith('/api/')) {
      const file = path.join(STATIC, p === '/' ? 'index.html' : p);
      if (!file.startsWith(STATIC + path.sep) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
      return;
    }

    if (p === '/api/login' && req.method === 'POST') {
      if (Date.now() < loginLockedUntil) return send(res, 429, { error: '로그인 실패가 반복되어 1분간 잠겼습니다' });
      const b = await readBody(req);
      if (!ADMIN_PASSWORD || !safeEqual(b.password || '', ADMIN_PASSWORD)) {
        if (++loginFailures >= 5) { loginLockedUntil = Date.now() + 60000; loginFailures = 0; }
        return send(res, 401, { error: '비밀번호가 올바르지 않습니다' });
      }
      loginFailures = 0;
      const sid = crypto.randomBytes(24).toString('base64url');
      const s = { csrf: crypto.randomBytes(24).toString('base64url'), expires: Date.now() + SESSION_MS };
      sessions.set(sid, s);
      return send(res, 200, { csrf: s.csrf }, { 'Set-Cookie': `pr_sid=${sid}; HttpOnly; SameSite=Strict; Path=/` });
    }

    const s = session(req);
    if (!s) return send(res, 401, { error: 'login required' });
    if (req.method === 'POST' && !safeEqual(req.headers['x-csrf-token'] || '', s.csrf)) {
      return send(res, 403, { error: 'CSRF token mismatch' });
    }

    if (p === '/api/me') return send(res, 200, { csrf: s.csrf });
    if (p === '/api/logout' && req.method === 'POST') {
      sessions.delete(cookie(req, 'pr_sid'));
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'pr_sid=; Max-Age=0; Path=/' });
    }
    if (p === '/api/summary') return send(res, 200, await summary());
    if (p === '/api/transactions') return send(res, 200, await transactions(Object.fromEntries(url.searchParams)));
    const ev = p.match(/^\/api\/transactions\/([A-Z0-9]{20})\/events$/);
    if (ev) return send(res, 200, await txEvents(ev[1]));
    if (p === '/api/security') return send(res, 200, await security(url.searchParams.get('limit')));
    if (p === '/api/reconcile') return send(res, 200, await reconcile(url.searchParams.get('date') || today().replace(/-/g, '')));
    if (p === '/api/unban' && req.method === 'POST') {
      const b = await readBody(req);
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(b.ip || '')) return send(res, 400, { error: 'invalid ip' });
      return send(res, 200, await control(`UNBAN ${b.ip}`));
    }
    if (p === '/api/pos' && req.method === 'POST') return send(res, 200, await posSend(await readBody(req)));
    const atk = p.match(/^\/api\/attack\/(garbage|bad_mac|slowloris|conn_flood|rogue_tls)$/);
    if (atk && req.method === 'POST') {
      const r = await fetch(`${ATTACKER_URL}/run/${atk[1]}`, { method: 'POST' });
      return send(res, r.status, await r.json());
    }
    if (p === '/api/attack/probe') {
      const r = await fetch(`${ATTACKER_URL}/probe`);
      return send(res, r.status, await r.json());
    }
    return send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    return send(res, 500, { error: e.message });
  }
});

server.listen(PORT, () => console.log(`admin console on :${PORT}`));
