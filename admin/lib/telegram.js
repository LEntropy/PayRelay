'use strict';
// Telegram codec in JavaScript: the third independent implementation (C gateway, Python
// tests, this one for the admin console's test terminal). All three must agree byte for byte.
const crypto = require('crypto');
const net = require('net');

const HEADER = [['msg_type', 4, 'n'], ['version', 2, 'n'], ['merchant_id', 10, 'a'], ['terminal_id', 8, 'a'],
  ['trace_no', 6, 'n'], ['tx_datetime', 14, 'n'], ['resp_code', 4, 'n']];

const BODIES = {
  '0200': [['order_no', 20, 'a'], ['card_no', 19, 'c'], ['expiry', 4, 'n'], ['amount', 12, 'n'],
    ['installment', 2, 'n'], ['currency', 3, 'a']],
  '0210': [['order_no', 20, 'a'], ['pg_tx_id', 20, 'a'], ['approval_no', 8, 'a'], ['amount', 12, 'n'],
    ['card_masked', 19, 'a']],
  '0400': [['order_no', 20, 'a'], ['pg_tx_id', 20, 'a'], ['amount', 12, 'n'], ['reason', 2, 'n']],
  '0410': [['order_no', 20, 'a'], ['pg_tx_id', 20, 'a'], ['amount', 12, 'n'], ['approval_no', 8, 'a']],
  '0800': [],
  '0810': [],
};

const RESPONSE_TEXT = {
  '0000': '정상 처리', '1001': 'MAC 오류', '1002': '전문 형식 오류', '1003': '미등록/정지 가맹점',
  '1004': '처리 중인 주문', '2001': '잔액 부족/한도 초과', '2002': '카드번호 오류', '2003': '유효기간 만료',
  '2004': '분실/정지 카드', '3001': '원거래 없음', '3002': '이미 취소됨', '3003': '취소 금액 불일치',
  '9001': 'VAN 응답 시간 초과 (망취소 처리)', '9002': 'VAN 연결 불가', '9003': '요청 과다 (속도 제한)',
  '9999': '시스템 오류',
};

function field(value, width, kind) {
  const s = String(value ?? (kind === 'n' ? 0 : ''));
  const out = kind === 'n' ? s.padStart(width, '0') : s.padEnd(width, ' ');
  if (out.length !== width || !/^[\x20-\x7e]*$/.test(out)) throw new Error(`필드 값 "${value}"이(가) ${width}자 칸에 맞지 않습니다`);
  return out;
}

function mac(key, signed) {
  return crypto.createHmac('sha256', key).update(signed).digest('hex').slice(0, 32).toUpperCase();
}

function encode(msg, key) {
  const defaults = { version: '01', resp_code: '0000' };
  const head = HEADER.map(([n, w, k]) => field(msg[n] ?? defaults[n], w, k)).join('');
  const body = BODIES[msg.msg_type].map(([n, w, k]) => field(msg[n], w, k)).join('');
  const signed = head + body;
  const payload = signed + mac(key, signed);
  return String(payload.length).padStart(4, '0') + payload;
}

function decode(frame) {
  const out = {};
  let pos = 4;
  for (const [n, w] of HEADER) { out[n] = frame.slice(pos, pos + w).trimEnd(); pos += w; }
  for (const [n, w] of BODIES[out.msg_type] || []) {
    const v = frame.slice(pos, pos + w);
    out[n] = n === 'amount' ? Number(v) : v.trimEnd();
    pos += w;
  }
  out.mac = frame.slice(pos, pos + 32);
  out.resp_text = RESPONSE_TEXT[out.resp_code] || '';
  return out;
}

function verify(frame, key) {
  const a = Buffer.from(mac(key, frame.slice(4, -32)));
  const b = Buffer.from(frame.slice(-32));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function now14() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

// One request on a new connection; resolves with { request, response, decoded, mac_ok, ms }.
function send(host, port, frame, key, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.connect({ host, port });
    let buf = '';
    const done = (result) => { sock.destroy(); resolve({ request: frame, ms: Date.now() - t0, ...result }); };
    sock.setTimeout(timeoutMs, () => done({ error: `응답 없음 (${timeoutMs / 1000}초)` }));
    sock.on('connect', () => sock.write(frame, 'ascii'));
    sock.on('data', (chunk) => {
      buf += chunk.toString('ascii');
      if (buf.length >= 4) {
        const need = Number(buf.slice(0, 4)) + 4;
        if (buf.length >= need) {
          const resp = buf.slice(0, need);
          done({ response: resp, decoded: decode(resp), mac_ok: verify(resp, key) });
        }
      }
    });
    sock.on('close', () => done({ error: buf ? `불완전한 응답: ${buf}` : '게이트웨이가 연결을 끊었습니다' }));
    sock.on('error', (e) => done({ error: `연결 오류: ${e.code || e.message}` }));
  });
}

module.exports = { encode, decode, verify, now14, send, RESPONSE_TEXT };
