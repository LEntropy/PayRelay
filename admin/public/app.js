'use strict';
// Admin console front end. Every value from the server is inserted with textContent, never
// as HTML, so data coming from merchants (order numbers, IPs, details) cannot inject markup.
const $ = (id) => document.getElementById(id);
let csrf = '';
let current = 'dash';
let refreshTimer = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
const won = (n) => `${Number(n || 0).toLocaleString('ko-KR')}원`;
const num = (n) => Number(n || 0).toLocaleString('ko-KR');

const STATUS = {
  APPROVED: ['승인', 'ok'], DECLINED: ['거절', 'warn'], CANCELED: ['취소', 'info'], PENDING: ['처리 중', 'info'],
  TIMEOUT: ['시간 초과', 'bad'], NET_CANCELED: ['망취소 완료', 'warn'], REVERSAL_FAILED: ['망취소 실패', 'bad'],
};
const pill = (status) => { const [t, c] = STATUS[status] || [status, 'info']; return el('span', `pill ${c}`, t); };

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.method === 'POST' ? { 'X-CSRF-Token': csrf } : {}) },
  });
  if (res.status === 401 && path !== '/api/login') { showLogin(); throw new Error('login required'); }
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function table(t, headers, rows) {
  t.replaceChildren();
  const thead = el('thead');
  const tr = el('tr');
  for (const h of headers) { const th = el('th', h.num ? 'num' : '', h.label || h); tr.appendChild(th); }
  thead.appendChild(tr);
  const tbody = el('tbody');
  if (!rows.length) {
    const r = el('tr'); const td = el('td', 'muted', '데이터가 없습니다'); td.colSpan = headers.length; r.appendChild(td); tbody.appendChild(r);
  }
  for (const cells of rows) {
    const r = el('tr', cells.onclick ? 'click' : '');
    if (cells.onclick) r.onclick = cells.onclick;
    for (let i = 0; i < headers.length; i++) {
      const c = cells[i];
      const td = el('td', headers[i].num ? 'num' : '');
      if (c instanceof Node) td.appendChild(c); else td.textContent = c ?? '';
      r.appendChild(td);
    }
    tbody.appendChild(r);
  }
  t.append(thead, tbody);
}

// ---- login --------------------------------------------------------------------------------

function showLogin() { $('app').classList.add('hidden'); $('login').classList.remove('hidden'); clearInterval(refreshTimer); }
function showApp() { $('login').classList.add('hidden'); $('app').classList.remove('hidden'); switchTab(current); }

$('loginForm').onsubmit = async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  try {
    const r = await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('pw').value }) });
    csrf = r.csrf; $('pw').value = ''; showApp();
  } catch (err) { $('loginError').textContent = err.message; }
};
$('logout').onclick = async () => { await api('/api/logout', { method: 'POST' }).catch(() => {}); showLogin(); };

// ---- tabs ---------------------------------------------------------------------------------

function switchTab(name) {
  current = name;
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab').forEach((s) => s.classList.toggle('hidden', s.id !== `tab-${name}`));
  clearInterval(refreshTimer);
  const loaders = { dash: loadDash, tx: loadTx, sec: loadSec };
  if (loaders[name]) { loaders[name](); refreshTimer = setInterval(loaders[name], 3000); }
  if (name === 'recon' && !$('reconDate').value) {
    const d = new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10).replace(/-/g, '');
    $('reconDate').value = d;
  }
}
document.querySelectorAll('#tabs button').forEach((b) => { b.onclick = () => switchTab(b.dataset.tab); });

// ---- dashboard ----------------------------------------------------------------------------

async function loadDash() {
  const s = await api('/api/summary');
  const by = Object.fromEntries(s.byStatus.map((r) => [r.status, r]));
  const count = (k) => Number(by[k]?.n || 0);
  const total = s.byStatus.reduce((a, r) => a + Number(r.n), 0);
  const decided = count('APPROVED') + count('CANCELED') + count('DECLINED');
  const rate = decided ? (((count('APPROVED') + count('CANCELED')) / decided) * 100).toFixed(1) : '-';
  const secTotal = s.security.reduce((a, r) => a + Number(r.n), 0);
  const tiles = [
    ['오늘 거래', num(total), ''], ['승인 금액 (취소 제외)', won(by.APPROVED?.amount), 'ok'], ['승인율', `${rate}%`, ''],
    ['망취소 완료', num(count('NET_CANCELED')), 'warn'], ['망취소 실패 (대사 필요)', num(count('REVERSAL_FAILED')), count('REVERSAL_FAILED') ? 'bad' : ''],
    ['보안 이벤트 (1시간)', num(secTotal), secTotal ? 'warn' : ''], ['차단 중인 IP', num(Array.isArray(s.bans) ? s.bans.length : 0), (s.bans || []).length ? 'bad' : ''],
  ];
  $('tiles').replaceChildren(...tiles.map(([k, v, c]) => { const t = el('div', `tile ${c}`); t.append(el('div', 'v', v), el('div', 'k', k)); return t; }));

  const chart = $('chart');
  chart.replaceChildren();
  const max = Math.max(1, ...s.perMinute.map((r) => Number(r.n)));
  for (const r of s.perMinute) {
    const b = el('div', 'bar');
    const f = el('div', 'fill');
    f.style.height = `${(Number(r.n) / max) * 100}%`;
    f.title = `${r.t} 거래 ${r.n}건, 승인 ${r.ok}건`;
    b.append(f, el('div', 'lbl', r.t.slice(3)));
    chart.appendChild(b);
  }
  if (!s.perMinute.length) chart.appendChild(el('div', 'muted', '최근 15분 동안 거래가 없습니다'));

  const g = s.gateway || {};
  const kv = $('gwStats');
  kv.replaceChildren();
  const items = g.error ? [['상태', g.error]] : [
    ['활성 연결', g.conn_active], ['누적 연결 / 거부', `${num(g.conn_accepted)} / ${num(g.conn_rejected)}`],
    ['받은 전문', num(g.received)], ['작업 큐 대기', g.queue_depth], ['워커 스레드', g.workers],
    ['VAN 평균 응답', `${g.van_avg_ms} ms (${num(g.van_calls)}회)`], ['중복 주문 재전송', num(g.duplicates)],
    ['속도 제한', num(g.rate_limited)], ['MAC 오류 / 형식 오류', `${num(g.bad_mac)} / ${num(g.bad_format)}`],
    ['차단 발생', num(g.bans)],
  ];
  for (const [k, v] of items) kv.append(el('dt', '', k), el('dd', '', v));

  table($('merchants'), ['가맹점', '이름', '상태', { label: '초당 한도', num: 1 }, { label: '거래', num: 1 }, { label: '승인', num: 1 }, { label: '정산 예정 금액', num: 1 }],
    s.merchants.map((m) => [m.merchant_id, m.name, el('span', `pill ${m.status === 'ACTIVE' ? 'ok' : 'bad'}`, m.status === 'ACTIVE' ? '정상' : '정지'),
      m.tps_limit, num(m.tx_count), num(m.approved_count), won(m.net_amount)]));
}

// ---- transactions -------------------------------------------------------------------------

async function loadTx() {
  const q = new URLSearchParams({ status: $('txStatus').value, q: $('txQuery').value.trim(), limit: 100 });
  const rows = await api(`/api/transactions?${q}`);
  table($('txTable'), ['요청 시각', 'PG 거래번호', '가맹점', '주문번호', { label: '금액', num: 1 }, '카드', '상태', '응답', '승인번호', { label: 'VAN 응답', num: 1 }],
    rows.map((r) => Object.assign([r.requested_at.slice(11, 19), r.pg_tx_id, r.merchant_id, r.order_no, won(r.amount), r.card, pill(r.status),
      `${r.resp_code || ''} ${r.resp_text}`, r.approval_no || '', r.van_latency_ms != null ? `${r.van_latency_ms} ms` : ''],
    { onclick: () => showTx(r) })));
}
$('txSearch').onclick = loadTx;

async function showTx(r) {
  const box = $('txDetail');
  box.classList.remove('hidden');
  box.replaceChildren(el('h2', '', `거래 이력: ${r.pg_tx_id}`));
  const dl = el('dl', 'kv');
  for (const [k, v] of [['주문번호', r.order_no], ['금액', won(r.amount)], ['카드 (저장된 형태)', r.card], ['상태', STATUS[r.status]?.[0] || r.status],
    ['응답 코드', `${r.resp_code || ''} ${r.resp_text}`], ['요청 IP', r.client_ip], ['취소 승인번호', r.cancel_approval || '-']]) dl.append(el('dt', '', k), el('dd', '', v));
  box.appendChild(dl);
  const ul = el('ul', 'timeline');
  for (const e of await api(`/api/transactions/${r.pg_tx_id}/events`)) {
    const li = el('li');
    li.append(el('b', '', e.event), el('span', 'muted', `  ${e.created_at.slice(11, 23)}  ${e.detail || ''}`));
    ul.appendChild(li);
  }
  box.append(el('h2', '', '상태 변화'), ul);
  box.scrollIntoView({ behavior: 'smooth' });
}

// ---- test terminal ------------------------------------------------------------------------

let lastApproval = null;
const uid = () => `WEB${Date.now().toString().slice(-9)}${Math.floor(Math.random() * 90 + 10)}`;
const PRESETS = [
  { t: '정상 승인', d: '15,000원, 정상 카드', set: { type: '0200', amount: 15000, card: '4111111111111111' } },
  { t: '잔액 부족', d: 'VAN이 거절 (2001)', set: { type: '0200', amount: 30000, card: '4000000000000002' } },
  { t: '분실 카드', d: 'VAN이 거절 (2004)', set: { type: '0200', amount: 8000, card: '4000000000000119' } },
  { t: '카드번호 오류', d: 'Luhn 검사 실패, VAN까지 안 감', set: { type: '0200', amount: 5000, card: '4111111111111112' } },
  { t: '유효기간 만료', d: '게이트웨이가 바로 거절', set: { type: '0200', amount: 5000, card: '4111111111111111', expiry: '2401' } },
  { t: 'VAN 응답 지연 → 망취소', d: '금액 끝 777: 3초 초과, 자동 망취소', set: { type: '0200', amount: 1777, card: '4111111111111111' } },
  { t: '망취소도 유실', d: '금액 끝 888: 대사에서 잡아야 함', set: { type: '0200', amount: 2888, card: '4111111111111111' } },
  { t: '같은 주문 다시 보내기', d: '중복 결제 방지 (멱등성)', set: { type: '0200', repeat: true } },
  { t: '직전 승인 취소', d: '0400 취소 요청', set: { type: '0400', cancelLast: true } },
  { t: 'MAC 위조', d: '틀린 키로 서명 (1001)', set: { type: '0200', amount: 990000, card: '4111111111111111', badMac: true } },
  { t: '정지된 가맹점', d: 'M000000003 (1003)', set: { type: '0200', amount: 1000, card: '4111111111111111', merchant: 'M000000003' } },
];

function applyPreset(p) {
  const s = p.set;
  $('posType').value = s.type;
  $('posMerchant').value = s.merchant || 'M000000001';
  $('posBadMac').checked = !!s.badMac;
  $('posExpiry').value = s.expiry || '2912';
  if (s.repeat && lastApproval) { $('posOrder').value = lastApproval.order_no; $('posAmount').value = lastApproval.amount; $('posCard').value = lastApproval.card_no; $('posMerchant').value = lastApproval.merchant_id; return; }
  if (s.cancelLast && lastApproval) {
    $('posOrder').value = lastApproval.order_no; $('posAmount').value = lastApproval.amount; $('posPgTx').value = lastApproval.pg_tx_id; $('posMerchant').value = lastApproval.merchant_id; return;
  }
  $('posOrder').value = uid();
  if (s.amount !== undefined) $('posAmount').value = s.amount;
  if (s.card) $('posCard').value = s.card;
  $('posPgTx').value = '';
}
$('presets').replaceChildren(...PRESETS.map((p) => {
  const b = el('button'); b.append(el('b', '', p.t), el('span', '', p.d)); b.onclick = () => applyPreset(p); return b;
}));
applyPreset(PRESETS[0]);

function fieldTable(decoded) {
  const t = el('table', 'fields');
  const skip = new Set(['resp_text']);
  for (const [k, v] of Object.entries(decoded)) {
    if (skip.has(k)) continue;
    const r = el('tr'); r.append(el('td', 'muted', k), el('td', '', v)); t.appendChild(r);
  }
  return t;
}

$('posSend').onclick = async () => {
  const btn = $('posSend');
  btn.disabled = true;
  const body = {
    msg_type: $('posType').value, merchant_id: $('posMerchant').value, order_no: $('posOrder').value.trim(),
    amount: $('posAmount').value, card_no: $('posCard').value.trim(), expiry: $('posExpiry').value.trim(),
    pg_tx_id: $('posPgTx').value.trim(), tamper: $('posBadMac').checked ? 'bad_mac' : '',
  };
  const box = $('posResult');
  box.replaceChildren(el('p', 'muted', '게이트웨이 응답을 기다리는 중...'));
  try {
    const r = await api('/api/pos', { method: 'POST', body: JSON.stringify(body) });
    box.replaceChildren();
    if (r.error) {
      box.append(el('div', 'verdict bad', r.error),
        el('p', 'muted', '게이트웨이가 응답 없이 연결을 끊는 것은 형식 위반이나 차단에 대한 정상 반응입니다.'),
        el('p', '', 'MAC 위조를 1분 안에 5번 이상 보냈다면 이 관리 콘솔이 차단된 것입니다. "보안 · 차단" 탭에서 "(이 관리 콘솔)" 표시가 붙은 IP를 차단 해제하세요.'));
    } else {
      const d = r.decoded;
      const head = el('div', 'result-head');
      head.append(el('span', 'code', d.resp_code), el('span', '', d.resp_text), el('span', 'muted', `${r.ms} ms`),
        el('span', `pill ${r.mac_ok ? 'ok' : 'bad'}`, r.mac_ok ? '응답 MAC 검증 성공' : '응답 MAC 불일치'));
      box.appendChild(head);
      if (d.msg_type === '0210' && d.resp_code === '0000') lastApproval = { ...body, pg_tx_id: d.pg_tx_id };
      if (d.pg_tx_id) box.appendChild(el('p', '', `PG 거래번호 ${d.pg_tx_id}${d.approval_no ? ` · 승인번호 ${d.approval_no}` : ''}${d.card_masked ? ` · 카드 ${d.card_masked}` : ''}`));
      box.append(el('h2', '', '응답 전문 해석'), fieldTable(d));
    }
    box.append(el('h2', '', '보낸 전문 (원문)'), el('pre', '', r.request));
    if (r.response) box.append(el('h2', '', '받은 전문 (원문)'), el('pre', '', r.response));
  } catch (e) {
    box.replaceChildren(el('div', 'verdict bad', e.message));
  } finally {
    btn.disabled = false;
  }
};

// ---- security -----------------------------------------------------------------------------

async function loadSec() {
  const s = await api('/api/summary');
  const bans = Array.isArray(s.bans) ? s.bans : [];
  table($('bans'), ['IP', '마지막 위반', { label: '남은 시간', num: 1 }, '커널(nftables)', ''], bans.map((b) => {
    const btn = el('button', 'small ghost', '차단 해제');
    btn.onclick = async () => { await api('/api/unban', { method: 'POST', body: JSON.stringify({ ip: b.ip }) }); loadSec(); };
    return [b.ip === s.consoleIp ? `${b.ip} (이 관리 콘솔)` : b.ip, b.reason, `${b.remaining_s}초`, el('span', `pill ${b.nftables ? 'ok' : 'warn'}`, b.nftables ? '패킷 차단 중' : '프로세스만'), btn];
  }));
  const ev = await api('/api/security?limit=150');
  const cls = { BANNED: 'bad', VIOLATION: 'warn', BAD_MAC: 'bad', RATE_LIMITED: 'warn', UNBANNED: 'ok', ORDER_REUSE: 'bad', MERCHANT_SUSPENDED: 'warn' };
  table($('secTable'), ['시각', 'IP', '이벤트', '가맹점', '내용'], ev.map((e) => [e.created_at.slice(5, 19), e.client_ip, el('span', `pill ${cls[e.event] || 'info'}`, e.event), e.merchant_id || '', e.detail || '']));
}

// ---- attack simulation --------------------------------------------------------------------

const ATTACKS = [
  { id: 'garbage', t: '쓰레기 데이터', d: 'HTTP 요청, TLS 핸드셰이크, SQL 문자열 등' },
  { id: 'bad_mac', t: 'MAC 위조', d: '키를 모르는 공격자가 99만원 승인 요청' },
  { id: 'slowloris', t: 'Slowloris', d: '전문을 시작만 하고 끝내지 않기' },
  { id: 'conn_flood', t: '연결 폭주', d: '동시 연결 70개 (허용 50개)' },
  { id: 'rogue_tls', t: 'VAN 사칭 접속', d: '다른 CA 인증서로 VAN에 mTLS 접속' },
];
const STATE_TEXT = { allowed: ['접속 가능', 'ok'], blocked_by_kernel: ['커널에서 차단됨', 'bad'], closed_by_gateway: ['게이트웨이가 거부', 'warn'],
  refused: ['연결 거부', 'warn'], blocked_or_closed: ['차단/끊김', 'bad'], 'n/a': ['해당 없음', 'info'] };

$('attacks').replaceChildren(...ATTACKS.map((a) => {
  const b = el('button'); b.append(el('b', '', a.t), el('span', '', a.d));
  b.onclick = () => runAttack(a, b);
  return b;
}));

function stateLine(label, p) {
  const [t, c] = STATE_TEXT[p.state] || [p.state, 'info'];
  const d = el('div', 'row');
  d.append(el('b', '', label), el('span', `pill ${c}`, t), el('span', 'muted', p.detail));
  return d;
}

async function runAttack(a, btn) {
  document.querySelectorAll('#attacks button').forEach((b) => { b.disabled = true; });
  const box = $('attackResult');
  box.replaceChildren(el('p', 'muted', `${a.t} 실행 중... (Slowloris는 10초쯤 걸립니다)`));
  try {
    const r = await api(`/api/attack/${a.id}`, { method: 'POST' });
    box.replaceChildren(el('h2', '', `${a.t} — 공격자 IP ${r.ip}`), stateLine('공격 전', r.before));
    for (const s of r.steps) { const d = el('div', 'step'); d.append(el('b', '', s.send), el('span', 'muted', s.result)); box.appendChild(d); }
    box.appendChild(stateLine('공격 후', r.after));
    const blocked = ['blocked_by_kernel', 'closed_by_gateway', 'blocked_or_closed'].includes(r.after.state);
    box.appendChild(el('div', `verdict ${blocked ? 'ok' : r.after.state === 'n/a' ? 'ok' : 'warn'}`,
      a.id === 'rogue_tls' ? 'VAN은 공유 CA가 서명한 인증서가 없는 상대와 TLS 연결을 맺지 않습니다.'
        : blocked ? '공격자 IP가 차단되었습니다. "보안 · 차단" 탭에서 확인하고 해제할 수 있습니다.'
          : '아직 차단되지 않았습니다. 위반이 1분 안에 5번 쌓이면 차단됩니다.'));
  } catch (e) {
    box.replaceChildren(el('div', 'verdict bad', e.message));
  } finally {
    document.querySelectorAll('#attacks button').forEach((b) => { b.disabled = false; });
  }
}

$('probe').onclick = async () => {
  $('probeResult').textContent = '확인 중...';
  try { const r = await api('/api/attack/probe'); $('probeResult').replaceChildren(stateLine(`공격자 ${r.ip}`, r.probe)); } catch (e) { $('probeResult').textContent = e.message; }
};

// ---- reconciliation -----------------------------------------------------------------------

$('reconRun').onclick = async () => {
  const box = $('reconResult');
  box.replaceChildren(el('p', 'muted', '대사 중...'));
  try {
    const r = await api(`/api/reconcile?date=${encodeURIComponent($('reconDate').value.trim())}`);
    box.replaceChildren(el('h2', '', `${r.date} 대사 결과`));
    const dl = el('dl', 'kv');
    for (const [k, v] of [['VAN 정산 파일', `${r.file} (${r.file_exists ? `${r.van_lines}줄` : '없음'})`], ['PG 거래 기록', `${num(r.pg_rows)}건`],
      ['VAN 기준 순매출', won(r.van_total)], ['PG 기준 순매출', won(r.pg_total)], ['차액', won(r.van_total - r.pg_total)]]) dl.append(el('dt', '', k), el('dd', '', v));
    box.appendChild(dl);
    box.appendChild(el('div', `verdict ${r.matched ? 'ok' : 'bad'}`, r.matched ? '모든 거래가 일치합니다.' : `불일치 ${r.mismatches.length}건: 아래 거래를 확인해야 합니다.`));
    if (!r.matched) {
      const t = el('table');
      box.appendChild(t);
      table(t, ['PG 거래번호', '주문번호', 'PG 상태', { label: 'PG 금액', num: 1 }, { label: 'VAN 금액', num: 1 }, 'VAN 기록', '조치'],
        r.mismatches.map((m) => [m.pg_tx_id, m.order_no, STATUS[m.pg_status]?.[0] || m.pg_status, won(m.pg_net), won(m.van_net), m.van_events, m.action]));
    }
  } catch (e) { box.replaceChildren(el('div', 'verdict bad', e.message)); }
};

// ---- start --------------------------------------------------------------------------------

api('/api/me').then((r) => { csrf = r.csrf; showApp(); }).catch(() => showLogin());
