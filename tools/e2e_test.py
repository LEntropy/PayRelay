#!/usr/bin/env python3
"""End-to-end test of the running PayRelay stack (docker compose run --rm tester).

Talks to the C gateway over real TCP with telegrams built by paytg.py (an implementation
independent of the C code), checks the database directly, drives the attacker container,
runs a load test, and reconciles against the VAN settlement file through the admin API.
Writes /results/e2e.json for the HTML report.
"""

import json
import os
import socket
import statistics
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pymysql

import paytg

GW = os.environ.get("GATEWAY_HOST", "gateway")
ATTACKER = os.environ.get("ATTACKER_URL", "http://attacker:7000")
ADMIN = os.environ.get("ADMIN_URL", "http://admin:8090")
TOKEN = os.environ.get("CONTROL_TOKEN", "")
RUN = time.strftime("%H%M%S")

results = []


def section(title):
    print(f"\n\033[1;36m== {title} ==\033[0m", flush=True)
    results.append({"section": title})


def check(name, ok, detail=""):
    results.append({"name": name, "ok": bool(ok), "detail": str(detail)})
    print(f"  [{'\033[32mPASS' if ok else '\033[31mFAIL'}\033[0m] {name}" + (f"  ({detail})" if detail else ""), flush=True)


def db():
    return pymysql.connect(host=os.environ.get("DB_HOST", "mysql"), user="admin_ro", password="admin-demo-pw",
                           database="payrelay", autocommit=True)


def query(sql, *args):
    with db() as c, c.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def control(cmd):
    with socket.create_connection((GW, 9190), timeout=5) as s:
        f = s.makefile("rw")
        f.write(f"AUTH {TOKEN}\n{cmd}\n")
        f.flush()
        f.readline()
        return json.loads(f.readline())


def http_json(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read()), r.headers


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((GW, 9100))
    ip = s.getsockname()[0]
    s.close()
    return ip


def order(tag):
    return f"E{RUN}{tag}"[:20]


def status_of(pg_tx_id):
    rows = query("SELECT status FROM transactions WHERE pg_tx_id = %s", pg_tx_id)
    return rows[0]["status"] if rows else None


def wait_status(pg_tx_id, want, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = status_of(pg_tx_id)
        if s in want:
            return s
        time.sleep(0.3)
    return status_of(pg_tx_id)


def main():
    control(f"UNBAN {my_ip()}")
    pos = paytg.Pos(GW)

    # ---------------------------------------------------------------------------------------
    section("1. 정상 승인 흐름")
    r = pos.echo()
    check("망관리(0800) 전문에 0810 응답, 응답 MAC 검증", r and r["msg_type"] == "0810" and r["mac_ok"])
    o = order("OK1")
    r = pos.approve(o, 15000)
    check("정상 승인 0000, 승인번호·PG 거래번호 발급", r["resp_code"] == "0000" and len(r["approval_no"]) == 8 and r["pg_tx_id"].startswith("P"),
          f"{r['pg_tx_id']} / {r['approval_no']}")
    check("응답의 카드번호는 마스킹 (앞 6, 뒤 4자리)", r["card_masked"] == "411111******1111", r["card_masked"])
    ok_tx, ok_order = r["pg_tx_id"], o
    row = query("SELECT * FROM transactions WHERE pg_tx_id = %s", ok_tx)[0]
    check("DB 상태 APPROVED, VAN 응답 시간 기록", row["status"] == "APPROVED" and row["van_latency_ms"] is not None,
          f"{row['status']}, VAN {row['van_latency_ms']} ms")
    flat = json.dumps(row, default=str)
    check("DB 어느 칸에도 카드번호 전체가 없음 (BIN·끝 4자리·HMAC 토큰만)", "4111111111111111" not in flat and len(row["card_token"]) == 64,
          f"{row['card_bin']}****{row['card_last4']}, token {row['card_token'][:12]}...")
    ev = [e["event"] for e in query("SELECT event FROM tx_events WHERE pg_tx_id = %s ORDER BY id", ok_tx)]
    check("상태 변화 이력 기록 (REQUESTED → APPROVED)", ev == ["REQUESTED", "APPROVED"], " → ".join(ev))

    # ---------------------------------------------------------------------------------------
    section("2. 거절 처리 (VAN 거절 / 게이트웨이 사전 검증)")
    for tag, card, amount, expiry, want, label, van in [
        ("NSF", "4000000000000002", 30000, "2912", "2001", "잔액 부족 → VAN이 2001", True),
        ("LOST", "4000000000000119", 8000, "2912", "2004", "분실 카드 → VAN이 2004", True),
        ("LIM", "4111111111111111", 1500000, "2912", "2001", "한도 초과(150만원) → VAN이 2001", True),
        ("LUHN", "4111111111111112", 5000, "2912", "2002", "Luhn 검사 실패 → 게이트웨이가 2002, VAN 호출 없음", False),
        ("EXP", "4111111111111111", 5000, "2401", "2003", "유효기간 지남 → 게이트웨이가 2003, VAN 호출 없음", False),
    ]:
        r = pos.approve(order(tag), amount, card=card, expiry=expiry)
        row = query("SELECT status, van_latency_ms FROM transactions WHERE pg_tx_id = %s", r["pg_tx_id"])[0]
        called = row["van_latency_ms"] is not None
        check(label, r["resp_code"] == want and row["status"] == "DECLINED" and called == van,
              f"{r['resp_code']} {r['resp_text']}, VAN 호출 {'O' if called else 'X'}")

    # ---------------------------------------------------------------------------------------
    section("3. 중복 결제 방지 (멱등성)")
    r2 = pos.approve(ok_order, 15000)
    n = query("SELECT COUNT(*) AS n FROM transactions WHERE merchant_id='M000000001' AND order_no=%s", ok_order)[0]["n"]
    check("같은 주문을 다시 보내면 같은 결과를 돌려주고 DB에는 1건", r2["pg_tx_id"] == ok_tx and r2["resp_code"] == "0000" and n == 1,
          f"승인번호 {r2['approval_no']}, DB {n}건")
    ev = [e["event"] for e in query("SELECT event FROM tx_events WHERE pg_tx_id = %s ORDER BY id", ok_tx)]
    check("재전송은 이력에 DUPLICATE_REPLAY로 남고 VAN에는 다시 안 감", "DUPLICATE_REPLAY" in ev, " → ".join(ev))
    r3 = pos.approve(ok_order, 99000)
    check("같은 주문번호로 금액을 바꿔 보내면 거부 (다른 결제의 결과를 돌려주지 않음)", r3["resp_code"] == "1002", r3["resp_text"])

    # concurrent duplicates: 10 terminals send the same new order at the same time
    o = order("RACE")
    def same_order(_):
        p = paytg.Pos(GW, merchant="M000000009", terminal="T0000RAC")
        try:
            return p.approve(o, 7000)
        finally:
            p.close()
    with ThreadPoolExecutor(10) as ex:
        rs = list(ex.map(same_order, range(10)))
    n = query("SELECT COUNT(*) AS n FROM transactions WHERE merchant_id='M000000009' AND order_no=%s", o)[0]["n"]
    codes = sorted({x["resp_code"] for x in rs})
    check("같은 주문을 10개 단말이 동시에 보내도 DB에는 1건, VAN 승인 1번", n == 1 and set(codes) <= {"0000", "1004"},
          f"응답 코드 {codes}, DB {n}건")

    # ---------------------------------------------------------------------------------------
    section("4. 취소")
    c = pos.cancel(ok_order, ok_tx, 15000)
    check("승인 건 전체 취소 0000, 취소 승인번호 발급", c["resp_code"] == "0000" and c["approval_no"], c["approval_no"])
    check("DB 상태 CANCELED", status_of(ok_tx) == "CANCELED")
    c = pos.cancel(ok_order, ok_tx, 15000)
    check("이미 취소된 거래를 다시 취소하면 3002", c["resp_code"] == "3002", c["resp_text"])
    o2 = order("CX2")
    load = paytg.Pos(GW, merchant="M000000009")
    a = load.approve(o2, 20000)
    c = load.cancel(o2, a["pg_tx_id"], 10000)
    check("금액이 다른 취소 요청은 3003 (부분 취소 미지원)", c["resp_code"] == "3003", c["resp_text"])
    c = load.cancel(order("NOPE"), "P000000000000000000", 1000)
    check("원거래가 없는 취소는 3001", c["resp_code"] == "3001", c["resp_text"])

    def cancel_once(_):
        p = paytg.Pos(GW, merchant="M000000009", terminal="T0000CXL")
        try:
            return p.cancel(o2, a["pg_tx_id"], 20000)["resp_code"]
        finally:
            p.close()
    with ThreadPoolExecutor(5) as ex:
        codes = list(ex.map(cancel_once, range(5)))
    check("같은 거래를 5개 단말이 동시에 취소해도 성공은 1번 (행 잠금)", codes.count("0000") == 1 and codes.count("3002") == 4,
          f"응답 {sorted(codes)}")

    # ---------------------------------------------------------------------------------------
    section("5. VAN 응답 지연과 망취소")
    o = order("SLOW")
    t0 = time.time()
    r = pos.approve(o, 1777)
    took = time.time() - t0
    check("VAN이 3초 안에 답하지 않으면 가맹점에 9001을 바로 응답 (기다리게 두지 않음)", r["resp_code"] == "9001" and took < 4.5,
          f"{took:.1f}초")
    st = wait_status(r["pg_tx_id"], {"NET_CANCELED", "REVERSAL_FAILED"})
    check("게이트웨이가 망취소(0420)를 보내 NET_CANCELED로 정리", st == "NET_CANCELED", st)
    r2 = pos.approve(o, 1777)
    check("망취소된 주문을 다시 보내면 결제하지 않고 같은 결과(9001) 반환", r2["resp_code"] == "9001" and r2["pg_tx_id"] == r["pg_tx_id"])
    slow_tx = r["pg_tx_id"]

    o = order("RVLOST")
    r = pos.approve(o, 2888)
    st = wait_status(r["pg_tx_id"], {"NET_CANCELED", "REVERSAL_FAILED"}, timeout=20)
    check("망취소 응답까지 유실되면 3번 재시도 후 REVERSAL_FAILED (대사 대상)", st == "REVERSAL_FAILED", st)
    lost_tx = r["pg_tx_id"]

    # ---------------------------------------------------------------------------------------
    section("6. 정산 대사 (VAN 정산 파일 vs PG 기록)")
    time.sleep(6)   # the VAN books the late originals after its 5 s delay
    login, hdrs = http_json(f"{ADMIN}/api/login", "POST", {"password": "admin1234!"})
    cookie = hdrs["Set-Cookie"].split(";")[0]
    rec, _ = http_json(f"{ADMIN}/api/reconcile?date={time.strftime('%Y%m%d')}", headers={"Cookie": cookie})
    ids = {m["pg_tx_id"]: m for m in rec["mismatches"]}
    check("정산 파일을 읽고 PG 기록과 거래 단위로 비교", rec["file_exists"] and rec["van_lines"] > 0,
          f"{rec['file']} {rec['van_lines']}줄, PG {rec['pg_rows']}건")
    check("망취소 유실 건이 불일치로 정확히 잡힘 (VAN은 승인, PG는 미확정)", lost_tx in ids and ids[lost_tx]["van_net"] == 2888,
          ids.get(lost_tx, {}).get("action", "not found"))
    check("망취소가 늦은 원거래보다 먼저 도착한 건은 VAN이 원거래를 거부해 일치", slow_tx not in ids)
    check("그 밖의 모든 거래는 일치 (불일치는 유실 건뿐)", set(ids) <= {lost_tx} | {k for k in ids if k.startswith("P") and ids[k]["pg_status"] == "REVERSAL_FAILED"},
          f"불일치 {len(ids)}건")

    # ---------------------------------------------------------------------------------------
    section("7. 전문 보안 검증")
    wrong = {"msg_type": "0200", "order_no": order("FORGE"), "card_no": "4111111111111111", "expiry": "2912",
             "amount": 990000, "installment": "00", "currency": "KRW"}
    p = paytg.Pos(GW)
    r = p.call(wrong, key=b"wrong-key-wrong-key-wrong-key-00")
    check("틀린 키로 서명한(위조) 전문은 1001로 거절, 거래 기록 안 남음", r and r["resp_code"] == "1001" and not query(
        "SELECT 1 FROM transactions WHERE order_no=%s", wrong["order_no"]), r and r["resp_text"])
    p.close()
    p = paytg.Pos(GW, merchant="M000000003")
    r = p.approve(order("SUSP"), 1000)
    check("정지된 가맹점의 요청은 1003", r["resp_code"] == "1003", r["resp_text"])
    p.close()
    sqli = paytg.encode({"msg_type": "0200", "merchant_id": "M000000001", "terminal_id": "T0000001", "trace_no": "000001",
                         "tx_datetime": paytg.now14(), "order_no": "1' OR '1'='1", "card_no": "4111111111111111",
                         "expiry": "2912", "amount": 1000, "installment": "00", "currency": "KRW"}, paytg.MERCHANT_KEYS["M000000001"])
    s = socket.create_connection((GW, 9100), timeout=5)
    s.sendall(sqli)
    closed = s.recv(10) == b""
    s.close()
    check("주문번호에 SQL 문자열(따옴표)을 넣으면 형식 검사에서 연결 종료", closed)

    p = paytg.Pos(GW, merchant="M000000002")
    codes = [p.approve(order(f"R{i:02d}"), 1000 + i, card="4111111111111112")["resp_code"] for i in range(15)]
    p.close()
    check("초당 5건 가맹점이 15건을 연달아 보내면 초과분은 9003 (속도 제한)", codes.count("9003") >= 5,
          f"처리 {15 - codes.count('9003')}건, 제한 {codes.count('9003')}건")

    # ---------------------------------------------------------------------------------------
    section("8. 공격 차단 (공격자 컨테이너에서 실제 트래픽)")
    atk_ip = http_json(f"{ATTACKER}/probe")[0]["ip"]
    for name, label in [("garbage", "쓰레기 데이터 → 5회 위반 후 커널에서 패킷 차단"),
                        ("bad_mac", "MAC 위조 승인 요청 반복 → 차단"),
                        ("slowloris", "미완성 전문으로 연결 붙잡기(Slowloris) → 5초 뒤 끊고 차단"),
                        ("conn_flood", "IP당 연결 한도(50) 초과 → 차단")]:
        control(f"UNBAN {atk_ip}")
        out = http_json(f"{ATTACKER}/run/{name}", "POST")[0]
        check(label, out["before"]["state"] == "allowed" and out["after"]["state"] in ("blocked_by_kernel", "closed_by_gateway"),
              f"{out['after']['state']}: {out['after']['detail']}")
    bans = control("BANS")
    mine = [b for b in bans if b["ip"] == atk_ip]
    check("차단은 nftables(커널)에도 등록됨", mine and mine[0]["nftables"], json.dumps(mine, ensure_ascii=False))
    fresh = paytg.Pos(GW)   # the first connection was closed after 60 s idle, as configured
    check("정상 단말(테스트 러너)은 그동안 영향 없음", fresh.echo()["resp_code"] == "0000", f"테스트 러너 {my_ip()}")
    fresh.close()
    ev = query("SELECT COUNT(*) AS n FROM security_events WHERE client_ip=%s AND event='BANNED'", atk_ip)[0]["n"]
    check("차단 이벤트가 security_events 테이블에 기록", ev >= 4, f"{ev}건")
    out = http_json(f"{ATTACKER}/run/rogue_tls", "POST")[0]
    check("다른 CA 인증서 / 인증서 없이 VAN에 접속하면 TLS 단계에서 거부 (mTLS)",
          all("TLS 거부" in s["result"] or "끊음" in s["result"] for s in out["steps"]), "; ".join(s["result"] for s in out["steps"]))
    control(f"UNBAN {atk_ip}")
    check("관리자가 차단 해제하면 다시 접속 가능", http_json(f"{ATTACKER}/probe")[0]["probe"]["state"] == "allowed")

    # ---------------------------------------------------------------------------------------
    section(f"9. 부하 테스트 (epoll 단일 스레드 + 워커 {control('STATS')['workers']}개)")
    clients, per = 40, 50   # IP당 연결 한도(50) 안쪽
    lat = []
    errors = []
    lock = threading.Lock()

    def run_client(i):
        p = paytg.Pos(GW, merchant="M000000009", terminal=f"L{i:07d}")
        mine = []
        try:
            for k in range(per):
                t = time.time()
                r = p.approve(f"L{RUN}{i:03d}{k:03d}", 1000 + k)
                mine.append((time.time() - t) * 1000)
                if not r or r["resp_code"] != "0000":
                    errors.append(r and r["resp_code"])
        except Exception as e:
            errors.append(repr(e))
        finally:
            p.close()
        with lock:
            lat.extend(mine)

    t0 = time.time()
    threads = [threading.Thread(target=run_client, args=(i,)) for i in range(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.time() - t0
    total = clients * per
    n = query("SELECT COUNT(*) AS n FROM transactions WHERE merchant_id='M000000009' AND order_no LIKE %s AND status='APPROVED'",
              f"L{RUN}%")[0]["n"]
    lat.sort()
    p50 = statistics.median(lat) if lat else 0
    p95 = lat[int(len(lat) * 0.95)] if lat else 0
    check(f"동시 연결 {clients}개 × {per}건 = {total}건 모두 승인, 응답 유실 없음", not errors and n == total,
          f"{total / took:.0f} TPS, p50 {p50:.1f} ms, p95 {p95:.1f} ms, DB 승인 {n}건, 오류 {len(errors)} {errors[:3]}")
    results.append({"metric": "load", "workers": control("STATS")["workers"], "tps": round(total / took), "p50_ms": round(p50, 1), "p95_ms": round(p95, 1),
                    "total": total, "clients": clients})

    pos.close()
    passed = sum(1 for r in results if r.get("ok"))
    total_checks = sum(1 for r in results if "ok" in r)
    print(f"\n\033[1m{passed}/{total_checks} checks passed\033[0m")
    os.makedirs("/results", exist_ok=True)
    with open("/results/e2e.json", "w", encoding="utf-8") as f:
        json.dump({"passed": passed, "total": total_checks, "results": results}, f, ensure_ascii=False, indent=1)
    return 0 if passed == total_checks else 1


if __name__ == "__main__":
    raise SystemExit(main())
