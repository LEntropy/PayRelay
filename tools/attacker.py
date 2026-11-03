#!/usr/bin/env python3
"""Attack simulator with a small HTTP API (port 7000, internal network only).

Runs in its own container so its traffic comes from its own IP address, separate from the
admin console and the test runner. Each scenario returns what happened step by step, then
probes whether the gateway still lets this address in.

  POST /run/garbage     non-telegram bytes (HTTP request, random data)
  POST /run/bad_mac     well-formed telegrams signed with a wrong key
  POST /run/slowloris   start telegrams and never finish them
  POST /run/conn_flood  more parallel connections than allowed per IP
  POST /run/rogue_tls   connect to the VAN with a certificate from a foreign CA / none at all
  GET  /probe           can this address still reach the gateway?
"""

import json
import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import paytg

GW = os.environ.get("GATEWAY_HOST", "gateway")
PORT = 9100
lock = threading.Lock()   # one scenario at a time


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((GW, PORT))
        return s.getsockname()[0]
    finally:
        s.close()


def probe(timeout=3.0):
    """Distinguishes 'kernel drops our packets' (connect times out) from an application refusal."""
    t0 = time.time()
    try:
        p = paytg.Pos(GW, PORT, timeout=timeout)
    except socket.timeout:
        return {"state": "blocked_by_kernel", "detail": f"TCP 연결이 {timeout:.0f}초 동안 응답 없음 (nftables가 패킷을 버림)",
                "ms": int((time.time() - t0) * 1000)}
    except OSError as e:
        return {"state": "refused", "detail": str(e), "ms": int((time.time() - t0) * 1000)}
    try:
        r = p.echo()
        if r is None:
            return {"state": "closed_by_gateway", "detail": "연결 직후 게이트웨이가 끊음 (프로세스 내부 차단 목록)",
                    "ms": int((time.time() - t0) * 1000)}
        return {"state": "allowed", "detail": f"망관리 전문 응답 {r['resp_code']}", "ms": int((time.time() - t0) * 1000)}
    except (socket.timeout, OSError) as e:
        return {"state": "blocked_or_closed", "detail": str(e), "ms": int((time.time() - t0) * 1000)}
    finally:
        p.close()


def one_shot(payload: bytes, wait=2.0):
    """Sends bytes on a fresh connection and reports how the gateway reacted."""
    try:
        s = socket.create_connection((GW, PORT), timeout=wait)
    except OSError as e:
        return f"연결 실패: {e.__class__.__name__}"
    try:
        s.sendall(payload)
        data = s.recv(512)
        if not data:
            return "게이트웨이가 연결을 끊음"
        try:
            d = paytg.decode(data)
            return f"응답 {d['msg_type']} 코드 {d['resp_code']} ({d['resp_text']})"
        except Exception:
            return f"응답 {data[:40]!r}"
    except socket.timeout:
        return "응답 없음 (시간 초과)"
    except OSError as e:
        return f"연결 끊김: {e.__class__.__name__}"
    finally:
        s.close()


def garbage():
    payloads = [b"GET / HTTP/1.1\r\nHost: gateway\r\n\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
                b"9999" + b"A" * 60, b"' OR 1=1 --", b"ABCD" * 20, b"0012hello"]
    return [{"send": repr(p[:24]), "result": one_shot(p)} for p in payloads]


def bad_mac():
    steps = []
    wrong_key = b"attacker-guessed-key-0000000000"
    for i in range(6):
        msg = {"msg_type": "0200", "merchant_id": "M000000001", "terminal_id": "T0000666",
               "trace_no": f"{i:06d}", "tx_datetime": paytg.now14(), "order_no": f"FORGED{int(time.time())}{i}",
               "card_no": "4111111111111111", "expiry": "2912", "amount": 990000, "installment": "00",
               "currency": "KRW"}
        steps.append({"send": f"위조 MAC 승인요청 #{i + 1} (99만원)", "result": one_shot(paytg.encode(msg, wrong_key))})
    return steps


def slowloris():
    socks, steps = [], []
    for i in range(6):
        try:
            s = socket.create_connection((GW, PORT), timeout=3)
            s.sendall(b"0140" + b"0200")    # a frame that is never finished
            socks.append(s)
        except OSError as e:
            steps.append({"send": f"느린 연결 #{i + 1}", "result": f"연결 실패: {e.__class__.__name__}"})
    steps.append({"send": f"미완성 전문 {len(socks)}개를 열어 두고 대기", "result": "게이트웨이 프레임 제한 시간(5초) 경과 기다리는 중"})
    time.sleep(7)
    closed = 0
    for s in socks:
        try:
            s.settimeout(1)
            if s.recv(1) == b"":
                closed += 1
        except OSError:
            closed += 1
        s.close()
    steps.append({"send": "7초 뒤 확인", "result": f"{closed}/{len(socks)}개 연결을 게이트웨이가 끊음"})
    return steps


def conn_flood():
    socks, opened, failed = [], 0, 0
    for _ in range(70):
        try:
            socks.append(socket.create_connection((GW, PORT), timeout=2))
            opened += 1
        except OSError:
            failed += 1
    time.sleep(1)
    alive = 0
    for s in socks:
        try:
            s.settimeout(0.2)
            if s.recv(1) != b"":
                alive += 1
        except socket.timeout:
            alive += 1
        except OSError:
            pass
        s.close()
    return [{"send": "동시 연결 70개 시도 (IP당 허용 50개)", "result": f"연결 성립 {opened}, 실패 {failed}, 1초 뒤 살아 있는 연결 {alive}"}]


def rogue_tls():
    steps = []
    for label, cert in (("다른 CA가 서명한 인증서", ("/certs/rogue.crt", "/certs/rogue.key")), ("클라이언트 인증서 없음", None)):
        ctx = ssl.create_default_context(cafile="/certs/ca.crt")
        ctx.check_hostname = False
        if cert:
            ctx.load_cert_chain(*cert)
        try:
            with socket.create_connection(("van", 9200), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname="van") as tls:
                    tls.sendall(b"0080")
                    data = tls.recv(10)
                    result = "VAN이 연결을 끊음" if not data else f"응답 받음 {data!r} (문제!)"
        except (ssl.SSLError, OSError) as e:
            result = f"TLS 거부: {e.__class__.__name__}"
        steps.append({"send": f"VAN에 접속: {label}", "result": result})
    return steps


SCENARIOS = {"garbage": garbage, "bad_mac": bad_mac, "slowloris": slowloris, "conn_flood": conn_flood,
             "rogue_tls": rogue_tls}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/probe":
            self._json(200, {"ip": my_ip(), "probe": probe()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        name = self.path.rsplit("/", 1)[-1]
        if not self.path.startswith("/run/") or name not in SCENARIOS:
            self._json(404, {"error": "unknown scenario"})
            return
        if not lock.acquire(blocking=False):
            self._json(409, {"error": "another scenario is running"})
            return
        try:
            before = probe(1.5)
            steps = SCENARIOS[name]()
            time.sleep(0.5)
            after = probe() if name != "rogue_tls" else {"state": "n/a", "detail": "VAN 직접 접속 시나리오"}
            self._json(200, {"scenario": name, "ip": my_ip(), "before": before, "steps": steps, "after": after})
        finally:
            lock.release()


if __name__ == "__main__":
    print(f"attacker ready on :7000, target {GW}:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 7000), Handler).serve_forever()
