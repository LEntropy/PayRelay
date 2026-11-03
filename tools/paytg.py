"""PayRelay telegram codec and POS client, written independently of the C implementation.

Used by the tests and the attacker simulator. If the C gateway and this module ever
disagree about the format, the end-to-end tests fail.
"""

import hashlib
import hmac
import socket
import time

HEADER = [("msg_type", 4, "n"), ("version", 2, "n"), ("merchant_id", 10, "a"), ("terminal_id", 8, "a"),
          ("trace_no", 6, "n"), ("tx_datetime", 14, "n"), ("resp_code", 4, "n")]

BODIES = {
    "0200": [("order_no", 20, "a"), ("card_no", 19, "c"), ("expiry", 4, "n"), ("amount", 12, "n"),
             ("installment", 2, "n"), ("currency", 3, "a")],
    "0210": [("order_no", 20, "a"), ("pg_tx_id", 20, "a"), ("approval_no", 8, "a"), ("amount", 12, "n"),
             ("card_masked", 19, "a")],
    "0400": [("order_no", 20, "a"), ("pg_tx_id", 20, "a"), ("amount", 12, "n"), ("reason", 2, "n")],
    "0410": [("order_no", 20, "a"), ("pg_tx_id", 20, "a"), ("amount", 12, "n"), ("approval_no", 8, "a")],
    "0420": [("order_no", 20, "a"), ("pg_tx_id", 20, "a"), ("amount", 12, "n"), ("reason", 2, "n")],
    "0430": [("order_no", 20, "a"), ("pg_tx_id", 20, "a"), ("amount", 12, "n"), ("approval_no", 8, "a")],
    "0800": [],
    "0810": [],
}

MERCHANT_KEYS = {
    "M000000001": bytes.fromhex("6d65726368616e742d312d64656d6f2d6b65792d303030303030303030303030"),
    "M000000002": bytes.fromhex("6d65726368616e742d322d64656d6f2d6b65792d303030303030303030303030"),
    "M000000009": bytes.fromhex("6d65726368616e742d392d6c6f61642d6b65792d303030303030303030303030"),
    "M000000003": bytes.fromhex("6d65726368616e742d332d64656d6f2d6b65792d303030303030303030303030"),
}

RESPONSE_TEXT = {
    "0000": "정상 처리", "1001": "MAC 오류", "1002": "전문 형식 오류", "1003": "미등록/정지 가맹점",
    "1004": "처리 중인 주문", "2001": "잔액 부족/한도 초과", "2002": "카드번호 오류", "2003": "유효기간 만료",
    "2004": "분실/정지 카드", "3001": "원거래 없음", "3002": "이미 취소됨", "3003": "취소 금액 불일치",
    "9001": "VAN 응답 시간 초과(망취소 처리)", "9002": "VAN 연결 불가", "9003": "요청 과다(속도 제한)",
    "9999": "시스템 오류",
}


def _field(value, width, kind):
    s = str(value)
    if kind == "n":
        s = s.rjust(width, "0")
    else:  # text and card numbers: left aligned, space padded
        s = s.ljust(width, " ")
    if len(s) != width:
        raise ValueError(f"value {value!r} does not fit in {width} characters")
    return s


def mac(key, signed: bytes) -> bytes:
    return hmac.new(key, signed, hashlib.sha256).hexdigest()[:32].upper().encode()


def encode(msg: dict, key: bytes) -> bytes:
    t = msg["msg_type"]
    body = "".join(_field(msg.get(n, "" if k != "n" else 0), w, k) for n, w, k in BODIES[t])
    head = "".join(_field(msg.get(n, {"version": "01", "resp_code": "0000"}.get(n, "")), w, k)
                   for n, w, k in HEADER)
    signed = (head + body).encode("ascii")
    payload = signed + mac(key, signed)
    return f"{len(payload):04d}".encode() + payload


def decode(frame: bytes) -> dict:
    text = frame.decode("ascii")
    out, pos = {}, 4
    for name, width, _ in HEADER:
        out[name] = text[pos:pos + width].rstrip(" ")
        pos += width
    for name, width, kind in BODIES[out["msg_type"]]:
        v = text[pos:pos + width]
        out[name] = int(v) if name == "amount" else v.rstrip(" ")
        pos += width
    out["mac"] = text[pos:pos + 32]
    out["resp_text"] = RESPONSE_TEXT.get(out["resp_code"], "")
    return out


def verify(frame: bytes, key: bytes) -> bool:
    return hmac.compare_digest(mac(key, frame[4:-32]), frame[-32:])


def now14():
    return time.strftime("%Y%m%d%H%M%S")


class Pos:
    """A merchant terminal: one TCP connection to the gateway."""

    _trace = int(time.time()) % 900000

    def __init__(self, host, port=9100, merchant="M000000001", terminal="T0000001", timeout=10):
        self.merchant, self.terminal = merchant, terminal
        self.key = MERCHANT_KEYS[merchant]
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @classmethod
    def next_trace(cls):
        cls._trace = (cls._trace + 1) % 1000000
        return f"{cls._trace:06d}"

    def recv_frame(self):
        head = self._recv_exact(4)
        if not head:
            return None
        return head + self._recv_exact(int(head))

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return buf if buf else None
            buf += chunk
        return buf

    def call(self, msg: dict, key=None):
        base = {"merchant_id": self.merchant, "terminal_id": self.terminal, "trace_no": self.next_trace(),
                "tx_datetime": now14()}
        base.update(msg)
        frame = encode(base, key or self.key)
        self.sock.sendall(frame)
        resp = self.recv_frame()
        if resp is None:
            return None
        d = decode(resp)
        d["mac_ok"] = verify(resp, self.key)
        d["raw_request"] = frame.decode()
        d["raw_response"] = resp.decode()
        return d

    def approve(self, order_no, amount, card="4111111111111111", expiry="2912", installment="00"):
        return self.call({"msg_type": "0200", "order_no": order_no, "card_no": card, "expiry": expiry,
                          "amount": amount, "installment": installment, "currency": "KRW"})

    def cancel(self, order_no, pg_tx_id, amount):
        return self.call({"msg_type": "0400", "order_no": order_no, "pg_tx_id": pg_tx_id, "amount": amount,
                          "reason": "01"})

    def echo(self):
        return self.call({"msg_type": "0800"})

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
