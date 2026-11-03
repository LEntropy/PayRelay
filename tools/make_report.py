#!/usr/bin/env python3
"""Builds test-results/report.html from the C and JavaScript unit test output and e2e.json."""

import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "test-results"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def read_text(f):
    """Windows PowerShell 5 Tee-Object writes UTF-16; everything else writes UTF-8."""
    b = f.read_bytes()
    return b.decode("utf-16") if b[:2] in (b"\xff\xfe", b"\xfe\xff") else b.decode("utf-8", errors="replace")

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1c2230;--muted:#5e6878;--line:#e2e5ea;--ok:#17794a;--ok-bg:#e3f3e9;
--bad:#b3261e;--bad-bg:#fcebea;--accent:#1f5fd1}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#101317;--card:#181c22;--text:#e4e7ec;
--muted:#97a0ad;--line:#29303a;--ok:#4cc38a;--ok-bg:#12301f;--bad:#ff7b72;--bad-bg:#3a1a18;--accent:#7aa2f7}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,"Segoe UI","Malgun Gothic",sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:30px 0 10px}
h3{font-size:15px;margin:20px 0 8px}.sub{color:var(--muted);margin:0 0 18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.tile .v{font-size:24px;font-weight:700}
.tile .k{color:var(--muted);font-size:13px}.ok{color:var(--ok)}.bad{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px}tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.badge.pass{background:var(--ok-bg);color:var(--ok)}.badge.fail{background:var(--bad-bg);color:var(--bad)}.d{color:var(--muted);font-size:12.5px;word-break:break-all}
"""


def esc(s):
    return html.escape(str(s))


def badge(ok):
    return "<span class='badge pass'>PASS</span>" if ok else "<span class='badge fail'>FAIL</span>"


def c_units():
    f = OUT / "unit_c.txt"
    groups, cur = [], None
    if not f.exists():
        return groups
    for raw in read_text(f).splitlines():
        line = ANSI.sub("", raw)
        m = re.match(r"\s+(PASS|FAIL) (.+)", line)
        if m:
            cur[1].append((m.group(1) == "PASS", m.group(2)))
        elif line and not line.startswith(" ") and "checks passed" not in line:
            cur = (line.strip(), [])
            groups.append(cur)
    return groups


def js_units():
    f = OUT / "unit_js.txt"
    if not f.exists():
        return []
    out = []
    for raw in read_text(f).splitlines():
        m = re.match(r"(not ok|ok) \d+ - (.+)$", ANSI.sub("", raw).strip())
        if m:
            out.append((m.group(1) == "ok", m.group(2)))
    return out


def main():
    cg = c_units()
    js = js_units()
    e2e = json.loads((OUT / "e2e.json").read_text(encoding="utf-8")) if (OUT / "e2e.json").exists() else None
    c_total = sum(len(g[1]) for g in cg)
    c_ok = sum(ok for g in cg for ok, _ in g[1])
    js_ok = sum(ok for ok, _ in js)
    load = next((r for r in (e2e or {}).get("results", []) if r.get("metric") == "load"), None)

    p = ["<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>PayRelay Test Report</title><style>{CSS}</style></head><body><main>",
         "<h1>PayRelay 테스트 결과</h1>",
         "<p class='sub'>C 게이트웨이 · VAN 시뮬레이터 · MySQL · Node.js 관리 콘솔을 Docker로 띄우고 실제 TCP로 검증한 결과</p><div class='tiles'>"]
    tiles = [(f"{c_ok} / {c_total}", "C 단위 테스트 (ASan·UBSan)", c_ok == c_total),
             (f"{js_ok} / {len(js)}", "JS 코덱 교차 검증", js_ok == len(js))]
    if e2e:
        tiles.append((f"{e2e['passed']} / {e2e['total']}", "E2E 검증 항목", e2e["passed"] == e2e["total"]))
    if load:
        tiles.append((f"{load['tps']:,} TPS", f"부하 {load['total']:,}건 · p95 {load['p95_ms']} ms", True))
    for v, k, ok in tiles:
        p.append(f"<div class='tile'><div class='v {'ok' if ok else 'bad'}'>{esc(v)}</div><div class='k'>{esc(k)}</div></div>")
    p.append("</div>")

    if e2e:
        p.append("<h2>1. End-to-End (실제 서버, 실제 TCP)</h2>")
        p.append("<p class='sub'>테스트 전문은 C 코드와 별개로 Python으로 구현한 코덱으로 만들었습니다. "
                 "공격 트래픽은 별도 컨테이너(다른 IP)에서 보냈습니다.</p>")
        open_card = False
        for r in e2e["results"]:
            if "section" in r:
                if open_card:
                    p.append("</table></div>")
                p.append(f"<h3>{esc(r['section'])}</h3><div class='card'><table><tr><th style='width:70px'>결과</th><th>확인 내용</th></tr>")
                open_card = True
            elif "ok" in r:
                d = f"<div class='d'>{esc(r['detail'])}</div>" if r.get("detail") else ""
                p.append(f"<tr><td>{badge(r['ok'])}</td><td>{esc(r['name'])}{d}</td></tr>")
        if open_card:
            p.append("</table></div>")

    p.append("<h2>2. C 단위 테스트 (전문 코덱 · MAC · 카드 · 속도 제한)</h2>")
    for title, items in cg:
        p.append(f"<h3>{esc(title)}</h3><div class='card'><table>")
        for ok, name in items:
            p.append(f"<tr><td style='width:70px'>{badge(ok)}</td><td>{esc(name)}</td></tr>")
        p.append("</table></div>")
    p.append("<h2>3. JavaScript 코덱 교차 검증</h2><div class='card'><table>")
    for ok, name in js:
        p.append(f"<tr><td style='width:70px'>{badge(ok)}</td><td>{esc(name)}</td></tr>")
    p.append("</table></div></main></body></html>")

    (OUT / "report.html").write_text("".join(p), encoding="utf-8")
    print(f"wrote {OUT / 'report.html'}: C {c_ok}/{c_total}, JS {js_ok}/{len(js)}"
          + (f", E2E {e2e['passed']}/{e2e['total']}" if e2e else ""))


if __name__ == "__main__":
    main()
