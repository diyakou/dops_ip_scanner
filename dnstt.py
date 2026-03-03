#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Scanner (Iran CIDR sampler) for DNSTT
- Cross-platform (Windows / Linux / Termux) - no 'dig' dependency
- Validates NOERROR + real answers (not just "got a response")
- Tests TXT + long subdomains + burst (rate-limit sensitive)
"""

import random
import time
import sys
import ipaddress
import statistics
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- Requires: dnspython ----
# pip install dnspython
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.exception

# ================= تنظیمات =================
DNSTT_NS_DOMAIN = "dnt.moonlightx.ir"

CIDR_FILE_PATH = "iran-ipv4.cidrs"
MAX_CIDR_TO_SAMPLE = 300
IPS_PER_CIDR = 5

MAX_WORKERS = 25

TIMEOUT = 2.2  # ثانیه (برای UDP)
SLEEP_BETWEEN_QUERIES = (0.03, 0.10)

MIN_SUCCESS_RATE = 85.0
MAX_AVG_LATENCY = 280.0

# تعداد تست‌ها
BASE_QUERIES_PER_TEST = 8         # پایدار بودن
BURST_QUERIES = 25                # رو کردن rate-limit
LONG_LABEL_LEN = 50               # نام‌های طولانی (شبیه dnstt)

# تست‌های کلیدی
TESTS = [
    # (name, qname_builder, qtype, count)
    ("whoami_txt", lambda base: "whoami.cloudflare.com", "TXT", BASE_QUERIES_PER_TEST),
    ("google_a",   lambda base: "www.google.com",       "A",   BASE_QUERIES_PER_TEST),

    # مربوط به دامنه‌ی dnstt
    ("dnstt_ns",   lambda base: base,                   "NS",  BASE_QUERIES_PER_TEST),

    # شبیه ترافیک dnstt (TXT + زیردامنه‌ی طولانی)
    ("dnstt_long_txt", lambda base: long_qname(base),   "TXT", BASE_QUERIES_PER_TEST),

    # burst برای rate-limit (زیردامنه‌ی طولانی)
    ("dnstt_burst_txt", lambda base: long_qname(base),  "TXT", BURST_QUERIES),
]
# ===========================================

def rand_label(n: int) -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(n))

def long_qname(base: str) -> str:
    # دو لیبل طولانی + base
    return f"{rand_label(LONG_LABEL_LEN)}.{rand_label(LONG_LABEL_LEN)}.{base}"

def dns_udp_query(server_ip: str, qname: str, qtype: str, timeout: float) -> Tuple[bool, Optional[float]]:
    """
    Returns (ok, latency_ms)
    ok = True only if NOERROR and at least 1 answer RRset exists
    """
    try:
        msg = dns.message.make_query(qname, qtype, want_dnssec=False)
        t0 = time.time()
        resp = dns.query.udp(msg, server_ip, timeout=timeout)
        latency_ms = (time.time() - t0) * 1000.0

        if resp.rcode() != dns.rcode.NOERROR:
            return (False, None)

        # dnspython: جواب‌ها داخل answer میاد؛
        # اگر خالی باشه یعنی عملاً چیزی برای استفاده نیست (برای dnstt معمولاً بد)
        if not resp.answer:
            return (False, None)

        return (True, round(latency_ms, 1))

    except (dns.exception.Timeout, OSError, dns.exception.DNSException):
        return (False, None)

def run_test(server_ip: str, test_name: str, qname: str, qtype: str, count: int) -> Dict:
    oks = 0
    lats: List[float] = []

    for _ in range(count):
        ok, lat = dns_udp_query(server_ip, qname, qtype, TIMEOUT)
        if ok and lat is not None:
            oks += 1
            lats.append(lat)

        time.sleep(random.uniform(*SLEEP_BETWEEN_QUERIES))

    rate = (oks / count) * 100.0
    avg = round(statistics.mean(lats), 1) if lats else None
    p95 = round(statistics.quantiles(lats, n=20)[-1], 1) if len(lats) >= 5 else None  # تقریبی

    return {
        "name": test_name,
        "qname": qname,
        "qtype": qtype,
        "count": count,
        "rate": round(rate, 1),
        "avg": avg,
        "p95": p95,
    }

def score_dns(test_results: Dict[str, Dict]) -> float:
    """
    Score lower is better.
    Penalize low min-rate heavily, penalize high latency, and penalize burst failure.
    """
    rates = [v["rate"] for v in test_results.values()]
    min_rate = min(rates)

    # میانگین latencyها (فقط مواردی که avg دارند)
    avgs = [v["avg"] for v in test_results.values() if v["avg"] is not None]
    avg_lat = statistics.mean(avgs) if avgs else 9999.0

    # burst اهمیت زیاد دارد
    burst_rate = test_results.get("dnstt_burst_txt", {}).get("rate", 0.0)

    penalty = (100.0 - min_rate) * 25.0
    burst_penalty = (100.0 - burst_rate) * 35.0

    return round(avg_lat + penalty + burst_penalty, 1)

def load_cidrs() -> List[str]:
    print("در حال بارگذاری لیست CIDR...")
    try:
        with open(CIDR_FILE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        cidrs = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        print(f"✓ لود شد {len(cidrs)} رنج CIDR")
        return random.sample(cidrs, min(MAX_CIDR_TO_SAMPLE, len(cidrs)))
    except Exception as e:
        print(f"خطا در لود CIDR: {e}")
        return []

def sample_ips(cidrs: List[str]) -> List[str]:
    print("در حال تولید IPها برای تست...")
    ips: List[str] = []
    for cidr_str in cidrs:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            hosts = list(net.hosts())
            if not hosts:
                continue
            sampled = random.sample(hosts, min(IPS_PER_CIDR, len(hosts)))
            ips.extend(str(ip) for ip in sampled)
        except Exception:
            pass
    random.shuffle(ips)
    print(f"→ {len(ips)} IP تولید شد")
    return ips

def test_dns_server(ip: str) -> Dict:
    test_results: Dict[str, Dict] = {}

    # 1) پیش‌فیلتر سریع: یک TXT ساده که recursive بودن رو مشخص کنه
    pre_ok, _ = dns_udp_query(ip, "whoami.cloudflare.com", "TXT", timeout=1.3)
    if not pre_ok:
        return {"ip": ip, "ok": False, "reason": "prefilter_fail", "score": 9999.0, "tests": {}}

    # 2) تست‌های اصلی
    for (name, builder, qtype, count) in TESTS:
        qname = builder(DNSTT_NS_DOMAIN)
        res = run_test(ip, name, qname, qtype, count)
        test_results[name] = res

    min_rate = min(v["rate"] for v in test_results.values())
    avgs = [v["avg"] for v in test_results.values() if v["avg"] is not None]
    overall_avg = round(statistics.mean(avgs), 1) if avgs else None

    score = score_dns(test_results)

    # معیار سلامت
    ok = (
        overall_avg is not None and
        overall_avg <= MAX_AVG_LATENCY and
        min_rate >= MIN_SUCCESS_RATE and
        test_results["dnstt_burst_txt"]["rate"] >= MIN_SUCCESS_RATE
    )

    return {
        "ip": ip,
        "ok": ok,
        "score": score,
        "avg_latency": overall_avg,
        "min_rate": min_rate,
        "tests": test_results
    }

def main():
    print(f"اسکن DNS برای dnstt → NS domain: {DNSTT_NS_DOMAIN}")
    print(f"MIN_SUCCESS_RATE={MIN_SUCCESS_RATE}%   MAX_AVG_LATENCY={MAX_AVG_LATENCY}ms")
    print(f"Workers={MAX_WORKERS}  Timeout={TIMEOUT}s\n")

    cidrs = load_cidrs()
    if not cidrs:
        print("لیست CIDR لود نشد. خروج.")
        sys.exit(1)

    ips = sample_ips(cidrs)
    if not ips:
        print("هیچ IP برای تست یافت نشد.")
        sys.exit(0)

    healthy: List[Dict] = []
    total = len(ips)
    done = 0

    print(f"شروع اسکن {total} IP...\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(test_dns_server, ip) for ip in ips]

        for fut in as_completed(futures):
            done += 1
            res = fut.result()

            if res.get("ok"):
                avg = res["avg_latency"]
                mark = "★★" if avg is not None and avg < 120 else "★" if avg is not None and avg < 200 else ""
                healthy.append(res)
                print(f"  {mark} {res['ip']:15}  score={res['score']:7.1f}  avg={avg:.1f}ms  min-rate={res['min_rate']:.1f}%")

            if done % 25 == 0:
                print(f"   پیشرفت: {done}/{total}   سالم: {len(healthy)}")

    print("\n" + "═" * 70)
    if not healthy:
        print("هیچ DNS مناسبی پیدا نشد.")
        print("پیشنهاد:")
        print(" - MIN_SUCCESS_RATE را به 80 کاهش بده")
        print(" - یا MAX_AVG_LATENCY را کمی بالاتر ببر")
        print(" - یا به جای اسکن CIDR، لیست واقعی resolverها رو تست کن")
        return

    healthy.sort(key=lambda x: x["score"])

    print(f"🏆 بهترین resolverها برای dnstt ({DNSTT_NS_DOMAIN})")
    for i, dnsr in enumerate(healthy[:8], 1):
        print(f"\n{i}. {dnsr['ip']:15}   score={dnsr['score']:.1f}   avg≈{dnsr['avg_latency']:.1f}ms   min-rate={dnsr['min_rate']:.1f}%")
        for tname in ["whoami_txt", "google_a", "dnstt_ns", "dnstt_long_txt", "dnstt_burst_txt"]:
            t = dnsr["tests"][tname]
            avg = f"{t['avg']:.1f}ms" if t["avg"] is not None else "FAIL"
            p95 = f"{t['p95']:.1f}ms" if t["p95"] is not None else "-"
            print(f"   • {tname:14} {t['qtype']:>3}  rate={t['rate']:>5.1f}%  avg={avg:>8}  p95={p95:>8}")

    best_ip = healthy[0]["ip"]
    print("\nدستور پیشنهادی dnstt-client (udp):")
    print(f"  dnstt-client -udp {best_ip}:53 -pubkey-file server.pub {DNSTT_NS_DOMAIN} 127.0.0.1:7000")
    print("\nاگر burst rate پایین بود یا قطع شد → IP بعدی رو تست کن.")

if __name__ == "__main__":
    main()
