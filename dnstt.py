#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اسکنر DNS ایران برای dnstt - دامنه NS: dnt.moonlightx.ir
- لیست CIDR از: https://github.com/MortezaBashsiz/dnsScanner
- فقط resolverهای سالم و سریع داخل ایران
- مناسب Termux (کم مصرف)
"""

import subprocess
import time
import sys
import random
import requests
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import statistics
import shutil

# ================= تنظیمات =================
DNSTT_NS_DOMAIN = "dnt.moonlightx.ir"   # دامنه NS که می‌خوای تست کنی

TEST_DOMAINS = [
    DNSTT_NS_DOMAIN,           # مهم‌ترین: باید resolve بشه
    "whoami.cloudflare.com",   # چک resolver واقعی
    "www.google.com",          # دسترسی خارجی
]

QUERIES_PER_DNS = 10           # تعداد query (برای dnstt مهم است پایدار باشه)
TIMEOUT = 3.5                  # ثانیه
MAX_WORKERS = 25               # مناسب Termux - بیشتر ممکنه هنگ کنه

MIN_SUCCESS_RATE = 85.0        # حداقل درصد موفقیت (dnstt حساس است)
MAX_AVG_LATENCY = 280.0        # ms - بالاتر معمولاً برای تونل بد است

CIDR_SOURCE_URL = "https://raw.githubusercontent.com/MortezaBashsiz/dnsScanner/refs/heads/main/python/iran-ipv4.cidrs"

MAX_CIDR_TO_SAMPLE = 300       # حداکثر رنج‌هایی که نمونه‌برداری کنیم
IPS_PER_CIDR = 5               # چند IP تصادفی از هر رنج

# ===========================================

def has_dig() -> bool:
    return shutil.which("dig") is not None

def run(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, check=False)
    except:
        return subprocess.CompletedProcess(cmd, 1, "", "error")

def dig_query(domain: str, dns_ip: str) -> Optional[float]:
    t0 = time.time()
    try:
        p = run(["dig", f"@{dns_ip}", domain, "+short", "+timeout=2"], timeout=TIMEOUT)
        latency = (time.time() - t0) * 1000
        if p.returncode == 0:
            return round(latency, 1)
        return None
    except:
        return None

def test_dns(dns_ip: str) -> Dict:
    results = {}
    success_count = 0
    latencies = []

    for domain in TEST_DOMAINS:
        dom_success = 0
        dom_lats = []
        for _ in range(QUERIES_PER_DNS):
            lat = dig_query(domain, dns_ip)
            if lat is not None:
                dom_lats.append(lat)
                latencies.append(lat)
                dom_success += 1
            time.sleep(random.uniform(0.05, 0.15))

        rate = (dom_success / QUERIES_PER_DNS) * 100
        results[domain] = {"rate": round(rate, 1), "avg": round(statistics.mean(dom_lats), 1) if dom_lats else None}

        if rate >= MIN_SUCCESS_RATE:
            success_count += 1

    overall_rate = (success_count / len(TEST_DOMAINS)) * 100
    if latencies and overall_rate >= MIN_SUCCESS_RATE:
        avg_lat = statistics.mean(latencies)
        penalty = (100 - min(d["rate"] for d in results.values())) * 1.2
        score = round(avg_lat + penalty, 1)
    else:
        score = 9999.0

    return {
        "ip": dns_ip,
        "score": score,
        "avg_latency": round(statistics.mean(latencies), 1) if latencies else None,
        "min_rate": min(d["rate"] for d in results.values()),
        "results": results
    }

def load_cidrs() -> List[str]:
    try:
        r = requests.get(CIDR_SOURCE_URL, timeout=15)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        cidrs = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        print(f"✓ لود شد {len(cidrs)} رنج CIDR ایران")
        return random.sample(cidrs, min(MAX_CIDR_TO_SAMPLE, len(cidrs)))
    except Exception as e:
        print(f"خطا در لود لیست CIDR: {e}")
        return []

def sample_ips(cidrs: List[str]) -> List[str]:
    ips = []
    for cidr_str in cidrs:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            hosts = list(net.hosts())
            if hosts:
                sampled = random.sample(hosts, min(IPS_PER_CIDR, len(hosts)))
                ips.extend(str(ip) for ip in sampled)
        except:
            pass
    random.shuffle(ips)
    print(f"→ {len(ips)} IP برای تست تولید شد")
    return ips

def main():
    if not has_dig():
        print("❗ dig پیدا نشد")
        print("   در Termux بزن:")
        print("      pkg update && pkg install dnsutils")
        sys.exit(1)

    print(f"اسکن DNSهای ایران برای dnstt → NS: {DNSTT_NS_DOMAIN}")
    print(f"   تست روی: {', '.join(TEST_DOMAINS)}")
    print(f"   حداقل success: {MIN_SUCCESS_RATE}%   max avg latency: {MAX_AVG_LATENCY}ms\n")

    cidrs = load_cidrs()
    if not cidrs:
        print("لیست CIDR لود نشد. برنامه متوقف می‌شود.")
        sys.exit(1)

    test_ips = sample_ips(cidrs)

    healthy: List[Dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_dns, ip) for ip in test_ips]

        done = 0
        total = len(test_ips)

        for future in as_completed(futures):
            done += 1
            res = future.result()
            ip = res["ip"]
            score = res["score"]
            avg = res["avg_latency"]

            if score < 800 and avg is not None and avg <= MAX_AVG_LATENCY and res["min_rate"] >= MIN_SUCCESS_RATE:
                healthy.append(res)
                mark = "★★" if avg < 120 else "★" if avg < 200 else ""
                print(f"  {mark} {ip:15}   score={score:5.1f}   avg={avg:.1f}ms   min-rate={res['min_rate']:.1f}%")

            if done % 20 == 0:
                print(f"   پیشرفت: {done}/{total}   سالم پیدا شده: {len(healthy)}")

    print("\n" + "═" * 60)

    if not healthy:
        print("هیچ DNS مناسبی پیدا نشد.")
        print("پیشنهاد: MIN_SUCCESS_RATE را به 80 یا کمتر کاهش بده و دوباره اجرا کن.")
        return

    healthy.sort(key=lambda x: x["score"])

    print(f"🏆 بهترین DNS resolverها برای اتصال به dnstt ({DNSTT_NS_DOMAIN})")
    print("   (به ترتیب امتیاز - پایین‌تر بهتر)")

    for i, dns in enumerate(healthy[:8], 1):
        print(f"\n{i}. {dns['ip']:15}   score = {dns['score']:5.1f}ms")
        print(f"     avg latency ≈ {dns['avg_latency']:.1f}ms   success ≥ {dns['min_rate']:.1f}%")
        for dom, data in dns["results"].items():
            print(f"       • {dom:25} {data['avg'] if data['avg'] else 'FAIL':>6}ms ({data['rate']}%)")

    print("\nدستور پیشنهادی dnstt-client (udp ساده):")
    if healthy:
        best_ip = healthy[0]["ip"]
        print(f"   dnstt-client -udp {best_ip}:53 -pubkey-file server.pub {DNSTT_NS_DOMAIN} 127.0.0.1:7000")
        print("   (server.pub را از صاحب سرور بگیر)")

    print("\nاگر rate-limit شدید دیدی → IP بعدی را امتحان کن یا تعداد query را کم کن.")

if __name__ == "__main__":
    main()
