#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اسکنر DNS ایران برای dnstt - استفاده از لیست CIDR ایران
- لود لیست CIDR از URL یا فایل
- انتخاب تصادفی IP از هر CIDR (برای جلوگیری از اسکن خیلی زیاد)
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

# ================= تنظیمات =================
TEST_DOMAINS = [
    "dnt.moonlightx.",     # خوب برای چک resolver واقعی
    "www.google.com",ir
    "dns.google",                # تست بیشتر
]

QUERIES_PER_DNS = 15             # کمتر از قبل برای سرعت بیشتر (dnstt نیاز به پایداری دارد)
TIMEOUT = 3.0
MAX_WORKERS = 50

MIN_SUCCESS_RATE = 90.0          # سخت‌گیرانه برای dnstt
MAX_AVG_LATENCY = 300.0          # ms

# منبع لیست CIDR ایران (بهترین گزینه aggregated)
CIDR_SOURCE_URL = "https://raw.githubusercontent.com/MortezaBashsiz/dnsScanner/refs/heads/main/python/iran-ipv4.cidrs"
# اگر آفلاین هستید → فایل محلی بگذارید مثلاً: CIDR_FILE = "iran-ipv4.cidrs"

MAX_CIDR_TO_SAMPLE = 300         # حداکثر تعداد CIDR که از لیست استفاده کنیم
IPS_PER_CIDR = 6                 # چند IP تصادفی از هر CIDR تست شود

# ===========================================

def run(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, check=False)
    except:
        return subprocess.CompletedProcess(cmd, 1, "", "error")


def has_dig() -> bool:
    return subprocess.run(["which", "dig"], stdout=subprocess.DEVNULL).returncode == 0


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


def test_dns(dns_ip: str, domains: List[str]) -> Dict:
    results = {}
    for domain in domains:
        latencies = []
        success = 0
        for _ in range(QUERIES_PER_DNS):
            lat = dig_query(domain, dns_ip)
            if lat is not None:
                latencies.append(lat)
                success += 1
            time.sleep(random.uniform(0.04, 0.12))  # jitter برای شبیه‌سازی واقعی

        rate = (success / QUERIES_PER_DNS) * 100
        stat = {
            "rate": round(rate, 1),
            "avg": round(statistics.mean(latencies), 1) if latencies else None,
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
        }
        results[domain] = stat

    min_rate = min(d["rate"] for d in results.values())
    if min_rate >= MIN_SUCCESS_RATE and results:
        avg_lat = statistics.mean(d["avg"] for d in results.values() if d["avg"] is not None)
        score = round(avg_lat + (100 - min_rate) * 1.5, 1)
    else:
        score = 9999.0

    return {"ip": dns_ip, "results": results, "score": score, "min_rate": min_rate}


def load_cidrs_from_url(url: str) -> List[str]:
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        cidrs = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        print(f"✓ لود شد: {len(cidrs)} رنج CIDR از {url}")
        return cidrs[:MAX_CIDR_TO_SAMPLE]  # محدود کردن برای سرعت
    except Exception as e:
        print(f"خطا در لود URL: {e}")
        return []


def sample_ips_from_cidrs(cidrs: List[str]) -> List[str]:
    all_ips = []
    for cidr_str in cidrs:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            hosts = list(net.hosts())
            if not hosts:
                continue
            sampled = random.sample(hosts, min(IPS_PER_CIDR, len(hosts)))
            all_ips.extend(str(ip) for ip in sampled)
        except:
            pass
    random.shuffle(all_ips)
    print(f"→ تولید {len(all_ips)} IP نمونه برای تست")
    return all_ips


def main():
    if not has_dig():
        print("dig نصب نیست → sudo apt install dnsutils")
        sys.exit(1)

    print("اسکنر DNS ایران برای dnstt")
    print(f"   منبع CIDR: {CIDR_SOURCE_URL}")
    print(f"   تست‌ها: {QUERIES_PER_DNS} query   حداقل success: {MIN_SUCCESS_RATE}%   max avg: {MAX_AVG_LATENCY}ms\n")

    cidrs = load_cidrs_from_url(CIDR_SOURCE_URL)
    if not cidrs:
        print("هیچ CIDRی لود نشد. اسکریپت متوقف می‌شود.")
        sys.exit(1)

    test_ips = sample_ips_from_cidrs(cidrs)

    healthy = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(test_dns, ip, TEST_DOMAINS) for ip in test_ips]

        done = 0
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            ip = res["ip"]
            score = res["score"]
            avg = statistics.mean(d["avg"] for d in res["results"].values() if d["avg"] is not None) if res["results"] else 999

            if score < 9000 and avg <= MAX_AVG_LATENCY and res["min_rate"] >= MIN_SUCCESS_RATE:
                healthy.append(res)
                print(f"  ✓ {ip:15}   score={score:5.1f}   avg={avg:.1f}ms   rate≥{res['min_rate']:.1f}%")
            elif done % 20 == 0:
                print(f"  - {ip:15}   rate={res['min_rate']:.1f}%   avg={avg:.1f}ms")

            if done % 40 == 0:
                print(f"پیشرفت: {done}/{len(test_ips)}")

    print("\n" + "═"*70)
    if not healthy:
        print("هیچ resolver خوبی پیدا نشد. معیارها را شل‌تر کنید یا لیست CIDR را چک کنید.")
        return

    healthy.sort(key=lambda x: x["score"])

    print(f"🏆 بهترین‌ها برای dnstt (top {min(10, len(healthy))})")
    for i, dns in enumerate(healthy[:10], 1):
        avg = statistics.mean(d["avg"] for d in dns["results"].values() if d["avg"] is not None)
        mr = min(d["rate"] for d in dns["results"].values())
        print(f"{i:2}. {dns['ip']:15}   score={dns['score']:5.1f}ms   avg≈{avg:.1f}ms   success≥{mr:.1f}%")

    print("\nنکته: ۲–۴ تای اول را در dnstt-client تست کنید (معمولاً udp/53):")
    print(f"   dnstt-client -udp {healthy[0]['ip']}:53   ...")
    print("اگر زود rate-limit خورد → IP بعدی را امتحان کنید.")


if __name__ == "__main__":
    main()
