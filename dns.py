#!/usr/bin/env python3
"""
🚀 DNS Parallel Tester - بهتری‌های فعلی:
- Parallel testing (همزمان تست چند DNS)
- dig استفاده (بهتر از nslookup)
- Success rate tracking
- Min/Max/Avg latency
- Better scoring system
"""
import subprocess
import time
import sys
from typing import Optional, List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

# ================= تنظیمات =================
TEST_DOMAINS = [
    "ar1.kingv2.com",  # ساب‌دامنه شما
    "chatgpt.com",               # دسترسی بیرونی
    "google.com",                # تست اضافی
]

TIMEOUT = 2.8          # ثانیه برای هر dig query
QUERIES_PER_DNS = 5    # تعداد query برای محاسبه reliability
MAX_WORKERS = 15       # تعداد parallel workers
# ===========================================

RAW_DNS_LIST = [
    ("رادار", "10.202.10.10"), ("رادار", "10.202.10.11"),
    ("سرویس 403", "10.202.10.202"), ("سرویس 403", "10.202.10.102"),
    ("بگذر", "185.55.226.26"), ("بگذر", "185.55.225.25"),
    ("شکن", "178.22.122.100"), ("شکن", "185.51.200.2"),
    ("شاتل", "85.15.1.14"), ("شاتل", "85.15.1.15"),
    ("الکترو", "78.157.42.100"), ("الکترو", "78.157.42.101"),
    ("هاستیران", "172.29.2.100"), ("هاستیران", "172.29.2.100"),

    ("Server ir", "194.104.158.48"), ("Server ir", "194.104.158.78"),
    ("Level3", "209.244.0.3"), ("Level3", "209.244.0.4"),
    ("OpenDNS", "208.67.222.222"), ("OpenDNS", "208.67.220.220"),

    ("Gmaing DNS 1", "78.157.42.100"), ("Gmaing DNS 1", "185.43.135.1"),
    ("Gmaing DNS 2", "156.154.70.1"), ("Gmaing DNS 2", "156.154.71.1"),
    ("Gmaing DNS 3", "149.112.112.112"), ("Gmaing DNS 3", "149.112.112.10"),
    ("Gmaing DNS 4", "185.108.22.133"), ("Gmaing DNS 4", "185.108.22.134"),
    ("Gmaing DNS 5", "85.214.41.206"), ("Gmaing DNS 5", "89.15.250.41"),
    ("Gmaing DNS 6", "9.9.9.9"), ("Gmaing DNS 6", "109.69.8.51"),
    ("Gmaing DNS 7", "8.26.56.26"), ("Gmaing DNS 7", "8.26.247.20"),
    ("Gmaing DNS 8", "185.121.177.177"), ("Gmaing DNS 8", "169.239.202.202"),
    ("Gmaing DNS 9", "185.231.182.126"), ("Gmaing DNS 9", "185.43.135.1"),
    ("Gmaing DNS 10", "185.43.135.1"), ("Gmaing DNS 10", "46.16.216.25"),
    ("مخابرات/شاتل/آسیاتک/رایتل", "91.239.100.100"), ("مخابرات/شاتل/آسیاتک/رایتل", "89.233.43.71"),
    ("پارس آنلاین", "46.224.1.221"), ("پارس آنلاین", "46.224.1.220"),
    ("همراه اول", "208.67.220.200"), ("همراه اول", "208.67.222.222"),
    ("ایرانسل", "109.69.8.51"), ("ایرانسل", "74.82.42.42"),
    ("مخابرات", "8.8.8.8"), ("مخابرات", "8.8.4.4"),
    ("مخابرات", "4.4.4.4"), ("مخابرات", "4.2.2.4"),
    ("مخابرات", "195.46.39.39"), ("مخابرات", "195.46.39.40"),
    ("مبین نت", "10.44.8.8"), ("مبین نت", "8.8.8.8"),
    ("سایر اپراتورها", "199.85.127.10"), ("سایر اپراتورها", "199.85.126.10"),
]

def run(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    """اجرای subprocess"""
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="timeout")

def has_cmd(name: str) -> bool:
    """چک کردن وجود command"""
    p = subprocess.run(["which", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode == 0

def normalize_dns_list(raw: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """حذف تکراری‌ها و IP‌های خاطی"""
    seen = set()
    out = []
    for name, ip in raw:
        ip = ip.strip()
        if ip == "0.0.0.0" or not ip:
            continue
        key = (name.strip(), ip)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out

def dig_query(domain: str, dns_ip: str) -> Optional[float]:
    """
    تست یک domain روی یک DNS server با dig
    خروجی: latency in ms (None = fail)
    """
    t0 = time.time()
    try:
        p = run(["dig", f"@{dns_ip}", domain, "+short", "+timeout=2"], timeout=TIMEOUT)
        latency = (time.time() - t0) * 1000
        
        # اگر dig خود جواب داده (حتی اگر خالی باشد = NODATA = موفق)
        if p.returncode == 0 and p.stdout.strip():
            return round(latency, 1)
        # NODATA یا NXDOMAIN - depends on what we'relooking for
        # اگه خالی بود = NODATA که باعث میشه return None (fail)
        return None
    except Exception:
        return None

def test_dns_reliable(dns_ip: str, domains: List[str]) -> Dict[str, any]:
    """
    تست یک DNS روی چند دامنه و چند بار
    خروجی: {domain: [latencies...], success_rate, avg_latency, min, max}
    """
    results = {}
    for domain in domains:
        latencies = []
        for _ in range(QUERIES_PER_DNS):
            lat = dig_query(domain, dns_ip)
            if lat is not None:
                latencies.append(lat)
        
        if latencies:
            results[domain] = {
                "latencies": latencies,
                "success": len(latencies),
                "total": QUERIES_PER_DNS,
                "rate": round((len(latencies) / QUERIES_PER_DNS) * 100, 0),
                "avg": round(statistics.mean(latencies), 1),
                "min": round(min(latencies), 1),
                "max": round(max(latencies), 1),
                "stdev": round(statistics.stdev(latencies), 1) if len(latencies) > 1 else 0,
            }
        else:
            results[domain] = {
                "latencies": [],
                "success": 0,
                "total": QUERIES_PER_DNS,
                "rate": 0,
                "avg": None,
                "min": None,
                "max": None,
                "stdev": 0,
            }
    
    return results

def compute_dns_score(results: Dict[str, any]) -> Optional[float]:
    """
    محاسبه امتیاز کل یک DNS
    - اگر حتی یک دامنه fail شد -> None (disqualified)
    - درغیر اینصورت: میانگین latency + penalty برای کم‌تر از 100% success
    """
    all_avgs = []
    worst_rate = 100
    
    for domain, data in results.items():
        if data["rate"] < 100:
            worst_rate = min(worst_rate, data["rate"])
        
        if data["avg"] is None:
            return None  # disqualify if any domain fails completely
        
        all_avgs.append(data["avg"])
    
    # امتیاز پایه: میانگین latency
    base_score = statistics.mean(all_avgs)
    
    # Penalty برای کم‌تر از 100% success
    penalty = (100 - worst_rate) * 0.5  # هر 1% کم = 0.5ms penalty
    
    final_score = base_score + penalty
    return round(final_score, 1)

def apply_dns_ubuntu(dns_ip: str):
    """ست کردن DNS روی اوبونتو"""
    try:
        if has_cmd("resolvectl"):
            # systemd-resolved
            p = run(["bash", "-lc", f"sudo resolvectl dns $(ip route show default | awk '{{print $5}}' | head -n1) {dns_ip}"])
            if p.returncode == 0:
                run(["bash", "-lc", "sudo resolvectl flush-caches"])
                print(f"✅ Applied via systemd-resolved: DNS={dns_ip}")
                return
        
        if has_cmd("nmcli"):
            # NetworkManager
            p = run(["bash", "-lc", "sudo nmcli c modify $(nmcli -t -f NAME,DEVICE c show --active | head -n1 | cut -d: -f1) ipv4.dns '{dns_ip}' ipv4.ignore-auto-dns yes && nmcli c up $(nmcli -t -f NAME c show --active | head -n1)"])
            if p.returncode == 0:
                print(f"✅ Applied via NetworkManager: DNS={dns_ip}")
                return
        
        # Fallback
        run(["bash", "-lc", f"echo 'nameserver {dns_ip}' | sudo tee /etc/resolv.conf"])
        print(f"✅ Applied via /etc/resolv.conf (may be overwritten): DNS={dns_ip}")
    except Exception as e:
        print(f"⚠️ Failed to apply DNS: {e}")

def main():
    import os
    if os.geteuid() != 0:
        print("❗ لطفاً با sudo اجرا کن: sudo python3 dns_tester_new.py")
        sys.exit(1)
    
    if not has_cmd("dig"):
        print("❗ dig پیدا نشد. نصب کن: sudo apt install -y dnsutils")
        sys.exit(1)
    
    dns_list = normalize_dns_list(RAW_DNS_LIST)
    
    print(f"🌐 Parallel DNS Test ({MAX_WORKERS} workers)")
    print(f"📋 Domains: {', '.join(TEST_DOMAINS)}")
    print(f"🔄 Queries: {QUERIES_PER_DNS} per DNS\n")
    
    results_all: List[Tuple[float, str, str, Dict]] = []
    
    # Parallel testing با ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_dns_reliable, ip, TEST_DOMAINS): (name, ip)
            for name, ip in dns_list
        }
        
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            name, ip = futures[future]
            
            try:
                test_results = future.result()
                score = compute_dns_score(test_results)
                
                if score is not None:
                    results_all.append((score, name, ip, test_results))
                    
                    # نمایش خاص
                    details = " | ".join([
                        f"{d}={test_results[d]['avg']}ms({test_results[d]['rate']:.0f}%)"
                        for d in TEST_DOMAINS
                    ])
                    print(f"✅ {name:<30} {ip:<15} score={score}ms  {details}")
                else:
                    print(f"❌ {name:<30} {ip:<15} FAIL (one of domains didn't resolve)")
            
            except Exception as e:
                name_info = futures[future]
                print(f"❌ Error testing {name_info}: {e}")
            
            if done_count % 10 == 0:
                print(f"   Progress: {done_count}/{len(dns_list)}")
    
    if not results_all:
        print("\n⚠️ هیچ DNSی پیدا نشد.")
        sys.exit(2)
    
    # مرتب‌سازی و انتخاب برتر
    results_all.sort(key=lambda x: x[0])
    
    print("\n" + "="*80)
    print("🏆 TOP 3 BEST DNS:")
    print("="*80)
    
    for idx, (score, name, ip, test_results) in enumerate(results_all[:3], 1):
        print(f"\n#{idx}. {name} → {ip}")
        print(f"   Score: {score}ms")
        for domain in TEST_DOMAINS:
            data = test_results[domain]
            if data["avg"] is not None:
                print(f"   • {domain:<30} avg={data['avg']}ms  min={data['min']}ms  max={data['max']}ms  rate={data['rate']:.0f}%  stdev={data['stdev']}ms")
            else:
                print(f"   • {domain:<30} FAILED")
    
    # انتخاب برترین
    best_score, best_name, best_ip, best_results = results_all[0]
    
    print("\n" + "="*80)
    print(f"✅ SELECTED: {best_name} → {best_ip} (score={best_score}ms)")
    print("="*80)
    
    # ست کردن
    try:
        apply_dns_ubuntu(best_ip)
    except Exception as e:
        print(f"⚠️ Failed to apply: {e}")
    
    # Verify
    print("\n🔎 Final Verification (5 queries):")
    verify_results = test_dns_reliable(best_ip, TEST_DOMAINS)
    for domain in TEST_DOMAINS:
        data = verify_results[domain]
        if data["avg"] is not None:
            print(f"   ✅ {domain}: {data['avg']}ms (success={data['rate']:.0f}%)")
        else:
            print(f"   ❌ {domain}: FAILED")

if __name__ == "__main__":
    main()
