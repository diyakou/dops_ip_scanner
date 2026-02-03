#!/usr/bin/env python3
import subprocess
import time
import sys
from typing import Optional, List, Tuple, Dict

# ================= تنظیمات =================
TEST_DOMAIN_1 = "server-fastly.morvism.ir"  # ساب‌دامنه‌ی شما
TEST_DOMAIN_2 = "chatgpt.com"            # تست سلامت DNS با کلادفلر (می‌تونی one.one.one.one هم بذاری)

TIMEOUT = 2.8   # ثانیه برای هر nslookup
REPEAT = 2      # تعداد تکرار برای میانگین
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
    ("Gmaing DNS 11", "185.213.182.126"), ("Gmaing DNS 11", "185.43.135.1"),
    ("Gmaing DNS 12", "199.85.127.10"), ("Gmaing DNS 12", "185.231.182.126"),
    ("Gmaing DNS 13", "91.239.100.100"), ("Gmaing DNS 13", "37.152.182.112"),
    ("Gmaing DNS 14", "8.26.56.26"), ("Gmaing DNS 14", "8.20.247.20"),
    ("Gmaing DNS 15", "78.157.42.100"), ("Gmaing DNS 15", "1.1.1.1"),
    ("Gmaing DNS 16", "87.135.66.81"), ("Gmaing DNS 16", "76.76.10.4"),

    ("مخابرات/شاتل/آسیاتک/رایتل", "91.239.100.100"), ("مخابرات/شاتل/آسیاتک/رایتل", "89.233.43.71"),
    ("پارس آنلاین", "46.224.1.221"), ("پارس آنلاین", "46.224.1.220"),
    ("همراه اول", "208.67.220.200"), ("همراه اول", "208.67.222.222"),
    ("ایرانسل", "109.69.8.51"), ("ایرانسل", "0.0.0.0"),
    ("ایرانسل", "74.82.42.42"), ("ایرانسل", "0.0.0.0"),
    ("مخابرات", "8.8.8.8"), ("مخابرات", "8.8.4.4"),
    ("مخابرات", "4.4.4.4"), ("مخابرات", "4.2.2.4"),
    ("مخابرات", "195.46.39.39"), ("مخابرات", "195.46.39.40"),
    ("مبین نت", "10.44.8.8"), ("مبین نت", "8.8.8.8"),
    ("سایر اپراتورها", "199.85.127.10"), ("سایر اپراتورها", "199.85.126.10"),
    ("سوئیس", "176.10.118.132"), ("سوئیس", "176.10.118.133"),
    ("کویت", "94.187.170.2"), ("کویت", "94.187.170.3"),
    ("اسپانیا", "195.235.194.7"), ("اسپانیا", "195.235.194.8"),
    ("تاجیکستان", "45.81.37.0"), ("تاجیکستان", "45.81.37.1"),
]

def run(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)

def has_cmd(name: str) -> bool:
    return subprocess.call(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"]) == 0

def systemd_resolved_active() -> bool:
    p = run(["bash", "-lc", "systemctl is-active systemd-resolved"], timeout=2.0)
    return p.stdout.strip() == "active"

def get_default_iface() -> str:
    p = run(["bash", "-lc", "ip route show default | awk '{print $5}' | head -n1"])
    return (p.stdout or "").strip() or "eth0"

def normalize_dns_list(raw: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
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

def nslookup_latency_ms(domain: str, dns_ip: str) -> Optional[float]:
    """
    با nslookup فقط با همین DNS تست می‌کند.
    اگر resolve موفق نبود -> None
    """
    total = 0.0
    ok = 0
    for _ in range(REPEAT):
        t0 = time.time()
        try:
            p = run(["nslookup", domain, dns_ip], timeout=TIMEOUT)
            if p.returncode == 0:
                total += (time.time() - t0) * 1000
                ok += 1
        except subprocess.TimeoutExpired:
            pass
    if ok == 0:
        return None
    return round(total / ok, 1)

def score_dns(dns_ip: str) -> Optional[Tuple[float, float, float]]:
    """
    باید هر دو دامنه resolve شوند.
    خروجی: (score, lat1, lat2) - هرچی score کمتر بهتر
    """
    lat1 = nslookup_latency_ms(TEST_DOMAIN_1, dns_ip)
    if lat1 is None:
        return None
    lat2 = nslookup_latency_ms(TEST_DOMAIN_2, dns_ip)
    if lat2 is None:
        return None

    # امتیاز: میانگین دو latency (می‌تونی وزن بدی)
    score = round((lat1 + lat2) / 2.0, 1)
    return score, lat1, lat2

def apply_dns_ubuntu(dns_ip: str):
    """
    ست کردن پایدار DNS روی اوبونتو:
    - اگر systemd-resolved فعال بود: resolvectl
    - اگر NetworkManager بود: nmcli
    - fallback: /etc/resolv.conf
    """
    if has_cmd("resolvectl") and systemd_resolved_active():
        iface = get_default_iface()
        # DNS روی اینترفیس پیش‌فرض
        p1 = run(["bash", "-lc", f"resolvectl dns {iface} {dns_ip}"])
        if p1.returncode != 0:
            raise RuntimeError(p1.stderr.strip() or "resolvectl dns failed")

        # دامنه‌ها رو route کن روی همین لینک (اختیاری ولی مفید)
        run(["bash", "-lc", f"resolvectl domain {iface} '~.'"])
        run(["bash", "-lc", "resolvectl flush-caches"])
        print(f"✅ Applied via systemd-resolved on {iface}: DNS={dns_ip}")
        return

    if has_cmd("nmcli"):
        # کانکشن فعال
        p = run(["bash", "-lc", "nmcli -t -f NAME,DEVICE c show --active | head -n1"])
        line = (p.stdout or "").strip()
        if not line:
            raise RuntimeError("No active NetworkManager connection found.")
        conn = line.split(":")[0]

        p2 = run(["bash", "-lc", f"nmcli c modify '{conn}' ipv4.dns '{dns_ip}' ipv4.ignore-auto-dns yes"])
        if p2.returncode != 0:
            raise RuntimeError(p2.stderr.strip() or "nmcli modify failed")

        run(["bash", "-lc", f"nmcli c down '{conn}' && nmcli c up '{conn}'"])
        print(f"✅ Applied via NetworkManager: {conn} DNS={dns_ip}")
        return

    # fallback
    p3 = run(["bash", "-lc", f"printf 'nameserver {dns_ip}\n' > /etc/resolv.conf"])
    if p3.returncode != 0:
        raise RuntimeError(p3.stderr.strip() or "write /etc/resolv.conf failed")
    print(f"✅ Applied by writing /etc/resolv.conf (may be overwritten): DNS={dns_ip}")

def main():
    if getattr(os := __import__("os"), "geteuid", lambda: 1)() != 0:
        print("❗ لطفاً با sudo اجرا کن: sudo python3 dns_scan_apply.py")
        sys.exit(1)

    if not has_cmd("nslookup"):
        print("❗ nslookup پیدا نشد. نصب کن: sudo apt install -y dnsutils")
        sys.exit(1)

    dns_list = normalize_dns_list(RAW_DNS_LIST)

    print(f"🌐 DNS Scan (must resolve BOTH):")
    print(f"  1) {TEST_DOMAIN_1}")
    print(f"  2) {TEST_DOMAIN_2}\n")

    results: List[Tuple[float, str, str, float, float]] = []
    for name, ip in dns_list:
        s = score_dns(ip)
        if s is None:
            print(f"❌ {name:<28} {ip:<15} FAIL (one of domains didn't resolve)")
            continue
        score, lat1, lat2 = s
        print(f"✅ {name:<28} {ip:<15} score={score}ms  {TEST_DOMAIN_1}={lat1}ms  {TEST_DOMAIN_2}={lat2}ms")
        results.append((score, name, ip, lat1, lat2))

    if not results:
        print("\n⚠️ هیچ DNSی پیدا نشد که هر دو دامنه رو درست Resolve کنه.")
        sys.exit(2)

    best = sorted(results, key=lambda x: x[0])[0]
    score, name, ip, lat1, lat2 = best

    print("\n🏆 Best DNS Selected")
    print(f"{name} → {ip}")
    print(f"score={score}ms | {TEST_DOMAIN_1}={lat1}ms | {TEST_DOMAIN_2}={lat2}ms\n")

    apply_dns_ubuntu(ip)

    # ✅ Verify after apply (optional but useful)
    print("\n🔎 Verify with system DNS (after apply):")
    v1 = nslookup_latency_ms(TEST_DOMAIN_1, ip)
    v2 = nslookup_latency_ms(TEST_DOMAIN_2, ip)
    print(f"  {TEST_DOMAIN_1}: {'OK ' + str(v1)+'ms' if v1 is not None else 'FAIL'}")
    print(f"  {TEST_DOMAIN_2}: {'OK ' + str(v2)+'ms' if v2 is not None else 'FAIL'}")

    if has_cmd("resolvectl"):
        print("\n(resolvectl status excerpt)")
        p = run(["bash", "-lc", "resolvectl status | sed -n '1,120p'"])
        print((p.stdout or "").strip())

if __name__ == "__main__":
    main()
