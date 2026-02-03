#!/usr/bin/env python3
import asyncio
import csv
import ipaddress
import json
import random
import re
import ssl
import sys
import time
from typing import List, Tuple, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import socket
from contextlib import contextmanager

# ===== تنظیمات اصلی =====
TEST_HOST = "cloudflare.com"          # یا هر دامنه دیگری که بخواهید تست کنید
TEST_PATH = "/"
PORT = 443

SAMPLES_PER_CIDR_V4 = 80              # چون بعضی رنج‌ها خیلی بزرگ هستند → تعداد کمتر
SAMPLES_PER_CIDR_V6 = 20
INCLUDE_IPV6 = False                  # فعلاً False — اگر خواستید True کنید

CONCURRENCY = 120

PING_ENABLED = True
PING_TIMEOUT_MS = 900

TCP_TIMEOUT = 2.0
TLS_TIMEOUT = 3.0
READ_TIMEOUT = 4.0
READ_BYTES = 150_000

SEED = 7

TRY_INSECURE_TLS = True
# ========================

# ===== Cloudflare Auto DNS (برای آپدیت رکورد A) =====
CF_ENABLED = True

CF_API_TOKEN = ""          # ← اینجا توکن Cloudflare خودتان
CF_ZONE_ID = ""            # ← Zone ID دامنه
CF_RECORD_NAMES = [
    "cf-best.yourdomain.ir",
    # "speed.yourdomain.com",
]

CF_PROXIED = False         # اگر پروکسی کلادفلر (نارنجی) بخواهید True کنید
CF_TTL = 1                 # 1 = auto
# ===================================================

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"


@contextmanager
def force_ipv4_dns():
    old_getaddrinfo = socket.getaddrinfo
    def ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
        return old_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    socket.getaddrinfo = ipv4_only
    try:
        yield
    finally:
        socket.getaddrinfo = old_getaddrinfo


def fetch_cloudflare_ranges() -> Tuple[List[str], List[str]]:
    ipv4 = []
    ipv6 = []

    headers = {"User-Agent": "cloudflare-probe/1.0"}

    # IPv4
    try:
        req = Request(CLOUDFLARE_IPV4_URL, headers=headers)
        with urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8").strip()
            ipv4 = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"خطا در دریافت IPv4 از Cloudflare: {e}")
    
    # IPv6
    if INCLUDE_IPV6:
        try:
            req = Request(CLOUDFLARE_IPV6_URL, headers=headers)
            with urlopen(req, timeout=30) as r:
                text = r.read().decode("utf-8").strip()
                ipv6 = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"خطا در دریافت IPv6 از Cloudflare: {e}")

    if not ipv4:
        print("⚠️ دریافت لیست IPv4 ناموفق بود. از fallback استفاده می‌شود.")
        ipv4 = [
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "108.162.192.0/18",
            "131.0.72.0/22",
            "141.101.64.0/18",
            "162.158.0.0/15",
            "172.64.0.0/13",
            "173.245.48.0/20",
            "188.114.96.0/20",
            # می‌توانید بقیه را هم اضافه کنید اگر لازم بود
        ]

    return ipv4, ipv6


def sample_ips_from_cidr(cidr: str, k: int, seed: int = 0) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    rnd = random.Random(hash((cidr, seed)))
    num = net.num_addresses

    if num < 4:
        return [str(ip) for ip in net.hosts()]

    if isinstance(net, ipaddress.IPv4Network):
        first = int(net.network_address) + 1
        last = int(net.broadcast_address) - 1
        host_count = max(0, last - first + 1)
        k_eff = min(k, host_count)
        if k_eff == 0:
            return []
        picks = set()
        while len(picks) < k_eff:
            picks.add(first + rnd.randrange(host_count))
        return [str(ipaddress.IPv4Address(x)) for x in picks]

    # IPv6 یا موارد عمومی
    k_eff = min(k, num)
    base = int(net.network_address)
    picks = set()
    while len(picks) < k_eff:
        picks.add(base + rnd.randrange(num))
    return [str(ipaddress.ip_address(x)) for x in picks]


async def ping_latency_ms(ip: str, timeout_ms: int = 900) -> Optional[float]:
    is_windows = sys.platform.startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, int((timeout_ms + 999) / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await proc.communicate()
        if proc.returncode != 0:
            return None

        text = out.decode("utf-8", errors="ignore")

        m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", text, re.IGNORECASE)
        if m:
            return float(m.group(1))

        m = re.search(r"time[=<]\s*(\d+)\s*ms", text, re.IGNORECASE)
        if m:
            return float(m.group(1))

        return None
    except Exception:
        return None


async def tcp_connect_only(ip: str):
    t0 = time.time()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, PORT), timeout=TCP_TIMEOUT)
        ms = (time.time() - t0) * 1000
        writer.close()
        await writer.wait_closed()
        return True, round(ms, 1), ""
    except Exception as e:
        return False, None, str(e)


def make_ssl_ctx(insecure: bool):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def https_probe_and_speed(ip: str) -> dict:
    ok_tcp, tcp_ms, tcp_err = await tcp_connect_only(ip)
    if not ok_tcp:
        return {"ip": ip, "ok": False, "stage": "tcp", "connect_ms": None, "mbps": None, "http": None, "tls_mode": None, "ping_ms": None, "err": tcp_err}

    tls_mode = "verified"
    ctx = make_ssl_ctx(insecure=False)

    t0 = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=PORT, ssl=ctx, server_hostname=TEST_HOST),
            timeout=TLS_TIMEOUT
        )
        connect_ms = (time.time() - t0) * 1000
    except Exception as e_verified:
        if not TRY_INSECURE_TLS:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "verified", "ping_ms": None, "err": str(e_verified)}

        tls_mode = "insecure"
        ctx2 = make_ssl_ctx(insecure=True)
        t0b = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=ip, port=PORT, ssl=ctx2, server_hostname=TEST_HOST),
                timeout=TLS_TIMEOUT
            )
            connect_ms = (time.time() - t0b) * 1000
        except Exception as e_insecure:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "insecure", "ping_ms": None, "err": str(e_insecure)}

    try:
        req = (
            f"GET {TEST_PATH} HTTP/1.1\r\n"
            f"Host: {TEST_HOST}\r\n"
            f"User-Agent: cloudflare-probe/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("utf-8"))
        await writer.drain()

        head = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT)
        if not head:
            writer.close()
            return {"ip": ip, "ok": False, "stage": "read", "connect_ms": round(connect_ms, 1), "mbps": None, "http": None, "tls_mode": tls_mode, "ping_ms": None, "err": "no data"}

        http_code = None
        try:
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
            parts = first_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                http_code = int(parts[1])
        except:
            pass

        got = len(head)
        t1 = time.time()
        while got < READ_BYTES:
            chunk = await asyncio.wait_for(reader.read(16384), timeout=READ_TIMEOUT)
            if not chunk:
                break
            got += len(chunk)
        dt = time.time() - t1

        writer.close()
        await writer.wait_closed()

        mbps = 0.0 if dt <= 0 else (got * 8) / (dt * 1_000_000)

        out = {
            "ip": ip,
            "ok": True,
            "stage": "ok",
            "connect_ms": round(connect_ms, 1),
            "mbps": round(mbps, 2),
            "http": http_code,
            "tls_mode": tls_mode,
            "ping_ms": None,
            "err": ""
        }
        if tls_mode == "insecure":
            out["err"] = f"verified_tls_failed"
        return out

    except Exception as e:
        try:
            writer.close()
        except:
            pass
        return {"ip": ip, "ok": False, "stage": "read", "connect_ms": round(connect_ms, 1), "mbps": None, "http": None, "tls_mode": tls_mode, "ping_ms": None, "err": str(e)}


# ─────────────── Cloudflare DNS Update ───────────────
def cf_api_request(method: str, url: str, payload: Optional[dict] = None) -> dict:
    if not CF_API_TOKEN:
        raise RuntimeError("CF_API_TOKEN تنظیم نشده است.")
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "cloudflare-probe/1.0",
    }
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = Request(url, headers=headers, data=data, method=method)

    with force_ipv4_dns():
        try:
            with urlopen(req, timeout=12) as r:
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except:
                body = ""
            raise RuntimeError(f"Cloudflare API خطا {e.code}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"Cloudflare connection error: {e}") from e


def cf_delete_records_by_name(record_name: str):
    base = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    qurl = f"{base}?type=A&name={record_name}"
    res = cf_api_request("GET", qurl)
    if not res.get("success"):
        print(f"Cloudflare GET failed: {res.get('errors')}")
        return

    for it in res.get("result", []):
        rid = it.get("id")
        if rid:
            durl = f"{base}/{rid}"
            cf_api_request("DELETE", durl)
            print(f"🗑️ حذف رکورد قدیمی: {record_name}  id={rid}")


def cf_create_a_record(record_name: str, ip: str):
    base = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    payload = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": CF_TTL,
        "proxied": CF_PROXIED,
    }
    res = cf_api_request("POST", base, payload)
    if res.get("success"):
        print(f"✅ رکورد ساخته شد: {record_name} → {ip}  (proxied={CF_PROXIED})")
    else:
        print(f"Cloudflare POST failed: {res.get('errors')}")


def push_best_ip_to_cloudflare(best_ip: str):
    if not CF_ENABLED:
        return
    if not CF_ZONE_ID or not CF_API_TOKEN:
        print("⚠️ تنظیمات Cloudflare کامل نیست (TOKEN یا ZONE_ID خالی)")
        return

    for name in CF_RECORD_NAMES:
        cf_delete_records_by_name(name)
        cf_create_a_record(name, best_ip)


def pick_best(alive: List[dict]) -> Optional[dict]:
    if not alive:
        return None

    def key(x: dict):
        ping = x.get("ping_ms")
        conn = x.get("connect_ms")
        mbps = x.get("mbps") or 0.0
        ping_sort = ping if ping is not None else 99999
        conn_sort = conn if conn is not None else 99999
        if PING_ENABLED:
            return (ping_sort, -mbps, conn_sort)
        return (conn_sort, -mbps)

    return min(alive, key=key)


async def main():
    ipv4_cidrs, ipv6_cidrs = fetch_cloudflare_ranges()
    print(f"Cloudflare ranges → IPv4: {len(ipv4_cidrs)}   IPv6: {len(ipv6_cidrs)}")

    targets: List[str] = []
    for cidr in ipv4_cidrs:
        targets.extend(sample_ips_from_cidr(cidr, SAMPLES_PER_CIDR_V4, seed=SEED))

    if INCLUDE_IPV6:
        for cidr in ipv6_cidrs:
            targets.extend(sample_ips_from_cidr(cidr, SAMPLES_PER_CIDR_V6, seed=SEED))

    targets = sorted(set(targets))
    print(f"تعداد IP نمونه‌برداری شده: {len(targets):,}")

    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def worker(ip: str):
        async with sem:
            r = await https_probe_and_speed(ip)
            if r["ok"] and PING_ENABLED:
                r["ping_ms"] = await ping_latency_ms(ip, PING_TIMEOUT_MS)
            return r

    tasks = [asyncio.create_task(worker(ip)) for ip in targets]

    done = ok_count = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        done += 1
        if r["ok"]:
            ok_count += 1
            pm = r.get("ping_ms")
            pm_txt = f"{pm:.1f}ms" if pm is not None else "n/a"
            print(f'  ✓  {r["ip"]:15}  ping={pm_txt:>6}  tls={r["connect_ms"]:>5.1f}ms  {r["mbps"]:>5.1f}Mbps  http={r["http"]}')
        else:
            print(f'  ✗  {r["ip"]:15}  {r["stage"]}  {r["err"] or "unknown"}')

        if done % 150 == 0 or done == len(targets):
            print(f"پیشرفت: {done}/{len(targets)}   موفق={ok_count}")

    alive = [x for x in results if x["ok"]]

    with open("alive_cloudflare.txt", "w", encoding="utf-8") as f:
        for x in sorted(alive, key=lambda z: z.get("mbps", 0), reverse=True):
            pm = x.get("ping_ms")
            f.write(f'{x["ip"]}  ping={pm if pm else "n/a"}ms  tls={x["connect_ms"]}ms  {x["mbps"]}Mbps  http={x["http"]}\n')

    with open("cloudflare_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "ok", "stage", "tls_mode", "connect_ms", "ping_ms", "mbps", "http", "err"])
        w.writeheader()
        w.writerows(results)

    print("\nفایل‌ها ذخیره شدند:")
    print("  alive_cloudflare.txt")
    print("  cloudflare_results.csv")

    best = pick_best(alive)
    if not best:
        print("هیچ IP سالمی پیدا نشد. آپدیت Cloudflare انجام نشد.")
        return

    print("\nبهترین IP انتخاب شد:")
    pm = best.get("ping_ms")
    print(f'  IP   = {best["ip"]}')
    print(f'  ping = {pm if pm else "n/a"} ms')
    print(f'  tls  = {best["connect_ms"]:.1f} ms')
    print(f'  mbps = {best["mbps"]:.2f}')

    try:
        print("\nدر حال آپدیت رکورد(های) Cloudflare ...")
        await asyncio.to_thread(push_best_ip_to_cloudflare, best["ip"])
        print("آپدیت Cloudflare با موفقیت انجام شد.")
    except Exception as e:
        print(f"خطا در آپدیت Cloudflare: {e}")


if __name__ == "__main__":
    asyncio.run(main())
