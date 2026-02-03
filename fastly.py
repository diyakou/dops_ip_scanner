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
FASTLY_IP_LIST_URL = "https://api.fastly.com/public-ip-list"

# ===== تنظیمات اصلی =====
TEST_HOST = "www.github.com"
TEST_PATH = "/"
PORT = 443

SAMPLES_PER_CIDR_V4 = 200
INCLUDE_IPV6 = False

CONCURRENCY = 200

PING_ENABLED = True          # ✅ اگر می‌خوای واقعا ping هم لحاظ شه True کن
PING_TIMEOUT_MS = 900

TCP_TIMEOUT = 2.0
TLS_TIMEOUT = 3.0
READ_TIMEOUT = 4.0
READ_BYTES = 150_000

SEED = 7

TRY_INSECURE_TLS = True
# ========================

# ===== Cloudflare Auto DNS =====
CF_ENABLED = True  # ✅ فعال/غیرفعال کردن کل بخش کلادفلر

# از Cloudflare > My Profile > API Tokens بساز:
# Permissions: Zone:DNS:Edit  + Zone:Zone:Read (یا Zone:Read)
CF_API_TOKEN = ""   # مثلا: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
CF_ZONE_ID = ""     # Zone ID دامنه‌ات (تو Overview هست)

# ساب‌دامنه(هایی) که می‌خوای تنظیم بشن (قبلی‌هاشون پاک میشه)
CF_RECORD_NAMES = [
    "server-fastly.simple.ir",
    # "best2.example.com",
]

CF_PROXIED = False  # اگر می‌خوای پشت پروکسی کلادفلر باشه True کن
CF_TTL = 1          # 1 یعنی Auto
# ===============================
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


def fetch_fastly_ranges() -> Tuple[List[str], List[str]]:
    fallback_ipv4 = [
        "140.248.128.0/17",
        "199.232.0.0/16",
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "140.248.64.0/18",
        "140.248.128.0/17",
        "146.75.0.0/17",
        "151.101.0.0/16",
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.224.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",
    ]
    fallback_ipv6 = ["2a04:4e40::/32", "2a04:4e42::/32"]

    req = Request(FASTLY_IP_LIST_URL, headers={"User-Agent": "fastly-probe/2.1"})
    last_err = None

    for attempt in range(1, 4):
        try:
            with urlopen(req, timeout=45) as r:
                data = json.loads(r.read().decode("utf-8"))
            ipv4 = data.get("addresses", [])
            ipv6 = data.get("ipv6_addresses", [])
            if ipv4:
                return ipv4, ipv6
            last_err = "API returned empty list"
        except Exception as e:
            last_err = str(e)
            try:
                time.sleep(1.5 * attempt)
            except Exception:
                pass

    print(f"⚠️ Fastly API fetch failed, using fallback CIDRs. Reason: {last_err}")
    return fallback_ipv4, fallback_ipv6


def sample_ips_from_cidr(cidr: str, k: int, seed: int = 0) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    rnd = random.Random(hash((cidr, seed)))
    num = net.num_addresses

    if isinstance(net, ipaddress.IPv4Network) and num >= 4:
        first = int(net.network_address) + 1
        last = int(net.broadcast_address) - 1
        host_count = max(0, last - first + 1)
        if host_count == 0:
            return []
        k_eff = min(k, host_count)
        picks = set()
        while len(picks) < k_eff:
            picks.add(first + rnd.randrange(host_count))
        return [str(ipaddress.IPv4Address(x)) for x in picks]

    k_eff = min(k, num)
    base = int(net.network_address)
    picks = set()
    while len(picks) < k_eff:
        picks.add(base + rnd.randrange(num))
    return [str(ipaddress.ip_address(x)) for x in picks]


async def ping_latency_ms(ip: str, timeout_ms: int = 900) -> Optional[float]:
    """
    ping واقعی و استخراج زمان (ms).
    اگر fail شود None برمی‌گرداند.
    """
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

        # Windows: time=14ms
        m = re.search(r"time[=<]\s*(\d+)\s*ms", text, re.IGNORECASE)
        if m:
            return float(m.group(1))

        # Linux/mac: time=14.2 ms
        m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", text, re.IGNORECASE)
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
        try:
            await writer.wait_closed()
        except Exception:
            pass
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
        coro = asyncio.open_connection(host=ip, port=PORT, ssl=ctx, server_hostname=TEST_HOST)
        reader, writer = await asyncio.wait_for(coro, timeout=TLS_TIMEOUT)
        connect_ms = (time.time() - t0) * 1000
    except Exception as e_verified:
        if not TRY_INSECURE_TLS:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "verified", "ping_ms": None, "err": str(e_verified)}

        tls_mode = "insecure"
        ctx2 = make_ssl_ctx(insecure=True)
        t0b = time.time()
        try:
            coro = asyncio.open_connection(host=ip, port=PORT, ssl=ctx2, server_hostname=TEST_HOST)
            reader, writer = await asyncio.wait_for(coro, timeout=TLS_TIMEOUT)
            connect_ms = (time.time() - t0b) * 1000
            verify_err = str(e_verified)
        except Exception as e_insecure:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "insecure", "ping_ms": None, "err": str(e_insecure)}

    try:
        req = (
            f"GET {TEST_PATH} HTTP/1.1\r\n"
            f"Host: {TEST_HOST}\r\n"
            f"User-Agent: fastly-probe/2.0\r\n"
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
        except Exception:
            http_code = None

        got = len(head)
        t1 = time.time()
        while got < READ_BYTES:
            chunk = await asyncio.wait_for(reader.read(16384), timeout=READ_TIMEOUT)
            if not chunk:
                break
            got += len(chunk)
        dt = time.time() - t1

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

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
            out["err"] = f"verified_tls_failed: {verify_err}"
        return out

    except Exception as e:
        try:
            writer.close()
        except Exception:
            pass
        return {"ip": ip, "ok": False, "stage": "read", "connect_ms": round(connect_ms, 1), "mbps": None, "http": None, "tls_mode": tls_mode, "ping_ms": None, "err": str(e)}


# -------- Cloudflare helpers --------
def cf_api_request(method: str, url: str, payload: Optional[dict] = None) -> dict:
    if not CF_API_TOKEN:
        raise RuntimeError("CF_API_TOKEN خالیه. توکن کلادفلر رو تنظیم کن.")
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "fastly-probe-cf/1.0",
    }
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = Request(url, headers=headers, data=data, method=method)

    print(f"CF → {method} {url}")  # ✅ debug

    # ✅ timeout کوتاه تا گیر نکنه
    timeout_s = 10

    # ✅ اجبار IPv4 (خیلی وقت‌ها همین مشکل رو حل می‌کنه)
    with force_ipv4_dns():
        try:
            with urlopen(req, timeout=timeout_s) as r:
                raw = r.read().decode("utf-8", errors="ignore")
                return json.loads(raw)
        except HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            raise RuntimeError(f"Cloudflare HTTPError {e.code}: {body}") from e
        except URLError as e:
            raise RuntimeError(f"Cloudflare URLError: {e}") from e

def cf_delete_records_by_name(record_name: str):
    base = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
    qurl = f"{base}?type=A&name={record_name}"
    res = cf_api_request("GET", qurl)
    if not res.get("success"):
        raise RuntimeError(f"Cloudflare list failed: {res}")

    items = res.get("result", [])
    for it in items:
        rid = it.get("id")
        if rid:
            durl = f"{base}/{rid}"
            cf_api_request("DELETE", durl)
            print(f"🗑️ Deleted old A record: {record_name} (id={rid})")


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
    if not res.get("success"):
        raise RuntimeError(f"Cloudflare create failed: {res}")
    print(f"✅ Cloudflare set: {record_name} -> {ip} (proxied={CF_PROXIED})")


def push_best_ip_to_cloudflare(best_ip: str):
    if not CF_ENABLED:
        return
    if not CF_ZONE_ID:
        raise RuntimeError("CF_ZONE_ID خالیه. Zone ID رو تنظیم کن.")

    for name in CF_RECORD_NAMES:
        cf_delete_records_by_name(name)   # پاک کردن قبلی‌ها
        cf_create_a_record(name, best_ip) # ساخت رکورد جدید


def pick_best(alive: List[dict]) -> Optional[dict]:
    if not alive:
        return None

    # اگر ping فعال باشه: اول ping کمتر، بعد سرعت بیشتر
    # اگر ping نباشه: connect_ms کمتر (تقریب پینگ)، بعد سرعت بیشتر
    def key(x: dict):
        ping = x.get("ping_ms")
        conn = x.get("connect_ms")
        mbps = x.get("mbps") or 0.0
        # None ها رو خیلی بد در نظر بگیر
        ping_sort = ping if ping is not None else 10_000.0
        conn_sort = conn if conn is not None else 10_000.0
        if PING_ENABLED:
            return (ping_sort, -mbps, conn_sort)
        return (conn_sort, -mbps)

    return sorted(alive, key=key)[0]


async def main():
    ipv4_cidrs, ipv6_cidrs = fetch_fastly_ranges()
    print(f"Fastly ranges: IPv4={len(ipv4_cidrs)}  IPv6={len(ipv6_cidrs)}")

    targets: List[str] = []
    for cidr in ipv4_cidrs:
        targets.extend(sample_ips_from_cidr(cidr, SAMPLES_PER_CIDR_V4, seed=SEED))

    if INCLUDE_IPV6:
        for cidr in ipv6_cidrs:
            targets.extend(sample_ips_from_cidr(cidr, 10, seed=SEED))

    targets = sorted(set(targets))
    print(f"Sampled IPs: {len(targets)}")

    sem = asyncio.Semaphore(CONCURRENCY)
    results = []

    async def worker(ip: str):
        async with sem:
            r = await https_probe_and_speed(ip)
            if r.get("ok") and PING_ENABLED:
                r["ping_ms"] = await ping_latency_ms(ip, timeout_ms=PING_TIMEOUT_MS)
            return r

    tasks = [asyncio.create_task(worker(ip)) for ip in targets]

    done = 0
    ok_count = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        done += 1

        if r["ok"]:
            ok_count += 1
            pm = r.get("ping_ms")
            pm_txt = f"{pm}ms" if pm is not None else "na"
            print(f'✅ {r["ip"]}  {r["tls_mode"]}  ping={pm_txt}  tls={r["connect_ms"]}ms  {r["mbps"]}Mbps  http={r["http"]}')
        else:
            print(f'❌ {r["ip"]}  {r["stage"]}  {r["err"]}')

        if done % 200 == 0 or done == len(targets):
            print(f"Progress: {done}/{len(targets)}  ok={ok_count}")

    alive = [x for x in results if x["ok"]]
    dead = [x for x in results if not x["ok"]]

    # مرتب‌سازی برای خروجی (صرفاً برای فایل‌ها)
    alive_sorted = sorted(alive, key=lambda x: (x["mbps"] or 0), reverse=True)

    with open("alive_fastly.txt", "w", encoding="utf-8") as f:
        for x in alive_sorted:
            f.write(f'{x["ip"]}  tls={x["tls_mode"]}  ping={x.get("ping_ms")}ms  connect={x["connect_ms"]}ms  {x["mbps"]}Mbps  http={x["http"]}\n')

    with open("dead_fastly.txt", "w", encoding="utf-8") as f:
        for x in dead:
            f.write(f'{x["ip"]}  stage={x["stage"]}  tls={x["tls_mode"]}  err={x["err"]}\n')

    with open("fastly_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "ok", "stage", "tls_mode", "connect_ms", "ping_ms", "mbps", "http", "err"])
        w.writeheader()
        w.writerows(results)

    print("\n📁 Done")
    print(f"Alive: {len(alive)} -> alive_fastly.txt")
    print(f"Dead : {len(dead)} -> dead_fastly.txt")
    print("CSV  : fastly_results.csv")

    # ✅ انتخاب بهترین و ست کردن روی Cloudflare
    best = pick_best(alive)
    if not best:
        print("⚠️ No alive IP found. Cloudflare update skipped.")
        return

    print("\n🏆 Best IP selected:")
    print(f'IP={best["ip"]}  ping={best.get("ping_ms")}ms  connect={best.get("connect_ms")}ms  mbps={best.get("mbps")}')

    try:
        print("➡️ entering cloudflare update...")
        await asyncio.to_thread(push_best_ip_to_cloudflare, best["ip"])

        print("✅ cloudflare update done.")
    except Exception as e:
        print(f"⚠️ Cloudflare update failed: {e}")
    


if __name__ == "__main__":
    asyncio.run(main())
