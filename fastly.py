#!/usr/bin/env python3
import asyncio
import csv
import ipaddress
import json
import random
import ssl
import sys
import time
from typing import List, Tuple
from urllib.request import urlopen, Request

FASTLY_IP_LIST_URL = "https://api.fastly.com/public-ip-list"

# ===== تنظیمات اصلی =====
TEST_HOST = "www.github.com"   # بهتر: دامنه‌ی خودت یا سرویسی که مطمئنی پشت Fastly هست
TEST_PATH = "/"                # مسیر سبک
PORT = 443

SAMPLES_PER_CIDR_V4 = 200      # زیادش کن: 300 یا 500
INCLUDE_IPV6 = False

CONCURRENCY = 200

PING_ENABLED = False
PING_TIMEOUT_MS = 900

TCP_TIMEOUT = 2.0              # جداگانه برای TCP
TLS_TIMEOUT = 3.0              # جداگانه برای TLS
READ_TIMEOUT = 4.0             # برای خواندن دیتا
READ_BYTES = 150_000           # کمتر = شانس OK بیشتر (150KB)

SEED = 7

# اگر True: حتی اگه verify fail شد، insecure رو هم امتحان می‌کنیم
TRY_INSECURE_TLS = True
# ========================


def fetch_fastly_ranges() -> Tuple[List[str], List[str]]:
    """
    1) از API رسمی Fastly می‌گیرد (با retry).
    2) اگر fail شد، از fallback CIDRهای معروف استفاده می‌کند تا تست متوقف نشود.
    """
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

    # Retry با timeout بیشتر
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
            # مکث کوتاه بین تلاش‌ها
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


async def ping_ip(ip: str, timeout_ms: int = 800) -> bool:
    is_windows = sys.platform.startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, int((timeout_ms + 999) / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return (await proc.wait()) == 0
    except Exception:
        return False


async def tcp_connect_only(ip: str):
    """فقط TCP connect به 443 (بدون TLS)"""
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
    """
    1) TCP connect check
    2) TLS connect (verified) - اگر fail شد و TRY_INSECURE_TLS=True => insecure
    3) HTTP GET و خواندن مقدار کمی دیتا + محاسبه سرعت
    """
    ok_tcp, tcp_ms, tcp_err = await tcp_connect_only(ip)
    if not ok_tcp:
        return {"ip": ip, "ok": False, "stage": "tcp", "connect_ms": None, "mbps": None, "http": None, "tls_mode": None, "err": tcp_err}

    # --- TLS verified ---
    tls_mode = "verified"
    ctx = make_ssl_ctx(insecure=False)

    t0 = time.time()
    try:
        coro = asyncio.open_connection(host=ip, port=PORT, ssl=ctx, server_hostname=TEST_HOST)
        reader, writer = await asyncio.wait_for(coro, timeout=TLS_TIMEOUT)
        connect_ms = (time.time() - t0) * 1000
    except Exception as e_verified:
        if not TRY_INSECURE_TLS:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "verified", "err": str(e_verified)}

        # --- TLS insecure fallback ---
        tls_mode = "insecure"
        ctx2 = make_ssl_ctx(insecure=True)
        t0b = time.time()
        try:
            coro = asyncio.open_connection(host=ip, port=PORT, ssl=ctx2, server_hostname=TEST_HOST)
            reader, writer = await asyncio.wait_for(coro, timeout=TLS_TIMEOUT)
            connect_ms = (time.time() - t0b) * 1000
            # خطای verify رو نگه می‌داریم برای گزارش
            verify_err = str(e_verified)
        except Exception as e_insecure:
            return {"ip": ip, "ok": False, "stage": "tls", "connect_ms": None, "mbps": None, "http": None, "tls_mode": "insecure", "err": str(e_insecure)}

    # --- HTTP request ---
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

        # اول چند کیلوبایت بخونیم تا status code رو دربیاریم
        head = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT)
        if not head:
            writer.close()
            return {"ip": ip, "ok": False, "stage": "read", "connect_ms": round(connect_ms, 1), "mbps": None, "http": None, "tls_mode": tls_mode, "err": "no data"}

        # status code
        http_code = None
        try:
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
            # مثال: HTTP/1.1 200 OK
            parts = first_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                http_code = int(parts[1])
        except Exception:
            http_code = None

        # حالا بقیه دیتا برای سرعت (همون head هم جزو دیتا حساب میشه)
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

        # حتی اگر 403/301 باشه هم یعنی IP جواب داده (هدف تو همین بود)
        if dt <= 0:
            mbps = 0.0
        else:
            mbps = (got * 8) / (dt * 1_000_000)

        out = {
            "ip": ip,
            "ok": True,
            "stage": "ok",
            "connect_ms": round(connect_ms, 1),
            "mbps": round(mbps, 2),
            "http": http_code,
            "tls_mode": tls_mode,
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
        return {"ip": ip, "ok": False, "stage": "read", "connect_ms": round(connect_ms, 1), "mbps": None, "http": None, "tls_mode": tls_mode, "err": str(e)}


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
            if PING_ENABLED:
                _ = await ping_ip(ip, timeout_ms=PING_TIMEOUT_MS)  # فقط info ـه
            return await https_probe_and_speed(ip)

    tasks = [asyncio.create_task(worker(ip)) for ip in targets]

    done = 0
    ok_count = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
        done += 1

        if r["ok"]:
            ok_count += 1
            print(f'✅ {r["ip"]}  {r["tls_mode"]}  {r["connect_ms"]}ms  {r["mbps"]}Mbps  http={r["http"]}')
        else:
            print(f'❌ {r["ip"]}  {r["stage"]}  {r["err"]}')

        if done % 200 == 0 or done == len(targets):
            print(f"Progress: {done}/{len(targets)}  ok={ok_count}")

    alive = [x for x in results if x["ok"]]
    dead = [x for x in results if not x["ok"]]

    alive_sorted = sorted(alive, key=lambda x: (x["mbps"] or 0), reverse=True)

    with open("alive_fastly.txt", "w", encoding="utf-8") as f:
        for x in alive_sorted:
            f.write(f'{x["ip"]}  tls={x["tls_mode"]}  {x["connect_ms"]}ms  {x["mbps"]}Mbps  http={x["http"]}\n')

    with open("dead_fastly.txt", "w", encoding="utf-8") as f:
        for x in dead:
            f.write(f'{x["ip"]}  stage={x["stage"]}  tls={x["tls_mode"]}  err={x["err"]}\n')

    with open("fastly_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "ok", "stage", "tls_mode", "connect_ms", "mbps", "http", "err"])
        w.writeheader()
        w.writerows(results)

    print("\n📁 Done")
    print(f"Alive: {len(alive)} -> alive_fastly.txt")
    print(f"Dead : {len(dead)} -> dead_fastly.txt")
    print("CSV  : fastly_results.csv")


if __name__ == "__main__":
    asyncio.run(main())
