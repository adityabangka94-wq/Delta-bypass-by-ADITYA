#!/usr/bin/env python3
# file: main_v2.py
# usage: python main_v2.py "https://auth.platorelay.com/a?d=..."

import sys, time, json, base64, urllib.parse
import requests
import urllib3
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH_API = "https://auth.platorelay.com/api"
SERVICE = 3
VERSION = "8.1.2"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 "
      "Mobile/15E148 Safari/604.1")
SCREEN = "390x844"
MIN_TICKET_LEN = 33
MIN_STEP_GAP = 5.0
STEP_THROTTLE_SLEEP = 2.0


def aes_ctr(plain, key_bytes, iv_bytes):
    """AES-CTR manual per blok 16 byte."""
    key = bytearray(key_bytes)
    iv = bytearray(iv_bytes)
    data = plain.encode()
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(iv))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], blk))
        j = 15
        while True:
            iv[j] = (iv[j] + 1) & 0xFF
            if iv[j] != 0:
                break
            j -= 1
            if j < 0:
                break
    return bytes(out)


def build_meta_stream(ticket, now_ms=None):
    if len(ticket) < MIN_TICKET_LEN:
        return None, None
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    key_meta, ctr_meta = ticket[:16], ticket[16:32]
    key_stream, ctr_stream = ticket[1:17], ticket[17:33]

    meta_plain = json.dumps({
        "browserInfo": [{"screen": SCREEN, "ua": UA, "time": now_ms}]
    }, separators=(',', ':'))

    stream_plain = json.dumps({
        "events": [{"event": 1, "data": {"time": now_ms}}]
    }, separators=(',', ':'))

    meta = aes_ctr(meta_plain,
                   [ord(c) for c in key_meta],
                   [ord(c) for c in ctr_meta]).hex()
    stream = aes_ctr(stream_plain,
                     [ord(c) for c in key_stream],
                     [ord(c) for c in ctr_stream]).hex()
    return meta, stream


def extract_ticket(arg):
    t = arg.strip()
    if t.startswith("http"):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(t).query)
        if "d" in qs:
            return qs["d"][0]
    return t


def decode_callback_url(loot_url):
    """Decode base64 'r=' param -> URL callback."""
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(loot_url).query)
    r_param = qs.get("r", [""])[0]
    if not r_param:
        return None
    b64 = r_param.replace("-", "+").replace("_", "/")
    padding = (4 - len(b64) % 4) % 4
    try:
        dec = base64.b64decode(b64 + "=" * padding).decode("utf-8")
        if dec.startswith("http"):
            return dec
    except Exception:
        pass
    return None


def extract_ticket_from_callback(cb):
    if not cb:
        return None
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(cb).query)
    return qs.get("d", [None])[0]


def do_step(ticket):
    meta, stream = build_meta_stream(ticket)
    if meta is None:
        return {"success": False, "error": "ticket terlalu pendek"}
    url = f"{AUTH_API}/session/step?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
    body = json.dumps({
        "captcha": None,
        "meta": meta,
        "stream": stream,
        "resolved": True,
    }).encode()
    r = requests.put(url, data=body, headers={
        "User-Agent": UA,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "x-client-name": "platoboost webclient",
        "x-client-version": VERSION,
    }, timeout=15, verify=False)
    try:
        return r.json()
    except Exception:
        return {"success": False, "raw": r.text[:200]}


def poll_key(ticket, tries=10):
    for _ in range(tries):
        url = f"{AUTH_API}/session/status?ticket={urllib.parse.quote(ticket)}&service={SERVICE}"
        try:
            r = requests.get(url, headers={
                "User-Agent": UA,
                "Accept": "application/json",
                "x-client-name": "platoboost webclient",
                "x-client-version": VERSION,
            }, timeout=10, verify=False)
            d = r.json()
            k = (d.get("data") or {}).get("key", "")
            if k and k != "KEY_NOT_FOUND":
                return k
        except Exception:
            pass
        time.sleep(0.5)
    return None


def solve(raw_link):
    ticket = extract_ticket(raw_link)
    if len(ticket) < MIN_TICKET_LEN:
        print("[-] ticket terlalu pendek")
        return None

    print(f"[*] start ticket: {ticket[:30]}...")

    seen = set()
    gap_ts = 0.0

    for rnd in range(12):
        if ticket in seen:
            print("[!] ticket berulang, stop")
            break
        seen.add(ticket)

        # WAJIB: jeda minimal 5 detik antar checkpoint (rate limit server)
        if gap_ts:
            elapsed = time.time() - gap_ts
            if elapsed < MIN_STEP_GAP:
                wait = MIN_STEP_GAP - elapsed
                print(f"[~] jeda {wait:.1f}s (rate limit server)...")
                time.sleep(wait)

        print(f"\n[*] round {rnd + 1} — {ticket[:30]}...")

        r = do_step(ticket)
        gap_ts = time.time()

        if not isinstance(r, dict) or not r.get("success"):
            msg = str(r.get("message") or r.get("error") or "").lower()
            if "too fast" in msg or "slow down" in msg:
                print(f"    [!] throttled, tunggu {STEP_THROTTLE_SLEEP}s...")
                time.sleep(STEP_THROTTLE_SLEEP)
                continue
            print(f"    [!] gagal: {msg}")
            time.sleep(1.5)
            continue

        data = r.get("data") or {}
        k = data.get("key")
        if k and k != "KEY_NOT_FOUND":
            return k

        url = data.get("url", "")
        print(f"    url: {url[:80]}...")

        if url == "about:blank" or not url:
            print("    polling...")
            k = poll_key(ticket)
            if k:
                return k
            break

        cb = decode_callback_url(url)
        nt = extract_ticket_from_callback(cb) if cb else None
        if nt and len(nt) > 50:
            print(f"    → ticket baru: {nt[:30]}...")
            ticket = nt
        else:
            print("    [!] decode gagal, polling...")
            k = poll_key(ticket)
            if k:
                return k
            break

    return None


def main():
    if len(sys.argv) < 2:
        print('usage: python main_v2.py "link"')
        sys.exit(1)
    k = solve(sys.argv[1])
    if k:
        print(f"\n[+] KEY : {k}")
    else:
        print("\n[-] gagal total")


if __name__ == "__main__":
    main()
