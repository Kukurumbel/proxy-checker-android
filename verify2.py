# -*- coding: utf-8 -*-
"""
СТРОГИЙ валидатор MTProto-прокси (v2). Запускается на сервере GitHub Actions.
Требует pycryptodome (pip install pycryptodome).

Критерий "рабочий" — настоящий, а не "держит сокет":

  • plain / dd (secure): полный obfuscated2 handshake + отправка req_pq_multi
    к Telegram ЧЕРЕЗ прокси. Прокси засчитывается, только если в дешифрованном
    ответе пришёл resPQ (constructor 0x05162463) — это значит, прокси реально
    проксирует трафик до серверов Telegram.

  • FakeTLS (ee): шлём настоящий TLS ClientHello, требуем валидный
    TLS ServerHello (record 0x16 0x03 + handshake type 0x02 внутри).
    Просто "ответил байтами" больше НЕ засчитывается.

Пишет working_proxies.json — только реально рабочие, по возрастанию пинга.
"""
import json
import os
import socket
import struct
import hashlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

from Crypto.Cipher import AES
from Crypto.Util import Counter as CtrCounter

CONNECT_T = 4.0
IO_T = 4.0
MAX_WORKERS = 50
RESPQ = struct.pack("<I", 0x05162463)


# --------------------------- разбор секрета ---------------------------------

def secret_type(secret):
    s = secret.lower().strip()
    if s.startswith("ee"):
        return "faketls"
    if s.startswith("dd"):
        return "secure"
    return "plain"


def secret_key(secret):
    """16-байтный ключ из секрета (или None, если битый)."""
    s = secret.lower().strip()
    if s.startswith("ee") or s.startswith("dd"):
        s = s[2:]
    if len(s) < 32:
        return None
    try:
        return bytes.fromhex(s[:32])
    except Exception:
        return None


def faketls_sni(secret):
    s = secret.lower().strip()
    if s.startswith("ee"):
        s = s[2:]
    try:
        dom = bytes.fromhex(s[32:]).decode("ascii", "ignore")
        return dom or None
    except Exception:
        return None


# ----------------------- obfuscated2 (plain/secure) -------------------------

def _ctr(key, iv):
    return AES.new(key, AES.MODE_CTR,
                   counter=CtrCounter.new(128, initial_value=int.from_bytes(iv, "big")))


def make_init(key):
    """64-байтный init + потоковые шифры (enc для отправки, dec для приёма)."""
    while True:
        b = bytearray(os.urandom(64))
        if b[0] == 0xef:
            continue
        if bytes(b[0:4]) in (b"GET ", b"POST", b"HEAD", b"\x16\x03\x01\x02",
                             b"\xdd\xdd\xdd\xdd", b"\xee\xee\xee\xee", b"\x50\x56\x4e\x47"):
            continue
        if b[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    b[56] = b[57] = b[58] = b[59] = 0xef    # abridged transport
    enc_key = hashlib.sha256(bytes(b[8:40]) + key).digest()
    enc_iv = bytes(b[40:56])
    rev = bytes(reversed(bytes(b[8:56])))
    dec_key = hashlib.sha256(rev[0:32] + key).digest()
    dec_iv = rev[32:48]
    enc = _ctr(enc_key, enc_iv)
    dec = _ctr(dec_key, dec_iv)
    enc_full = enc.encrypt(bytes(b))
    packet = bytes(b[0:56]) + enc_full[56:64]
    return packet, enc, dec


def abridged_wrap(payload):
    ln = len(payload) // 4
    if ln < 0x7f:
        return bytes([ln]) + payload
    return b"\x7f" + struct.pack("<I", ln)[0:3] + payload


def make_req_pq():
    nonce = os.urandom(16)
    body = struct.pack("<I", 0xbe7e8ef1) + nonce       # req_pq_multi
    msg_id = int(time.time()) << 32
    msg = struct.pack("<q", 0) + struct.pack("<q", msg_id) + \
        struct.pack("<i", len(body)) + body
    return msg


def check_mtproto(server, port, key):
    s = None
    try:
        t0 = time.monotonic()
        s = socket.create_connection((server, port), timeout=CONNECT_T)
        ping = int((time.monotonic() - t0) * 1000)
        s.settimeout(IO_T)
        packet, enc, dec = make_init(key)
        s.sendall(packet)
        s.sendall(enc.encrypt(abridged_wrap(make_req_pq())))
        buf = b""
        try:
            while len(buf) < 16:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        if not buf:
            return (False, ping)
        plain = dec.decrypt(buf)
        return (RESPQ in plain, ping)
    except (socket.timeout, OSError):
        return (False, None)
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


# ------------------------------- FakeTLS ------------------------------------

def build_client_hello(sni):
    sni_b = (sni or "www.cloudflare.com").encode()
    ext_sni = (b"\x00\x00" + (len(sni_b) + 5).to_bytes(2, "big") +
               (len(sni_b) + 3).to_bytes(2, "big") + b"\x00" +
               len(sni_b).to_bytes(2, "big") + sni_b)
    # supported_versions (TLS 1.3) + key_share минимально
    exts = ext_sni
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" +
            len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def check_faketls(server, port, sni):
    s = None
    try:
        t0 = time.monotonic()
        s = socket.create_connection((server, port), timeout=CONNECT_T)
        ping = int((time.monotonic() - t0) * 1000)
        s.settimeout(IO_T)
        s.sendall(build_client_hello(sni))
        buf = b""
        try:
            while len(buf) < 6:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        if len(buf) < 6:
            return (False, ping)
        # валидный TLS record: 0x16 (handshake) 0x03 0x0X, затем тип 0x02 (ServerHello)
        ok = (buf[0] == 0x16 and buf[1] == 0x03 and buf[5] == 0x02)
        return (ok, ping)
    except (socket.timeout, OSError):
        return (False, None)
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


# --------------------------------- main -------------------------------------

def check(proxy):
    secret = proxy.get("secret", "")
    key = secret_key(secret)
    if key is None:
        return ("bad_secret", False, None)
    typ = secret_type(secret)
    if typ == "faketls":
        ok, ping = check_faketls(proxy["server"], proxy["port"], faketls_sni(secret))
    else:
        ok, ping = check_mtproto(proxy["server"], proxy["port"], key)
    return (typ, ok, ping)


def main():
    proxies = json.load(open("proxies.json", encoding="utf-8"))["proxies"]
    sys.stderr.write("Строгая проверка %d прокси...\n" % len(proxies))
    working = []
    stats = Counter()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(check, proxies))
    for proxy, (typ, ok, ping) in zip(proxies, results):
        if typ == "bad_secret":
            stats["bad_secret"] += 1
            continue
        if ok:
            stats[typ + "_ok"] += 1
            item = dict(proxy)
            item["ping"] = ping
            working.append(item)
        else:
            stats["dead"] += 1
    working.sort(key=lambda p: p["ping"])
    out = {"proxies": working, "count": len(working), "checked": len(proxies)}
    with open("working_proxies.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    sys.stderr.write(
        "РАБОЧИХ: %d из %d  (%s)\n" %
        (len(working), len(proxies), dict(stats)))


if __name__ == "__main__":
    main()
