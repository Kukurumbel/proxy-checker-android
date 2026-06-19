# -*- coding: utf-8 -*-
"""
Серверный валидатор MTProto-прокси (запускается на GitHub Actions, чистый
интернет). Проверяет каждый прокси из proxies.json правильным способом по типу:

  • FakeTLS (секрет ee...) — шлём настоящий TLS ClientHello с нужным SNI,
    живой прокси отвечает TLS-записью (0x16 0x03 ...).
  • dd/обычные — TCP-connect + базовый обфусцированный init, ждём, что
    соединение держится и/или приходят байты.

Пишет working_proxies.json — только прошедшие проверку, по возрастанию пинга.
Только стандартная библиотека Python 3.
"""
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

CONNECT_T = 3.0
IO_T = 3.0
MAX_WORKERS = 60
PING_LIMIT_MS = 1500


def secret_type(secret):
    s = secret.lower().strip()
    if s.startswith("ee"):
        return "faketls"
    if s.startswith("dd"):
        return "secure"
    return "plain"


def faketls_sni(secret):
    """Из FakeTLS-секрета ee + 32hex + hexdomain достаём домен для SNI."""
    s = secret.lower().strip()
    if s.startswith("ee"):
        s = s[2:]
    try:
        dom = bytes.fromhex(s[32:]).decode("ascii", "ignore")
        return dom or None
    except Exception:
        return None


def valid_secret(secret):
    """Базовая проверка корректности секрета (отсев битых)."""
    s = secret.lower().strip()
    if s.startswith("ee") or s.startswith("dd"):
        s = s[2:]
    if len(s) < 32:
        return False
    try:
        bytes.fromhex(s[:32])
        return True
    except Exception:
        return False


def build_client_hello(sni):
    sni_b = (sni or "www.cloudflare.com").encode()
    ext_sni = (b"\x00\x00" + (len(sni_b) + 5).to_bytes(2, "big") +
               (len(sni_b) + 3).to_bytes(2, "big") + b"\x00" +
               len(sni_b).to_bytes(2, "big") + sni_b)
    exts = ext_sni
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" +
            len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def check(proxy):
    """Возвращает (ok: bool, ping_ms|None)."""
    secret = proxy.get("secret", "")
    if not valid_secret(secret):
        return (False, None)
    server, port = proxy["server"], proxy["port"]
    typ = secret_type(secret)
    s = None
    try:
        t0 = time.monotonic()
        s = socket.create_connection((server, port), timeout=CONNECT_T)
        ping = int((time.monotonic() - t0) * 1000)
        if ping > PING_LIMIT_MS:
            return (False, ping)
        s.settimeout(IO_T)

        if typ == "faketls":
            # настоящий способ для FakeTLS: ждём TLS-ответ на ClientHello
            s.sendall(build_client_hello(faketls_sni(secret)))
            try:
                data = s.recv(8)
            except socket.timeout:
                return (False, ping)        # FakeTLS обязан отвечать TLS-ом
            if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
                return (True, ping)          # валидная TLS-запись = живой
            return (False, ping)
        else:
            # secure/plain: обфусцированный init, ждём, что соединение живо
            init = bytearray(os.urandom(64))
            init[0] = 0xEE
            try:
                s.sendall(bytes(init))
                s.sendall(os.urandom(64))
            except OSError:
                return (False, ping)
            try:
                data = s.recv(16)
                return (len(data) > 0, ping)
            except socket.timeout:
                return (True, ping)          # держит соединение — считаем живым
            except OSError:
                return (False, ping)
    except (socket.timeout, OSError):
        return (False, None)
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


def main():
    proxies = json.load(open("proxies.json", encoding="utf-8"))["proxies"]
    sys.stderr.write("Проверяю %d прокси...\n" % len(proxies))
    working = []
    stats = {"faketls_ok": 0, "other_ok": 0, "bad_secret": 0, "dead": 0}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(check, proxies))
    for proxy, (ok, ping) in zip(proxies, results):
        if not valid_secret(proxy.get("secret", "")):
            stats["bad_secret"] += 1
            continue
        if ok:
            if secret_type(proxy["secret"]) == "faketls":
                stats["faketls_ok"] += 1
            else:
                stats["other_ok"] += 1
            item = dict(proxy)
            item["ping"] = ping
            working.append(item)
        else:
            stats["dead"] += 1
    working.sort(key=lambda p: p["ping"])
    out = {"proxies": working, "count": len(working),
           "checked": len(proxies)}
    with open("working_proxies.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    sys.stderr.write(
        "Рабочих: %d из %d  (FakeTLS=%d, прочие=%d, битый секрет=%d, мёртвых=%d)\n"
        % (len(working), len(proxies), stats["faketls_ok"], stats["other_ok"],
           stats["bad_secret"], stats["dead"]))


if __name__ == "__main__":
    main()
