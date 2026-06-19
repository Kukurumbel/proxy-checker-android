# -*- coding: utf-8 -*-
"""
Сборщик MTProto-прокси — запускается на сервере GitHub Actions (не на телефоне).

Сервер GitHub находится за границей, ему доступен t.me без VPN. Скрипт читает
публичные каналы, вытаскивает прокси и сохраняет их в proxies.json. Этот файл
затем раздаётся через GitHub, и телефон скачивает уже готовый список без VPN.

Только стандартная библиотека Python 3.
"""

import json
import html
import re
import socket
import sys
import urllib.error
import urllib.request

CHANNELS = ["TProxyRU", "ProxyMTProto"]   # публичные каналы с прокси
MAX_PAGES = 10                            # страниц истории на канал

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36")

PROXY_LINK_RE = re.compile(
    r'(?:tg://proxy\?|https?://t\.me/proxy\?)([^"\'<>\s]+)', re.IGNORECASE)
POST_ID_RE = re.compile(r'data-post="[^"]+/(\d+)"')


def fetch_channel(channel, before=None):
    url = "https://t.me/s/{}".format(channel)
    if before is not None:
        url += "?before={}".format(before)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", "ignore")
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        sys.stderr.write("fetch error @{}: {}\n".format(channel, e))
        return ""


def min_post_id(text):
    ids = [int(x) for x in POST_ID_RE.findall(text)]
    return min(ids) if ids else None


def parse_proxies(text):
    found = {}
    for raw in PROXY_LINK_RE.findall(text):
        query = html.unescape(raw)
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip().lower()] = v.strip()
        server = params.get("server")
        port = params.get("port")
        secret = params.get("secret")
        if not (server and port and secret):
            continue
        try:
            port = int(port)
        except ValueError:
            continue
        key = (server.lower(), port, secret.lower())
        found[key] = {"server": server, "port": port, "secret": secret}
    return list(found.values())


def collect():
    all_proxies = {}
    for ch in CHANNELS:
        before = None
        for page in range(MAX_PAGES):
            text = fetch_channel(ch, before)
            if not text:
                break
            for p in parse_proxies(text):
                key = (p["server"].lower(), p["port"], p["secret"].lower())
                all_proxies[key] = p
            nxt = min_post_id(text)
            if nxt is None or nxt == before:
                break
            before = nxt
    return list(all_proxies.values())


def main():
    proxies = collect()
    # сортируем стабильно, чтобы git видел реальные изменения, а не перестановки
    proxies.sort(key=lambda p: (p["server"].lower(), p["port"], p["secret"]))
    data = {"proxies": proxies, "count": len(proxies)}
    with open("proxies.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    sys.stderr.write("collected {} proxies\n".format(len(proxies)))


if __name__ == "__main__":
    main()
