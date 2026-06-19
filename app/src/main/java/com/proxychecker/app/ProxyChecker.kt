package com.proxychecker.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/**
 * Логика загрузки и проверки MTProto-прокси.
 *
 * Список прокси собирается на сервере GitHub (см. scrape.py) и скачивается
 * приложением как готовый proxies.json — поэтому VPN на телефоне не нужен.
 * Каждый прокси проверяется: TCP-connect (пинг) + начало MTProto-рукопожатия
 * по реальному интернету телефона. Логин в Telegram не требуется.
 */
object ProxyChecker {

    // ----------------------------- НАСТРОЙКИ -------------------------------

    // Каналы-источники (сбор идёт на сервере, см. scrape.py) — для подписи в UI
    val CHANNELS = listOf("TProxyRU", "ProxyMTProto")
    const val PING_LIMIT_MS = 1000                      // порог пинга, мс
    const val CONNECT_TIMEOUT_MS = 1000                 // таймаут TCP-connect
    const val HANDSHAKE_TIMEOUT_MS = 1000               // таймаут ответа прокси
    const val MAX_WORKERS = 40                          // параллельных проверок

    private const val USER_AGENT =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"

    // --- данные ---

    data class Proxy(val server: String, val port: Int, val secret: String) {
        /** Ключ для дедупликации (без учёта регистра). */
        val key: String get() = "${server.lowercase()}:$port:${secret.lowercase()}"

        /** Кликабельная ссылка — Telegram добавит прокси в один тап. */
        fun link(): String =
            "https://t.me/proxy?server=$server&port=$port&secret=$secret"
    }

    data class Result(val proxy: Proxy, val ok: Boolean, val pingMs: Int?)

    // ----------------------- ЗАГРУЗКА СПИСКА ПРОКСИ -------------------------
    //
    // Список прокси собирается на сервере GitHub (ему доступен t.me без VPN) и
    // лежит в proxies.json. Телефон качает готовый файл — поэтому VPN НЕ нужен,
    // а проверка пинга идёт по твоему реальному интернету.

    // raw.githubusercontent — отдаёт файл напрямую. Если он недоступен у
    // провайдера, пробуем jsDelivr CDN (другой домен, часто открыт).
    private val PROXY_LIST_URLS = listOf(
        "https://raw.githubusercontent.com/Kukurumbel/proxy-checker-android/main/proxies.json",
        "https://cdn.jsdelivr.net/gh/Kukurumbel/proxy-checker-android@main/proxies.json"
    )

    /** Скачать текст по URL (или null при ошибке). */
    private fun httpGet(urlStr: String): String? {
        return try {
            val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("User-Agent", USER_AGENT)
                connectTimeout = 15_000
                readTimeout = 15_000
            }
            if (conn.responseCode != 200) {
                conn.disconnect()
                return null
            }
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            null
        }
    }

    /** Разобрать proxies.json в список прокси. */
    private fun parseJson(text: String): List<Proxy> {
        val out = LinkedHashMap<String, Proxy>()
        val arr = org.json.JSONObject(text).getJSONArray("proxies")
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val server = o.optString("server")
            val port = o.optInt("port", -1)
            val secret = o.optString("secret")
            if (server.isNotEmpty() && port > 0 && secret.isNotEmpty()) {
                val p = Proxy(server, port, secret)
                out[p.key] = p
            }
        }
        return out.values.toList()
    }

    /** Скачать готовый список прокси с GitHub (VPN не требуется). */
    suspend fun collectProxies(log: (String) -> Unit): List<Proxy> =
        withContext(Dispatchers.IO) {
            log("Загружаю список прокси...")
            for (url in PROXY_LIST_URLS) {
                val text = httpGet(url) ?: continue
                try {
                    val list = parseJson(text)
                    if (list.isNotEmpty()) {
                        log("Загружено ${list.size} прокси, проверяю...")
                        return@withContext list
                    }
                } catch (e: Exception) {
                    // битый JSON — пробуем следующий источник
                }
            }
            log("Не удалось загрузить список. Проверь интернет.")
            emptyList()
        }

    // --------------------------- ПРОВЕРКА ПИНГА ----------------------------

    /**
     * Строгая проверка: TCP-connect (пинг) + начало MTProto-рукопожатия.
     * Возвращает Result(proxy, ok, pingMs). pingMs = реальная латентность.
     */
    private fun checkProxy(proxy: Proxy): Result {
        var sock: Socket? = null
        try {
            // --- шаг 1: TCP-connect, замер пинга ---
            val start = System.nanoTime()
            sock = Socket()
            sock.connect(
                InetSocketAddress(proxy.server, proxy.port),
                CONNECT_TIMEOUT_MS
            )
            val pingMs = ((System.nanoTime() - start) / 1_000_000).toInt()

            if (pingMs > PING_LIMIT_MS) return Result(proxy, false, pingMs)

            // --- шаг 2: начало MTProto-рукопожатия ---
            sock.soTimeout = HANDSHAKE_TIMEOUT_MS
            // 64 детерминированных «псевдослучайных» байта на основе адреса
            val seed = (proxy.server + proxy.port).toByteArray(Charsets.UTF_8)
            val nonce = ByteArray(64)
            for (i in 0 until 64) {
                nonce[i] = ((seed[i % seed.size].toInt() and 0xFF) *
                    (i + 7) + i * 31 and 0xFF).toByte()
            }
            nonce[0] = 0xEE.toByte()
            val out = sock.getOutputStream()
            try {
                out.write(nonce)
                out.flush()
            } catch (e: Exception) {
                return Result(proxy, false, pingMs)
            }
            // ждём любой ответный байт; живой прокси держит соединение
            val responsive = try {
                val buf = ByteArray(16)
                val n = sock.getInputStream().read(buf)
                n > 0
            } catch (e: java.net.SocketTimeoutException) {
                // FakeTLS-прокси может молчать, но держит соединение — живой
                true
            } catch (e: Exception) {
                false
            }
            return Result(proxy, responsive, pingMs)
        } catch (e: Exception) {
            return Result(proxy, false, null)
        } finally {
            try {
                sock?.close()
            } catch (e: Exception) {
            }
        }
    }

    /**
     * Проверить все прокси параллельно (до MAX_WORKERS одновременно).
     * onProgress(done, total) вызывается по мере готовности.
     */
    suspend fun checkAll(
        proxies: List<Proxy>,
        onProgress: (done: Int, total: Int) -> Unit
    ): List<Result> = coroutineScope {
        val total = proxies.size
        val sem = Semaphore(MAX_WORKERS)
        var done = 0
        val lock = Any()
        val jobs = proxies.map { p ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val r = checkProxy(p)
                    synchronized(lock) {
                        done++
                        onProgress(done, total)
                    }
                    r
                }
            }
        }
        val results = jobs.awaitAll()
        // рабочие — сверху, по возрастанию пинга
        results.sortedWith(
            compareBy({ !it.ok }, { it.pingMs ?: Int.MAX_VALUE })
        )
    }
}
