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
 * Логика сбора и проверки MTProto-прокси — порт proxy_checker.py на Kotlin.
 *
 * Читает публичную веб-версию Telegram-каналов (t.me/s/...), вытаскивает
 * ссылки tg://proxy, проверяет каждый прокси: TCP-connect (пинг) + начало
 * MTProto-рукопожатия. Логин в Telegram не требуется.
 */
object ProxyChecker {

    // ----------------------------- НАСТРОЙКИ -------------------------------

    val CHANNELS = listOf("TProxyRU", "ProxyMTProto")  // публичные каналы
    const val MAX_PAGES = 10                            // страниц истории на канал
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

    // --------------------------- ЧТЕНИЕ КАНАЛОВ ----------------------------

    private val proxyLinkRe = Regex(
        """(?:tg://proxy\?|https?://t\.me/proxy\?)([^"'<>\s]+)""",
        RegexOption.IGNORE_CASE
    )
    private val postIdRe = Regex("""data-post="[^"]+/(\d+)"""")

    /** Скачать веб-версию канала; before — id поста для пагинации вглубь. */
    private fun fetchChannel(channel: String, before: Int?): String {
        var urlStr = "https://t.me/s/$channel"
        if (before != null) urlStr += "?before=$before"
        return try {
            val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("User-Agent", USER_AGENT)
                connectTimeout = 20_000
                readTimeout = 20_000
            }
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            ""
        }
    }

    /** Минимальный id поста на странице — курсор для следующей страницы. */
    private fun minPostId(html: String): Int? =
        postIdRe.findAll(html).map { it.groupValues[1].toInt() }.minOrNull()

    /** Декодировать HTML-сущности (&amp; -> & и т.п.) без сторонних либ. */
    private fun unescapeHtml(s: String): String =
        s.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")

    /** Из HTML вытащить уникальные прокси. */
    private fun parseProxies(html: String): List<Proxy> {
        val found = LinkedHashMap<String, Proxy>()
        for (m in proxyLinkRe.findAll(html)) {
            val query = unescapeHtml(m.groupValues[1])
            val params = HashMap<String, String>()
            for (pair in query.split("&")) {
                val i = pair.indexOf('=')
                if (i > 0) {
                    params[pair.substring(0, i).trim().lowercase()] =
                        pair.substring(i + 1).trim()
                }
            }
            val server = params["server"] ?: continue
            val portStr = params["port"] ?: continue
            val secret = params["secret"] ?: continue
            val port = portStr.toIntOrNull() ?: continue
            val p = Proxy(server, port, secret)
            found[p.key] = p
        }
        return found.values.toList()
    }

    /** Собрать прокси со всех каналов, листая до MAX_PAGES страниц вглубь. */
    suspend fun collectProxies(log: (String) -> Unit): List<Proxy> =
        withContext(Dispatchers.IO) {
            val all = LinkedHashMap<String, Proxy>()
            for (ch in CHANNELS) {
                log("Читаю канал @$ch ...")
                var before: Int? = null
                var chCount = 0
                for (page in 0 until MAX_PAGES) {
                    val text = fetchChannel(ch, before)
                    if (text.isEmpty()) {
                        if (page == 0) log("  ! не удалось прочитать @$ch")
                        break
                    }
                    for (p in parseProxies(text)) {
                        if (!all.containsKey(p.key)) chCount++
                        all[p.key] = p
                    }
                    val nxt = minPostId(text)
                    if (nxt == null || nxt == before) break
                    before = nxt
                }
                log("  + новых прокси из @$ch: $chCount")
            }
            all.values.toList()
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
