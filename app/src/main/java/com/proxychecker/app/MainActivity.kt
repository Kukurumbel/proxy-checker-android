package com.proxychecker.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

// --- цвета в стиле Telegram (как в .exe-версии) ---
private val BG = Color(0xFF0E1621)
private val BG2 = Color(0xFF17212B)
private val CARD = Color(0xFF1C2733)
private val FG = Color(0xFFE9EEF3)
private val MUTED = Color(0xFF7A8A99)
private val ACCENT = Color(0xFF3390EC)
private val OK = Color(0xFF4DD07A)
private val BAD = Color(0xFFE06666)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = BG) {
                    ProxyScreen()
                }
            }
        }
    }
}

@Composable
private fun ProxyScreen() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    var running by remember { mutableStateOf(false) }
    var status by remember {
        mutableStateOf("Готово. Нажми «Проверить все прокси».")
    }
    var progress by remember { mutableStateOf(0f) }
    var results by remember {
        mutableStateOf<List<ProxyChecker.Result>>(emptyList())
    }

    fun runCheck() {
        if (running) return
        running = true
        results = emptyList()
        progress = 0f
        scope.launch {
            try {
                val proxies = ProxyChecker.collectProxies { msg -> status = msg }
                if (proxies.isEmpty()) {
                    status = "Прокси не найдены. Проверь интернет/каналы."
                    return@launch
                }
                status = "Проверяю ${proxies.size} прокси..."
                val res = ProxyChecker.checkAll(proxies) { done, total ->
                    progress = done.toFloat() / total
                    status = "Проверено $done/$total..."
                }
                results = res
                val working = res.count { it.ok }
                status = if (working > 0) {
                    val best = res.first { it.ok }.pingMs
                    "Готово: $working рабочих из ${res.size} " +
                        "(лимит ${ProxyChecker.PING_LIMIT_MS} мс, лучший $best мс)"
                } else {
                    "Рабочих прокси с пингом ≤ ${ProxyChecker.PING_LIMIT_MS} мс " +
                        "не найдено. Попробуй позже."
                }
            } catch (e: Exception) {
                status = "Ошибка: ${e.message}"
            } finally {
                running = false
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // --- шапка ---
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("✈", fontSize = 22.sp, color = ACCENT)
            Spacer(Modifier.width(8.dp))
            Text(
                "Telegram Proxy Checker",
                color = FG, fontSize = 20.sp, fontWeight = FontWeight.Bold
            )
        }
        Text(
            "источники: @${ProxyChecker.CHANNELS.joinToString(", @")} · без VPN",
            color = MUTED, fontSize = 12.sp,
            modifier = Modifier.padding(top = 4.dp)
        )

        Spacer(Modifier.height(16.dp))

        // --- кнопки ---
        Row(modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { runCheck() },
                enabled = !running,
                colors = ButtonDefaults.buttonColors(
                    containerColor = ACCENT, contentColor = Color.White,
                    disabledContainerColor = CARD, disabledContentColor = MUTED
                ),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null,
                    modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(if (running) "Проверяю..." else "Проверить все прокси")
            }
            Spacer(Modifier.width(10.dp))
            Button(
                onClick = {
                    val links = results.filter { it.ok }
                        .joinToString("\n") { it.proxy.link() }
                    if (links.isNotEmpty()) {
                        copyToClipboard(context, links)
                        toast(context, "Скопировано в буфер")
                    }
                },
                enabled = results.any { it.ok },
                colors = ButtonDefaults.buttonColors(
                    containerColor = CARD, contentColor = FG,
                    disabledContainerColor = CARD, disabledContentColor = MUTED
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = null,
                    modifier = Modifier.size(18.dp))
            }
        }

        Spacer(Modifier.height(12.dp))

        // --- прогресс ---
        if (running) {
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
                color = ACCENT, trackColor = BG2
            )
            Spacer(Modifier.height(8.dp))
        }

        // --- список ---
        Box(
            modifier = Modifier.weight(1f).fillMaxWidth()
                .background(BG2, RoundedCornerShape(10.dp))
        ) {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(6.dp)) {
                items(results) { r -> ProxyRow(r, context) }
            }
        }

        Spacer(Modifier.height(10.dp))
        Text(status, color = MUTED, fontSize = 12.sp)
    }
}

@Composable
private fun ProxyRow(r: ProxyChecker.Result, context: Context) {
    val clickable = r.ok
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .background(CARD, RoundedCornerShape(8.dp))
            .then(
                if (clickable) Modifier.clickable {
                    openProxy(context, r.proxy.link())
                } else Modifier
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            if (r.ok) "●" else "○",
            color = if (r.ok) OK else BAD,
            fontSize = 14.sp
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "${r.proxy.server}:${r.proxy.port}",
                color = FG, fontSize = 14.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                if (r.ok) "нажми — добавить в Telegram"
                else "не отвечает",
                color = MUTED, fontSize = 11.sp, maxLines = 1
            )
        }
        Spacer(Modifier.width(8.dp))
        Text(
            when {
                r.ok -> "${r.pingMs} мс"
                r.pingMs != null -> "${r.pingMs} (>лимит)"
                else -> "—"
            },
            color = if (r.ok) OK else MUTED,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

// --- системные действия ---

private fun openProxy(context: Context, link: String) {
    // tg://proxy откроет Telegram напрямую; https-ссылка — через выбор приложения
    try {
        val tgUri = link.replace("https://t.me/proxy?", "tg://proxy?")
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(tgUri)))
    } catch (e: Exception) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)))
        } catch (e2: Exception) {
            copyToClipboard(context, link)
            toast(context, "Telegram не найден — ссылка скопирована")
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("proxy", text))
}

private fun toast(context: Context, msg: String) {
    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
}
