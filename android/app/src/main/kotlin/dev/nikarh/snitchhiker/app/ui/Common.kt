package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.core.graphics.set
import dev.nikarh.snitchhiker.app.NodeSession
import okio.ByteString
import snitchhiker.v1.Action
import snitchhiker.v1.Request
import snitchhiker.v1.Response
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** A request's result, loaded when shown and again on [reload] (or when [key] changes). */
class Loaded<T>(
    val value: T?,
    val error: String?,
    val reload: () -> Unit,
)

@Composable
fun <T> rememberRequest(
    session: NodeSession,
    key: Any?,
    request: () -> Request,
    pick: (Response) -> T?,
): Loaded<T> {
    var value by remember { mutableStateOf<T?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var generation by remember { mutableIntStateOf(0) }
    LaunchedEffect(key, generation) {
        runCatching { pick(session.call(request())) }
            .onSuccess {
                value = it
                error = null
            }.onFailure { error = it.message }
    }
    return Loaded(value, error) { generation++ }
}

/** Runs a request from a click; reports its error. */
suspend fun run(
    session: NodeSession,
    request: Request,
): String? = runCatching { session.call(request) }.exceptionOrNull()?.message

private val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT)

fun time(ms: Long): String = if (ms == 0L) "" else timeFormat.format(Date(ms))

fun address(bytes: ByteString): String = runCatching { InetAddress.getByAddress(bytes.toByteArray()).hostAddress }.getOrNull() ?: ""

fun protocol(number: Int): String =
    when (number) {
        6 -> "tcp"
        17 -> "udp"
        1 -> "icmp"
        58 -> "icmpv6"
        else -> number.toString()
    }

@Composable
fun actionColor(action: Action): Color =
    when (action) {
        Action.ACTION_ALLOW -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.error
    }

fun actionName(action: Action): String =
    when (action) {
        Action.ACTION_ALLOW -> "allow"
        Action.ACTION_DENY -> "deny"
        Action.ACTION_REJECT -> "reject"
        Action.ACTION_UNSPECIFIED -> "?"
    }

/** A scrolling page of cards. */
@Composable
fun Page(
    modifier: Modifier = Modifier,
    content: LazyListScope.() -> Unit,
) {
    LazyColumn(
        modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

/** A card whose text gets the whole width: its controls go in its top line. */
@Composable
fun Item(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Card(
        modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) { content() }
    }
}

@Composable
fun Muted(text: String) {
    Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
}

@Composable
fun Problem(text: String?) {
    if (text != null) Text(text, color = MaterialTheme.colorScheme.error)
}

/** Hands `text` to the share sheet (another app, a file, a message), as `name`. */
fun share(
    context: android.content.Context,
    name: String,
    text: String,
    mime: String = "text/plain",
) {
    val send =
        android.content
            .Intent(android.content.Intent.ACTION_SEND)
            .setType(mime)
            .putExtra(android.content.Intent.EXTRA_SUBJECT, name)
            .putExtra(android.content.Intent.EXTRA_TITLE, name)
            .putExtra(android.content.Intent.EXTRA_TEXT, text)
    context.startActivity(
        android.content.Intent
            .createChooser(send, name)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
    )
}

/** Rows as CSV (RFC 4180): fields with commas, quotes or line breaks are quoted. */
fun csv(rows: List<List<String>>): String =
    rows.joinToString("\r\n") { row ->
        row.joinToString(",") { field ->
            if (field.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
                "\"" + field.replace("\"", "\"\"") + "\""
            } else {
                field
            }
        }
    } + "\r\n"

/** `text` as a QR code (black on white, with its quiet zone), or null if it doesn't fit one. */
fun qrBitmap(text: String): androidx.compose.ui.graphics.ImageBitmap? =
    runCatching {
        val matrix =
            com.google.zxing.qrcode.QRCodeWriter().encode(
                text,
                com.google.zxing.BarcodeFormat.QR_CODE,
                0,
                0,
                mapOf(com.google.zxing.EncodeHintType.MARGIN to 2),
            )
        val scale = 8
        val bitmap =
            androidx.core.graphics.createBitmap(matrix.width * scale, matrix.height * scale, android.graphics.Bitmap.Config.RGB_565)
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                val color = if (matrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
                for (dy in 0 until scale) for (dx in 0 until scale) bitmap[x * scale + dx, y * scale + dy] = color
            }
        }
        bitmap.asImageBitmap()
    }.getOrNull()
