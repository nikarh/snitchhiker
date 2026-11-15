package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import dev.nikarh.snitchhiker.app.NodeSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import snitchhiker.v1.Action
import snitchhiker.v1.ConnectionEvent
import snitchhiker.v1.Notice
import snitchhiker.v1.Topic

/** How many connections the page keeps. */
private const val KEPT = 200

/** Connections as they are decided, on a connection of the page's own while it is shown. */
@Composable
fun LivePage(
    session: NodeSession,
    modifier: Modifier,
) {
    var events by remember { mutableStateOf(emptyList<ConnectionEvent>()) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(session) {
        withContext(Dispatchers.IO) {
            val link = runCatching { session.openLink() }.onFailure { error = it.message }.getOrNull() ?: return@withContext
            try {
                link.subscribe(Topic.TOPIC_EVENTS.value)
                while (currentCoroutineContext().isActive) {
                    val bytes = link.nextNotice(1000) ?: continue
                    Notice.ADAPTER
                        .decode(bytes)
                        .event
                        ?.let { event -> events = (listOf(event) + events).take(KEPT) }
                }
            } catch (e: Exception) {
                error = e.message
            } finally {
                link.close()
            }
        }
    }
    val minute = System.currentTimeMillis() - 60_000
    val recent = events.filter { it.time_ms >= minute }
    Page(modifier) {
        item {
            Item {
                Text(
                    "${recent.count {
                        it.action == Action.ACTION_ALLOW
                    }} allowed · ${recent.count { it.action != Action.ACTION_ALLOW }} blocked",
                    style = MaterialTheme.typography.titleMedium,
                )
                Muted("in the last minute")
            }
        }
        item { Problem(error) }
        items(events, key = { it.seq }) { event ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(inContext(event.container, event.exe.substringAfterLast('/').ifEmpty { "?" }), modifier = Modifier.weight(1f))
                Text("${event.host.ifEmpty { address(event.address) }}:${event.port}", modifier = Modifier.weight(1.4f))
                Text(actionName(event.action), color = actionColor(event.action))
            }
        }
    }
}
