package dev.nikarh.snitchhiker.app

import android.content.Context
import dev.nikarh.snitchhiker.core.NodeClient
import dev.nikarh.snitchhiker.core.NodeState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import snitchhiker.v1.GetStatus
import snitchhiker.v1.Request
import snitchhiker.v1.Response
import snitchhiker.v1.Topic
import java.io.IOException

/**
 * A paired node, while the app runs: two connections (requests, notices) kept up with backoff, and what its notices
 * say folded into [state].
 */
class NodeSession(
    private val context: Context,
    val info: NodeInfo,
    private val scope: CoroutineScope,
) {
    private val mutableState = MutableStateFlow(NodeState())
    val state: StateFlow<NodeState> = mutableState.asStateFlow()

    @Volatile private var client: NodeClient? = null
    private var job: Job? = null

    fun start() {
        if (job != null) return
        job =
            scope.launch(Dispatchers.IO) {
                var backoff = BACKOFF_MIN_MS
                // Since when the node hasn't answered (it was connected before), and whether that was told.
                var offlineSince: Long? = null
                var told = false
                while (isActive) {
                    try {
                        val key = DeviceKey.get(context)
                        val connected = NodeClient(RustLink(key, info), RustLink(key, info))
                        client = connected
                        // The subscriptions send what waits now: the lists start again from that.
                        mutableState.update { NodeState(connected = true, openAlerts = it.openAlerts) }
                        if (told) Notifications.online(context, info)
                        offlineSince = null
                        told = false
                        backoff = BACKOFF_MIN_MS
                        refreshStatus()
                        connected.notices(TOPICS).collect { notice ->
                            val before = mutableState.value
                            val after = before.apply(notice)
                            mutableState.value = after
                            Notifications.onChange(context, info, before, after)
                        }
                    } catch (error: Exception) {
                        android.util.Log.w("snitchhiker", "${info.name}: ${error.message}")
                        mutableState.update { it.copy(connected = false, error = error.message) }
                    }
                    client?.close()
                    client = null
                    val now = System.currentTimeMillis()
                    val since = offlineSince ?: now.also { offlineSince = it }
                    if (!told && now - since >= OFFLINE_AFTER_MS) {
                        Notifications.offline(context, info, mutableState.value.stopping)
                        told = true
                    }
                    delay(backoff)
                    backoff = (backoff * 2).coerceAtMost(BACKOFF_MAX_MS)
                }
            }
    }

    fun stop() {
        job?.cancel()
        job = null
        client?.close()
        client = null
    }

    /** A request to the node; its response, or an error. */
    suspend fun call(request: Request): Response = client?.call(request) ?: throw IOException("not connected to ${info.name}")

    suspend fun refreshStatus() {
        val status = runCatching { call(Request(get_status = GetStatus())).status }.getOrNull() ?: return
        mutableState.update { it.copy(status = status, openAlerts = status.open_alerts) }
    }

    private companion object {
        val TOPICS =
            listOf(Topic.TOPIC_PROMPTS, Topic.TOPIC_ALERTS, Topic.TOPIC_PROPOSALS, Topic.TOPIC_APPROVALS, Topic.TOPIC_RULES)
        const val BACKOFF_MIN_MS = 1_000L
        const val BACKOFF_MAX_MS = 30_000L

        /** How long a node may not answer before it is reported offline. */
        const val OFFLINE_AFTER_MS = 120_000L
    }
}
