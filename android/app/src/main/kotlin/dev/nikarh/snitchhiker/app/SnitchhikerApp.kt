package dev.nikarh.snitchhiker.app

import android.app.Application
import androidx.core.content.edit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The app: its nodes' sessions, live while the process is. */
class SnitchhikerApp : Application() {
    private companion object {
        const val PREFERENCES = "settings"
        const val LIVE = "live"
    }

    private val scope = CoroutineScope(SupervisorJob())
    private val mutableSessions = MutableStateFlow<List<NodeSession>>(emptyList())
    val sessions: StateFlow<List<NodeSession>> = mutableSessions.asStateFlow()

    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        mutableSessions.value = NodeStore.load(this).map { NodeSession(this, it, scope).also(NodeSession::start) }
        live = getSharedPreferences(PREFERENCES, MODE_PRIVATE).getBoolean(LIVE, true)
    }

    /** Live mode: the connections kept in the background by a foreground service (with nodes to keep). */
    var live: Boolean = true
        set(value) {
            field = value
            getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit { putBoolean(LIVE, value) }
            updateLive()
        }

    fun updateLive() {
        if (live && sessions.value.isNotEmpty()) LiveService.start(this) else LiveService.stop(this)
    }

    fun session(id: String): NodeSession? = sessions.value.firstOrNull { it.info.id == id }

    /** Keeps a node just paired, and connects to it. */
    fun add(node: NodeInfo) {
        val kept = NodeStore.load(this).filter { it.id != node.id } + node
        NodeStore.save(this, kept)
        sessions.value.firstOrNull { it.info.id == node.id }?.stop()
        mutableSessions.value = sessions.value.filter { it.info.id != node.id } +
            NodeSession(this, node, scope).also(NodeSession::start)
        updateLive()
    }

    /** Forgets a node (it stays paired on the node until unpaired there). */
    fun forget(id: String) {
        NodeStore.save(this, NodeStore.load(this).filter { it.id != id })
        sessions.value.firstOrNull { it.info.id == id }?.stop()
        mutableSessions.value = sessions.value.filter { it.info.id != id }
        updateLive()
    }

    /** The relays of the nodes paired, where a pairing code is looked for beside the local network. */
    fun relays(): Array<String> =
        sessions.value
            .flatMap { it.info.relays }
            .distinct()
            .toTypedArray()
}
