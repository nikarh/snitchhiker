package dev.nikarh.snitchhiker.app

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.nikarh.snitchhiker.app.ui.LockedScreen
import dev.nikarh.snitchhiker.app.ui.NodeScreen
import dev.nikarh.snitchhiker.app.ui.NodesScreen
import dev.nikarh.snitchhiker.app.ui.PairScreen
import dev.nikarh.snitchhiker.app.ui.SnitchhikerTheme

/** Where the app is. */
sealed interface Screen {
    data object Nodes : Screen

    data class Pair(
        val prefill: String = "",
    ) : Screen

    data class Node(
        val id: String,
    ) : Screen
}

class MainActivity : ComponentActivity() {
    private var screen by mutableStateOf<Screen>(Screen.Nodes)

    /** Whether the content shows (the app lock is off, or it was unlocked). */
    private var open by mutableStateOf(true)

    /** The unlock prompt is showing: resuming from it doesn't ask again. */
    private var prompting = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        val app = application as SnitchhikerApp
        handle(intent, app)
        app.updateLive()
        if (!PushProvider.FCM) UnifiedPushes.useDefault(this)
        open = app.open
        setContent {
            SnitchhikerTheme {
                if (!open) {
                    LockedScreen(unlock = ::unlock)
                    return@SnitchhikerTheme
                }
                when (val current = screen) {
                    Screen.Nodes -> {
                        NodesScreen(
                            app = app,
                            open = { screen = Screen.Node(it) },
                            add = { screen = Screen.Pair() },
                        )
                    }

                    is Screen.Pair -> {
                        BackHandler { screen = Screen.Nodes }
                        PairScreen(app = app, prefill = current.prefill, done = { id ->
                            screen = if (id == null) Screen.Nodes else Screen.Node(id)
                        })
                    }

                    is Screen.Node -> {
                        BackHandler { screen = Screen.Nodes }
                        val session = app.session(current.id)
                        if (session == null) {
                            screen = Screen.Nodes
                        } else {
                            NodeScreen(session = session, app = app, back = { screen = Screen.Nodes })
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        open = (application as SnitchhikerApp).open
        if (!open) unlock()
    }

    override fun onStop() {
        super.onStop()
        // Locked again once out of sight, but not by turning the screen.
        if (!isChangingConfigurations) (application as SnitchhikerApp).unlocked = false
    }

    private fun unlock() {
        if (prompting) return
        prompting = true
        AppLock.unlock(this) { unlocked ->
            prompting = false
            val app = application as SnitchhikerApp
            if (unlocked) app.unlocked = true
            open = app.open
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent, application as SnitchhikerApp)
    }

    /** A pairing link opened, or a notification of a node tapped. */
    private fun handle(
        intent: Intent?,
        app: SnitchhikerApp,
    ) {
        val link = intent?.data?.toString()
        if (link != null && link.startsWith("snitchhiker://pair")) {
            screen = Screen.Pair(prefill = link)
            return
        }
        intent?.getStringExtra(EXTRA_NODE)?.let { id -> if (app.session(id) != null) screen = Screen.Node(id) }
    }

    companion object {
        const val EXTRA_NODE = "node"
    }
}
