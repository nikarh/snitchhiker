package dev.nikarh.snitchhiker.app

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * A push woke the app for a node: a short foreground service keeps it running while its session connects and is sent
 * what waits (a process started by a broadcast is otherwise frozen seconds later, before it gets there). It stops
 * itself after [HOLD_MS]; live mode needs none of it.
 */
class WakeService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val stop = Runnable { stopSelf() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        val app = application as SnitchhikerApp
        val session = intent?.getStringExtra(EXTRA_NODE)?.let(app::session)
        // The short-service type exists from Android 14; before it, a foreground service has none to declare.
        val type =
            if (Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE
            ) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE
            } else {
                0
            }
        val notification =
            NotificationCompat
                .Builder(this, Notifications.LIVE)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("Checking ${session?.info?.name ?: "your nodes"}")
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .build()
        ServiceCompat.startForeground(this, ID, notification, type)
        session?.wake()
        handler.removeCallbacks(stop)
        handler.postDelayed(stop, HOLD_MS)
        return START_NOT_STICKY
    }

    /** The system's limit for a short service: stop at once. */
    override fun onTimeout(startId: Int) = stopSelf()

    override fun onDestroy() {
        handler.removeCallbacks(stop)
        super.onDestroy()
    }

    companion object {
        private const val ID = 2
        private const val EXTRA_NODE = "node"
        private const val HOLD_MS = 30_000L

        /** Wakes `node`'s session, holding the app up for it when it is in the background without live mode. */
        fun wake(
            context: Context,
            node: String,
        ) {
            val app = context.applicationContext as SnitchhikerApp
            if (app.live) {
                app.session(node)?.wake()
                return
            }
            try {
                context.startForegroundService(Intent(context, WakeService::class.java).putExtra(EXTRA_NODE, node))
            } catch (error: IllegalStateException) {
                // Not allowed from where this push came: the session tries in the time it has.
                android.util.Log.w("snitchhiker", "holding the app up for a wake-up: ${error.message}")
                app.session(node)?.wake()
            }
        }
    }
}
