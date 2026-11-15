package dev.nikarh.snitchhiker.app

import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Live mode: a foreground service, so Android keeps the app's connections to its nodes while it is in the background
 * and prompts arrive at once. Its only work is to exist; the sessions are the app's.
 */
class LiveService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        // The special-use type exists from Android 14; before it, a foreground service has none to declare.
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, ID, notification(this), type)
        return START_STICKY
    }

    companion object {
        private const val ID = 1

        private fun notification(context: Context): Notification =
            NotificationCompat
                .Builder(context, Notifications.LIVE)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("Watching your nodes")
                .setContentText("Prompts arrive at once while this is shown.")
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .build()

        fun start(context: Context) {
            context.startForegroundService(Intent(context, LiveService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, LiveService::class.java))
        }
    }
}
