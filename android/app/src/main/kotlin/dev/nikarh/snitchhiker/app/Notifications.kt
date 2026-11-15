package dev.nikarh.snitchhiker.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import dev.nikarh.snitchhiker.core.NodeState
import snitchhiker.v1.Prompt

/** Notifications: prompts the node's routing says to notify about, and their answers' cancellation. */
object Notifications {
    const val PROMPTS = "prompts"
    const val ALERTS = "alerts"
    const val LIVE = "live"

    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(PROMPTS, context.getString(R.string.channel_prompts), NotificationManager.IMPORTANCE_HIGH)
                .apply { description = context.getString(R.string.channel_prompts_description) },
        )
        manager.createNotificationChannel(
            NotificationChannel(LIVE, context.getString(R.string.channel_live), NotificationManager.IMPORTANCE_MIN)
                .apply { description = context.getString(R.string.channel_live_description) },
        )
        manager.createNotificationChannel(
            NotificationChannel(ALERTS, context.getString(R.string.channel_alerts), NotificationManager.IMPORTANCE_DEFAULT)
                .apply { description = context.getString(R.string.channel_alerts_description) },
        )
    }

    private fun status(node: NodeInfo): String = "status:${node.id}"

    /** Posts a notification, when the app may (from Android 13 the user allows it). */
    private fun post(
        context: Context,
        tag: String,
        id: Int,
        notification: android.app.Notification,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        NotificationManagerCompat.from(context).notify(tag, id, notification)
    }

    /** A node stopped answering: how it went, if it said. */
    fun offline(
        context: Context,
        node: NodeInfo,
        stopping: String?,
    ) {
        val notification =
            NotificationCompat
                .Builder(context, ALERTS)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("${node.name} is offline")
                .setContentText(stopping?.let { "It said: $it" } ?: "It stopped answering without a word.")
                .build()
        post(context, status(node), 0, notification)
    }

    fun online(
        context: Context,
        node: NodeInfo,
    ) {
        val notification =
            NotificationCompat
                .Builder(context, ALERTS)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("${node.name} is back online")
                .setTimeoutAfter(60_000)
                .build()
        post(context, status(node), 0, notification)
    }

    /** One notification per prompt, across nodes. */
    private fun tag(node: NodeInfo): String = "prompt:${node.id}"

    fun onChange(
        context: Context,
        node: NodeInfo,
        before: NodeState,
        after: NodeState,
    ) {
        for ((id, prompt) in after.prompts) {
            // New and to notify about, or escalated to this device just now.
            if (prompt.notify && before.prompts[id]?.notify != true) show(context, node, prompt)
        }
        for (id in before.prompts.keys - after.prompts.keys) {
            NotificationManagerCompat.from(context).cancel(tag(node), id.toInt())
        }
    }

    private fun show(
        context: Context,
        node: NodeInfo,
        prompt: Prompt,
    ) {
        val program = prompt.exe.substringAfterLast('/').ifEmpty { "An unknown program" }
        val destination =
            prompt.hosts.firstOrNull()
                ?: runCatching {
                    java.net.InetAddress
                        .getByAddress(prompt.address.toByteArray())
                        .hostAddress
                }.getOrNull()
                ?: "an address"
        val open =
            PendingIntent.getActivity(
                context,
                prompt.id.toInt(),
                Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_NODE, node.id),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        val suggestion = prompt.suggestions.firstOrNull()?.label ?: "this connection"
        val notification =
            NotificationCompat
                .Builder(context, PROMPTS)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("$program wants to connect")
                .setContentText("to $destination:${prompt.port} on ${node.name}")
                .setStyle(
                    NotificationCompat.BigTextStyle().bigText(
                        "to $destination:${prompt.port} on ${node.name}\nAllow makes the rule: $suggestion",
                    ),
                ).setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setContentIntent(open)
                .setAutoCancel(true)
                .addAction(0, "Allow", PromptActions.intent(context, node, prompt.id, PromptActions.ALLOW))
                .addAction(0, "Deny", PromptActions.intent(context, node, prompt.id, PromptActions.DENY))
                .build()
        post(context, tag(node), prompt.id.toInt(), notification)
    }
}
