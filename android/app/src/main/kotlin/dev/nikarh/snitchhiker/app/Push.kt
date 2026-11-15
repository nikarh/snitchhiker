package dev.nikarh.snitchhiker.app

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import okio.ByteString.Companion.toByteString
import snitchhiker.v1.FcmToken
import snitchhiker.v1.PushKind
import snitchhiker.v1.PushMessage
import snitchhiker.v1.PushTarget
import snitchhiker.v1.Request
import snitchhiker.v1.SetPushTarget
import snitchhiker.v1.UnifiedPush

/**
 * Push (plan §8.5): where this phone is woken (a UnifiedPush endpoint, or an FCM token in the Play build), told to each
 * node on connecting and when it changes; and what a push says. A wake-up says only "connect": the session connects and
 * the node sends what waits, with its notifications. A node's push gateway also says when the node went offline (it
 * can't), and when it is back.
 */
object Push {
    private const val PREFERENCES = "push"
    private const val TARGET = "target"
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Where this phone is woken now, if anywhere. */
    fun target(context: Context): PushTarget? =
        context
            .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(TARGET, null)
            ?.let { runCatching { PushTarget.ADAPTER.decode(Base64.decode(it, Base64.NO_WRAP)) }.getOrNull() }

    /** The push service gave a new target (or took it away): kept, and told to every node. */
    fun set(
        context: Context,
        target: PushTarget?,
    ) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit {
            if (target == null) remove(TARGET) else putString(TARGET, Base64.encodeToString(target.encode(), Base64.NO_WRAP))
        }
        val app = context.applicationContext as SnitchhikerApp
        for (session in app.sessions.value) scope.launch { runCatching { tell(session, target) } }
    }

    /** Tells a node where this phone is woken. */
    suspend fun tell(
        session: NodeSession,
        target: PushTarget?,
    ) {
        session.call(Request(set_push_target = SetPushTarget(target = target)))
    }

    fun unifiedPush(
        endpoint: String,
        publicKey: String,
        auth: String,
    ): PushTarget =
        PushTarget(
            unified_push =
                UnifiedPush(
                    endpoint = endpoint,
                    p256dh = Base64.decode(publicKey, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING).toByteString(),
                    auth = Base64.decode(auth, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING).toByteString(),
                ),
        )

    fun fcm(token: String): PushTarget = PushTarget(fcm = FcmToken(token = token))

    /** A push arrived (decrypted): an encoded `PushMessage`. */
    fun received(
        context: Context,
        content: ByteArray,
    ) {
        val message = runCatching { PushMessage.ADAPTER.decode(content) }.getOrNull() ?: return
        val app = context.applicationContext as SnitchhikerApp
        val session = app.session(message.node) ?: return
        when (message.kind) {
            PushKind.PUSH_KIND_WAKE -> {
                session.wake()
            }

            PushKind.PUSH_KIND_OFFLINE -> {
                Notifications.offline(context, session.info, message.reason.ifEmpty { null })
            }

            PushKind.PUSH_KIND_ONLINE -> {
                Notifications.online(context, session.info)
                // Alerts it raised starting again (a crash) are fetched.
                WakeService.wake(context, session.info.id)
            }

            else -> {}
        }
    }
}
