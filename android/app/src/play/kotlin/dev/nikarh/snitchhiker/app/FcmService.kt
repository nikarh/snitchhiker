package dev.nikarh.snitchhiker.app

import android.util.Base64
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/** FCM's side: its registration token, and data messages from the push gateway (`m`: an encoded `PushMessage`). */
class FcmService : FirebaseMessagingService() {
    override fun onRegistered(token: String) = Push.set(this, Push.fcm(token))

    /** The token as Firebase reported it before `register()` (and may still, after a refresh). */
    @Deprecated("Firebase reports tokens to onRegistered")
    override fun onNewToken(token: String) = Push.set(this, Push.fcm(token))

    override fun onUnregistered(token: String) = Push.set(this, null)

    override fun onMessageReceived(message: RemoteMessage) {
        val content = message.data["m"] ?: return
        runCatching { Base64.decode(content, Base64.DEFAULT) }.getOrNull()?.let { Push.received(this, it) }
    }
}
