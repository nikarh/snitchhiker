package dev.nikarh.snitchhiker.app

import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/** UnifiedPush's side: the distributor's endpoint (with the keys pushes are encrypted to), and its messages. */
class UnifiedPushService : PushService() {
    override fun onNewEndpoint(
        endpoint: PushEndpoint,
        instance: String,
    ) {
        val keys = endpoint.pubKeySet ?: return
        Push.set(this, Push.unifiedPush(endpoint.url, keys.pubKey, keys.auth))
    }

    override fun onMessage(
        message: PushMessage,
        instance: String,
    ) {
        // A push not encrypted to this phone's keys isn't the gateway's.
        if (message.decrypted) Push.received(this, message.content)
    }

    override fun onRegistrationFailed(
        reason: FailedReason,
        instance: String,
    ) {
        android.util.Log.w("snitchhiker", "UnifiedPush registration failed: $reason")
    }

    override fun onUnregistered(instance: String) = Push.set(this, null)
}
