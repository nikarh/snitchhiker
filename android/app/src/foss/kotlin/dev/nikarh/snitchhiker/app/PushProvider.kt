package dev.nikarh.snitchhiker.app

import android.content.Context

/** The F-Droid build: woken through UnifiedPush only. */
object PushProvider {
    const val FCM = false

    fun start(context: Context) = UnifiedPushes.start(context)
}
