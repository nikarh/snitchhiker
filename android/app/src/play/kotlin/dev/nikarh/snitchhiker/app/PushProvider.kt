package dev.nikarh.snitchhiker.app

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging

/**
 * The Play build: woken through FCM, with the Firebase project it was built with (the relay's push gateway holds that
 * project's service account); through UnifiedPush when built without one.
 */
object PushProvider {
    val FCM = BuildConfig.FCM_PROJECT_ID.isNotEmpty()

    fun start(context: Context) {
        if (!FCM) {
            UnifiedPushes.start(context)
            return
        }
        if (FirebaseApp.getApps(context).isEmpty()) {
            FirebaseApp.initializeApp(
                context,
                FirebaseOptions
                    .Builder()
                    .setProjectId(BuildConfig.FCM_PROJECT_ID)
                    .setApplicationId(BuildConfig.FCM_APP_ID)
                    .setApiKey(BuildConfig.FCM_API_KEY)
                    .setGcmSenderId(BuildConfig.FCM_SENDER_ID)
                    .build(),
            )
        }
        // The token comes to FcmService.onRegistered.
        FirebaseMessaging.getInstance().register()
    }
}
