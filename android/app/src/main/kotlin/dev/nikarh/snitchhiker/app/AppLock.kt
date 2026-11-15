package dev.nikarh.snitchhiker.app

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal

/**
 * The app lock: with it on, the app opens only after the device's own check (a biometric or the screen lock's PIN,
 * pattern or password), and notifications only open the app: answering a prompt needs the app unlocked. The check is
 * the platform's `BiometricPrompt`, so no library and no fragment activity.
 */
object AppLock {
    /** Whether the device has a screen lock at all: without one there is nothing to check against. */
    fun available(context: Context): Boolean = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    /** Asks the user to unlock; [done] says whether they did (a cancel leaves the app locked). */
    fun unlock(
        activity: Activity,
        done: (Boolean) -> Unit,
    ) {
        val builder =
            BiometricPrompt
                .Builder(activity)
                .setTitle(activity.getString(R.string.app_name))
                .setSubtitle("Unlock to see and answer what waits on your nodes")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
        } else {
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        }
        builder.build().authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = done(true)

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence?,
                ) = done(false)
            },
        )
    }
}
