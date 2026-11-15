package dev.nikarh.snitchhiker.app

import android.app.Activity
import android.content.Context
import org.unifiedpush.android.connector.UnifiedPush

/** Registering with a UnifiedPush distributor (ntfy, for example) installed on the phone. */
object UnifiedPushes {
    /** Registers again with the distributor chosen before (the endpoint is renewed), if there is one. */
    fun start(context: Context) {
        if (UnifiedPush.getAckDistributor(context) != null) UnifiedPush.register(context)
    }

    /** With none chosen yet: the distributor the user made the default, or the only one there is. */
    fun useDefault(activity: Activity) {
        if (UnifiedPush.getAckDistributor(activity) != null) return
        UnifiedPush.tryUseCurrentOrDefaultDistributor(activity) { found ->
            if (found) UnifiedPush.register(activity)
        }
    }

    /** Asks which distributor to use (with several installed), then registers with it. */
    fun pick(
        activity: Activity,
        done: () -> Unit,
    ) {
        UnifiedPush.tryPickDistributor(activity) { picked ->
            if (picked) UnifiedPush.register(activity)
            done()
        }
    }

    /** The distributor used, by its name, if any. */
    fun distributor(context: Context): String? =
        UnifiedPush.getAckDistributor(context)?.let { name ->
            runCatching {
                val pm = context.packageManager
                pm.getApplicationLabel(pm.getApplicationInfo(name, 0)).toString()
            }.getOrDefault(name)
        }

    fun available(context: Context): Boolean = UnifiedPush.getDistributors(context).isNotEmpty()
}
