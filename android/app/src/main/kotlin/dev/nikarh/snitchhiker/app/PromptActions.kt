package dev.nikarh.snitchhiker.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import snitchhiker.v1.Action
import snitchhiker.v1.AnswerPrompt
import snitchhiker.v1.Duration
import snitchhiker.v1.Request

/**
 * A prompt's notification actions: Allow makes the suggested rule (the narrowest, kept), Deny refuses the
 * connections waiting, once. Answered through the node's session.
 */
class PromptActions : BroadcastReceiver() {
    override fun onReceive(
        context: Context,
        intent: Intent,
    ) {
        val app = context.applicationContext as SnitchhikerApp
        val session = app.session(intent.getStringExtra(EXTRA_NODE) ?: return) ?: return
        val prompt = intent.getLongExtra(EXTRA_PROMPT, 0)
        val allow = intent.action == ALLOW
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                session.call(
                    Request(
                        answer_prompt =
                            AnswerPrompt(
                                id = prompt,
                                action = if (allow) Action.ACTION_ALLOW else Action.ACTION_DENY,
                                duration = if (allow) Duration.DURATION_FOREVER else Duration.DURATION_ONCE,
                                suggestion = 0,
                            ),
                    ),
                )
            } catch (_: Exception) {
                // Answered elsewhere, timed out, or the node is gone: the prompt's resolution says which.
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ALLOW = "dev.nikarh.snitchhiker.ALLOW"
        const val DENY = "dev.nikarh.snitchhiker.DENY"
        private const val EXTRA_NODE = "node"
        private const val EXTRA_PROMPT = "prompt"

        fun intent(
            context: Context,
            node: NodeInfo,
            prompt: Long,
            action: String,
        ): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                (prompt * 2 + if (action == ALLOW) 1 else 0).toInt(),
                Intent(context, PromptActions::class.java)
                    .setAction(action)
                    .putExtra(EXTRA_NODE, node.id)
                    .putExtra(EXTRA_PROMPT, prompt),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
    }
}
