package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.core.NodeState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import snitchhiker.v1.Action
import snitchhiker.v1.AnswerPrompt
import snitchhiker.v1.Approval
import snitchhiker.v1.DecideApproval
import snitchhiker.v1.Duration
import snitchhiker.v1.Prompt
import snitchhiker.v1.Request

private val durations =
    listOf(
        Duration.DURATION_ONCE to "Once",
        Duration.DURATION_UNTIL_RESTART to "Until restart",
        Duration.DURATION_HOUR to "1 hour",
        Duration.DURATION_HALF_DAY to "12 hours",
        Duration.DURATION_FOREVER to "Forever",
    )

/** How long a new prompt's buttons stay disarmed, so a tap meant for something else can't answer it. */
private const val ARM_AFTER_MS = 800L

@Composable
fun PromptsPage(
    session: NodeSession,
    state: NodeState,
    modifier: Modifier,
) {
    Page(modifier) {
        if (state.prompts.isEmpty() && state.approvals.isEmpty()) {
            item { Muted("No connection is waiting for an answer.") }
        }
        if (state.prompts.size > 1) item { AnswerAll(session, state.prompts.keys.toList()) }
        items(state.approvals.values.toList(), key = { "approval-${it.id}" }) { ApprovalCard(session, it) }
        items(state.prompts.values.sortedBy { it.created_ms }, key = { "prompt-${it.id}" }) { PromptCard(session, it) }
    }
}

/** Every prompt at once: allowed with its narrowest rule (kept), or denied once. */
@Composable
private fun AnswerAll(
    session: NodeSession,
    ids: List<Long>,
) {
    val scope = rememberCoroutineScope()

    fun answer(action: Action) {
        scope.launch {
            for (id in ids) {
                val duration = if (action == Action.ACTION_ALLOW) Duration.DURATION_FOREVER else Duration.DURATION_ONCE
                run(session, Request(answer_prompt = AnswerPrompt(id = id, action = action, duration = duration, suggestion = 0)))
            }
        }
    }
    Item {
        Text("${ids.size} waiting", style = MaterialTheme.typography.titleMedium)
        Muted("All at once: allowed with each one's narrowest rule, or denied this time.")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { answer(Action.ACTION_ALLOW) }) { Text("Allow all") }
            OutlinedButton(onClick = { answer(Action.ACTION_DENY) }) { Text("Deny all") }
        }
    }
}

@Composable
private fun ApprovalCard(
    session: NodeSession,
    approval: Approval,
) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    Item {
        Text("${approval.device} asks", style = MaterialTheme.typography.titleMedium)
        Text("to ${approval.action}.")
        Muted("A device, over the network (${approval.fingerprint}). Only a client on the node, or root, can approve it.")
        Problem(error)
        OutlinedButton(onClick = {
            scope.launch { error = run(session, Request(decide_approval = DecideApproval(id = approval.id, approve = false))) }
        }) { Text("Deny") }
    }
}

@Composable
private fun PromptCard(
    session: NodeSession,
    prompt: Prompt,
) {
    val scope = rememberCoroutineScope()
    var suggestion by remember { mutableIntStateOf(0) }
    var duration by remember { mutableIntStateOf(durations.size - 1) }
    var armed by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(prompt.id) {
        delay(ARM_AFTER_MS)
        armed = true
    }

    fun answer(action: Action) {
        scope.launch {
            error =
                run(
                    session,
                    Request(
                        answer_prompt =
                            AnswerPrompt(
                                id = prompt.id,
                                action = action,
                                duration = durations[duration].first,
                                suggestion = suggestion,
                            ),
                    ),
                )
        }
    }
    val destination = prompt.hosts.firstOrNull() ?: address(prompt.address)
    Item {
        Text(prompt.exe.ifEmpty { "An unknown program" }, style = MaterialTheme.typography.titleMedium)
        Muted(
            "${prompt.user.ifEmpty { prompt.uid.toString() }} → $destination:${prompt.port} (${protocol(
                prompt.protocol,
            )}), ${prompt.waiting} waiting",
        )
        if (prompt.exe_writable) Text("Its executable is writable by a user other than root", color = MaterialTheme.colorScheme.tertiary)
        if (prompt.agent_note.isNotEmpty()) {
            Muted("The agent that started it says (not verified):")
            Text(prompt.agent_note)
        }
        prompt.suggestions.forEachIndexed { index, it ->
            Row(
                Modifier.fillMaxWidth().selectable(selected = suggestion == index, onClick = { suggestion = index }),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = suggestion == index, onClick = { suggestion = index })
                Text(it.label, modifier = Modifier.weight(1f))
                if (it.broad) Text("broad", color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.labelMedium)
            }
        }
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            durations.forEachIndexed { index, (_, label) ->
                FilterChip(selected = duration == index, onClick = { duration = index }, label = { Text(label) })
            }
        }
        Problem(error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = armed, onClick = { answer(Action.ACTION_ALLOW) }) { Text("Allow") }
            OutlinedButton(enabled = armed, onClick = { answer(Action.ACTION_DENY) }) { Text("Deny") }
            OutlinedButton(
                enabled = armed,
                onClick = { answer(Action.ACTION_REJECT) },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Text("Reject") }
        }
    }
}
