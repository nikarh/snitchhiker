package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import dev.nikarh.snitchhiker.app.NodeSession
import snitchhiker.v1.ListEvents
import snitchhiker.v1.Request

/** The newest connections, filtered with the query language. */
@Composable
fun EventsPage(
    session: NodeSession,
    modifier: Modifier,
) {
    var typed by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    var explained by remember { mutableStateOf<Long?>(null) }
    explained?.let { seq -> Explain(session, seq) { explained = null } }
    val events =
        rememberRequest(session, query, { Request(list_events = ListEvents(limit = 300, query = query)) }) { it.events?.events }
    Page(modifier) {
        item {
            OutlinedTextField(
                value = typed,
                onValueChange = { typed = it },
                label = { Text("Filter") },
                placeholder = { Text("curl  host:*.example.com  -action:allow") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { query = typed.trim() }),
            )
        }
        item { Problem(events.error) }
        items(events.value.orEmpty(), key = { it.seq }) { event ->
            Item(Modifier.clickable { explained = event.seq }) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(
                        event.exe.ifEmpty { "(unknown program)" },
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.weight(1f),
                    )
                    Text(actionName(event.action), color = actionColor(event.action), style = MaterialTheme.typography.labelLarge)
                }
                Text("${event.host.ifEmpty { address(event.address) }}:${event.port}/${protocol(event.protocol)}")
                Muted("${time(event.time_ms)} · uid ${event.uid}")
            }
        }
    }
}

/** Why a recorded connection is decided as it is, by today's rules: every rule that matches it, the deciding first. */
@Composable
private fun Explain(
    session: NodeSession,
    seq: Long,
    close: () -> Unit,
) {
    val explanation =
        rememberRequest(session, seq, { Request(explain = snitchhiker.v1.Explain(seq = seq)) }) { it.explanation }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = close,
        confirmButton = { androidx.compose.material3.TextButton(onClick = close) { Text("Close") } },
        title = { Text("Why") },
        text = {
            androidx.compose.foundation.layout.Column {
                Problem(explanation.error)
                val value = explanation.value
                when {
                    value == null -> {
                        Muted("Loading…")
                    }

                    value.rules.isEmpty() -> {
                        Text("No rule matches it now: the policy decides.")
                    }

                    else -> {
                        value.rules.forEachIndexed { index, rule ->
                            Text(
                                (if (index == 0) "Decides: " else "Also matches: ") +
                                    "${rule.name} (${actionName(rule.action)}, ${rule.tier.name.removePrefix("TIER_").lowercase()})",
                            )
                        }
                    }
                }
                if (value?.partial == true) Muted("Rules on command lines or parent programs can't be checked against history.")
            }
        },
    )
}
