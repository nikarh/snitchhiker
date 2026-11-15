package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.core.NodeState
import kotlinx.coroutines.launch
import snitchhiker.v1.AcknowledgeAlerts
import snitchhiker.v1.ListAlerts
import snitchhiker.v1.Request

/** The node's alerts: acknowledged here, they are for every client. */
@Composable
fun AlertsPage(
    session: NodeSession,
    state: NodeState,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val alerts = rememberRequest(session, state.openAlerts, { Request(list_alerts = ListAlerts(limit = 200)) }) { it.alerts }
    Page(modifier) {
        item {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("${alerts.value?.open_ ?: 0} not acknowledged", modifier = Modifier.weight(1f))
                OutlinedButton(onClick = {
                    scope.launch {
                        run(session, Request(acknowledge_alerts = AcknowledgeAlerts(all = true)))
                        alerts.reload()
                    }
                }) { Text("Acknowledge all") }
            }
        }
        item { Problem(alerts.error) }
        items(alerts.value?.alerts.orEmpty(), key = { it.id }) { alert ->
            Item {
                Text(alert.title, style = MaterialTheme.typography.titleSmall)
                Text(alert.body)
                Muted("${time(alert.time_ms)} · ${alert.kind}" + if (alert.acknowledged) " · acknowledged" else "")
                if (!alert.acknowledged) {
                    TextButton(onClick = {
                        scope.launch {
                            run(session, Request(acknowledge_alerts = AcknowledgeAlerts(ids = listOf(alert.id))))
                            alerts.reload()
                        }
                    }) { Text("Acknowledge") }
                }
            }
        }
    }
}
