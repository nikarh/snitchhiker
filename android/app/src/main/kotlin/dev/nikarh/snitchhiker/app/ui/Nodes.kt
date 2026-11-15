package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.app.SnitchhikerApp

/** The nodes paired: each with whether it is reachable and what waits on it. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodesScreen(
    app: SnitchhikerApp,
    open: (String) -> Unit,
    add: () -> Unit,
) {
    val sessions by app.sessions.collectAsState()
    Scaffold(
        topBar = { TopAppBar(title = { Text("Nodes") }) },
        floatingActionButton = {
            ExtendedFloatingActionButton(onClick = add, icon = { Icon(Icons.Default.Add, null) }, text = { Text("Add node") })
        },
    ) { padding ->
        if (sessions.isEmpty()) {
            Column(Modifier.padding(padding).padding(16.dp)) {
                Text("No node yet.", style = MaterialTheme.typography.titleMedium)
                Text(
                    "On a machine running Snitchhiker, run `sudo snitchhiker pair`, then add it here with its code, its link " +
                        "or its QR code.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                Modifier.fillMaxSize().padding(padding),
                contentPadding =
                    androidx.compose.foundation.layout
                        .PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(sessions, key = { it.info.id }) { session -> NodeCard(session) { open(session.info.id) } }
                item { LiveSwitch(app) }
            }
        }
    }
}

/** Live mode on or off: whether the app stays connected in the background. */
@Composable
private fun LiveSwitch(app: SnitchhikerApp) {
    var live by remember { mutableStateOf(app.live) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Stay connected in the background", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                Switch(checked = live, onCheckedChange = {
                    live = it
                    app.live = it
                })
            }
            Text(
                "Prompts arrive at once, with an ongoing notification while the app is in the background. Off, they arrive " +
                    "when you open the app.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun NodeCard(
    session: NodeSession,
    open: () -> Unit,
) {
    val state by session.state.collectAsState()
    Card(Modifier.fillMaxWidth().clickable(onClick = open)) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(session.info.name, style = MaterialTheme.typography.titleMedium)
                Text(
                    if (state.connected) "connected" else "offline",
                    color = if (state.connected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
            val waiting =
                listOfNotNull(
                    state.prompts.size
                        .takeIf { it > 0 }
                        ?.let { "$it waiting" },
                    state.pendingProposals.takeIf { it > 0 }?.let { "$it proposals" },
                    state.openAlerts.takeIf { it > 0 }?.let { "$it alerts" },
                )
            Text(
                when {
                    !state.connected && state.error != null -> state.error.orEmpty()
                    waiting.isEmpty() -> "Nothing waits"
                    else -> waiting.joinToString(" · ")
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
