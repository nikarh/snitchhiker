package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.automirrored.filled.Rule
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.app.SnitchhikerApp

private enum class Tab(
    val label: String,
    val icon: ImageVector,
) {
    Prompts("Prompts", Icons.Default.Notifications),
    Events("Events", Icons.AutoMirrored.Filled.List),
    Rules("Rules", Icons.AutoMirrored.Filled.Rule),
    Alerts("Alerts", Icons.Default.Warning),
    More("More", Icons.Default.Menu),
}

/** A node's pages, with a bottom bar. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeScreen(
    session: NodeSession,
    app: SnitchhikerApp,
    back: () -> Unit,
) {
    val state by session.state.collectAsState()
    var tab by rememberSaveable { mutableStateOf(Tab.Prompts) }
    var more by rememberSaveable { mutableStateOf<String?>(null) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(more ?: session.info.name) },
                navigationIcon = {
                    IconButton(onClick = { if (more != null) more = null else back() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                for (entry in Tab.entries) {
                    val count =
                        when (entry) {
                            Tab.Prompts -> state.prompts.size + state.approvals.size
                            Tab.Alerts -> state.openAlerts
                            Tab.More -> state.pendingProposals
                            else -> 0
                        }
                    NavigationBarItem(
                        selected = tab == entry,
                        onClick = {
                            tab = entry
                            more = null
                        },
                        icon = {
                            BadgedBox(badge = { if (count > 0) Badge { Text(count.toString()) } }) {
                                Icon(entry.icon, null)
                            }
                        },
                        label = { Text(entry.label) },
                    )
                }
            }
        },
    ) { padding ->
        val modifier = Modifier.padding(padding)
        if (!state.connected) {
            Page(modifier) { item { Problem("Not connected to ${session.info.name}: ${state.error ?: "connecting…"}") } }
            return@Scaffold
        }
        when (tab) {
            Tab.Prompts -> PromptsPage(session, state, modifier)
            Tab.Events -> EventsPage(session, modifier)
            Tab.Rules -> RulesPage(session, state, modifier)
            Tab.Alerts -> AlertsPage(session, state, modifier)
            Tab.More -> MorePage(session, app, more, { more = it }, back, modifier)
        }
    }
}
