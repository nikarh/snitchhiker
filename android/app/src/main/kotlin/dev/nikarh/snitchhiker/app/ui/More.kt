package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.app.SnitchhikerApp
import kotlinx.coroutines.launch
import snitchhiker.v1.ChainPolicy
import snitchhiker.v1.DecideProposal
import snitchhiker.v1.Dimension
import snitchhiker.v1.Explore
import snitchhiker.v1.GetPolicy
import snitchhiker.v1.GetSystemFirewall
import snitchhiker.v1.KillConnection
import snitchhiker.v1.ListChanges
import snitchhiker.v1.ListConnections
import snitchhiker.v1.ListDevices
import snitchhiker.v1.ListProposals
import snitchhiker.v1.Mode
import snitchhiker.v1.Policy
import snitchhiker.v1.ProposalDuration
import snitchhiker.v1.ProposalState
import snitchhiker.v1.RemoveDevice
import snitchhiker.v1.Request
import snitchhiker.v1.SetPolicy
import snitchhiker.v1.SetSystemFirewall
import snitchhiker.v1.Undo

private val pages = listOf("Proposals", "Explorer", "Connections", "History", "Firewall", "Devices", "Status", "Settings")

@Composable
fun MorePage(
    session: NodeSession,
    app: SnitchhikerApp,
    page: String?,
    open: (String?) -> Unit,
    gone: () -> Unit,
    modifier: Modifier,
) {
    when (page) {
        "Proposals" -> {
            ProposalsPage(session, modifier)
        }

        "Explorer" -> {
            ExplorerPage(session, modifier)
        }

        "Connections" -> {
            ConnectionsPage(session, modifier)
        }

        "History" -> {
            HistoryPage(session, modifier)
        }

        "Firewall" -> {
            FirewallPage(session, modifier)
        }

        "Devices" -> {
            DevicesPage(session, modifier)
        }

        "Status" -> {
            StatusPage(session, modifier)
        }

        "Settings" -> {
            SettingsPage(session, modifier)
        }

        else -> {
            Page(modifier) {
                items(
                    pages,
                ) { name -> Item(Modifier.clickable { open(name) }) { Text(name, style = MaterialTheme.typography.titleMedium) } }
                item {
                    Item {
                        Text("Forget this node", style = MaterialTheme.typography.titleMedium)
                        Muted("It stays paired on the node until unpaired there (Devices, on the node).")
                        OutlinedButton(onClick = {
                            app.forget(session.info.id)
                            gone()
                        }) { Text("Forget") }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProposalsPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val state by session.state.collectAsState()
    val scope = rememberCoroutineScope()
    val list =
        rememberRequest(session, state.proposals, { Request(list_proposals = ListProposals(limit = 50)) }) { it.proposals?.proposals }
    Page(modifier) {
        item { Problem(list.error) }
        items(list.value.orEmpty(), key = { it.id }) { proposal ->
            var reason by remember { mutableStateOf("") }
            var error by remember { mutableStateOf<String?>(null) }
            val provenance = proposal.provenance
            Item {
                Text(provenance?.agent_exe ?: "an agent", style = MaterialTheme.typography.titleMedium)
                Muted("in ${provenance?.cwd ?: "?"} · ${provenance?.user ?: ""}")
                Muted("The agent says (not verified):")
                Text(proposal.justification)
                for (rule in proposal.rules) {
                    Text(summary(rule.conditions), style = MaterialTheme.typography.bodyMedium)
                    for (risk in rule.risks) Text(risk.description, color = MaterialTheme.colorScheme.tertiary)
                }
                if (proposal.state == ProposalState.PROPOSAL_STATE_PENDING) {
                    OutlinedTextField(
                        value = reason,
                        onValueChange = { reason = it },
                        label = { Text("Reason, told to the agent") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Problem(error)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            scope.launch {
                                error =
                                    run(
                                        session,
                                        Request(
                                            decide_proposal =
                                                DecideProposal(
                                                    id = proposal.id,
                                                    approve = true,
                                                    reason = reason,
                                                    duration = ProposalDuration.PROPOSAL_DURATION_SESSION,
                                                ),
                                        ),
                                    )
                                list.reload()
                            }
                        }) { Text(if (proposal.broad) "Approve (needs step-up)" else "Approve") }
                        OutlinedButton(onClick = {
                            scope.launch {
                                error =
                                    run(
                                        session,
                                        Request(decide_proposal = DecideProposal(id = proposal.id, approve = false, reason = reason)),
                                    )
                                list.reload()
                            }
                        }) { Text("Deny") }
                    }
                } else {
                    Muted(
                        proposal.state.name
                            .removePrefix("PROPOSAL_STATE_")
                            .lowercase() +
                            if (proposal.reason.isEmpty()) "" else ": ${proposal.reason}",
                    )
                }
            }
        }
    }
}

@Composable
private fun ExplorerPage(
    session: NodeSession,
    modifier: Modifier,
) {
    var by by remember { mutableStateOf(Dimension.DIMENSION_PROGRAM) }
    var hours by remember { mutableLongStateOf(24L) }
    val rows =
        rememberRequest(session, by to hours, {
            val now = System.currentTimeMillis()
            Request(explore = Explore(from_ms = now - hours * 3_600_000, to_ms = now, group_by = by, limit = 100))
        }) { it.explored?.rows }
    Page(modifier) {
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for ((dimension, label) in listOf(
                    Dimension.DIMENSION_PROGRAM to "Programs",
                    Dimension.DIMENSION_HOST to "Hosts",
                    Dimension.DIMENSION_PORT to "Ports",
                    Dimension.DIMENSION_USER to "Users",
                )) {
                    FilterChip(selected = by == dimension, onClick = { by = dimension }, label = { Text(label) })
                }
            }
        }
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for ((span, label) in listOf(1L to "Hour", 24L to "Day", 168L to "Week", 720L to "Month")) {
                    FilterChip(selected = hours == span, onClick = { hours = span }, label = { Text(label) })
                }
            }
        }
        item { Problem(rows.error) }
        items(rows.value.orEmpty()) { row ->
            Item {
                Text(row.key, style = MaterialTheme.typography.titleSmall)
                Muted("${row.allowed} allowed · ${row.blocked} blocked · ${row.bytes_out} B out · ${row.bytes_in} B in")
            }
        }
    }
}

@Composable
private fun ConnectionsPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val list = rememberRequest(session, Unit, { Request(list_connections = ListConnections()) }) { it.connections?.connections }
    Page(modifier) {
        item { OutlinedButton(onClick = list.reload) { Text("Refresh") } }
        item { Problem(list.error) }
        items(list.value.orEmpty()) { c ->
            Item {
                Text(c.exe.ifEmpty { "?" }, style = MaterialTheme.typography.titleSmall)
                Text(
                    "${address(
                        c.local,
                    )}:${c.local_port} → ${c.host.ifEmpty { address(c.remote) }}:${c.remote_port} (${protocol(c.protocol)}, ${c.state})",
                )
                Muted("uid ${c.uid} · ${c.bytes_out} B out · ${c.bytes_in} B in")
                TextButton(onClick = {
                    scope.launch {
                        run(
                            session,
                            Request(
                                kill_connection =
                                    KillConnection(
                                        protocol = c.protocol,
                                        local = c.local,
                                        local_port = c.local_port,
                                        remote = c.remote,
                                        remote_port = c.remote_port,
                                    ),
                            ),
                        )
                        list.reload()
                    }
                }) { Text("Close") }
            }
        }
    }
}

@Composable
private fun HistoryPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val state by session.state.collectAsState()
    val scope = rememberCoroutineScope()
    val list = rememberRequest(session, state.rulesVersion, { Request(list_changes = ListChanges(limit = 200)) }) { it.changes?.changes }
    var error by remember { mutableStateOf<String?>(null) }
    Page(modifier) {
        item { Problem(list.error ?: error) }
        items(list.value.orEmpty(), key = { it.id }) { change ->
            Item {
                Text(change.what)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Muted("${time(change.time_ms)} · ${change.app}")
                    TextButton(
                        onClick = { scope.launch { error = run(session, Request(undo = Undo(change = change.id))) } },
                    ) { Text("Undo") }
                }
            }
        }
    }
}

@Composable
private fun FirewallPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val firewall = rememberRequest(session, Unit, { Request(get_system_firewall = GetSystemFirewall()) }) { it.system_firewall }
    var error by remember { mutableStateOf<String?>(null) }
    Page(modifier) {
        item { Problem(firewall.error ?: error) }
        firewall.value?.let { current ->
            item {
                Item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("System firewall", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        Switch(checked = current.enabled, onCheckedChange = { on ->
                            scope.launch {
                                error =
                                    run(session, Request(set_system_firewall = SetSystemFirewall(firewall = current.copy(enabled = on))))
                                firewall.reload()
                            }
                        })
                    }
                    Muted(
                        "Inbound: ${if (current.input == ChainPolicy.CHAIN_POLICY_DROP) "drop" else "accept"} · forwarded: " +
                            if (current.forward == ChainPolicy.CHAIN_POLICY_DROP) "drop" else "accept",
                    )
                }
            }
            items(current.rules) { rule ->
                Item {
                    Text(rule.description.ifEmpty { "(no description)" }, style = MaterialTheme.typography.titleSmall)
                    Muted(
                        "${rule.chain.name.removePrefix("SYSTEM_CHAIN_").lowercase()} ${rule.protocol} ${rule.destination_ports} " +
                            "→ ${rule.target.name.removePrefix("SYSTEM_TARGET_").lowercase()}" + if (rule.enabled) "" else " (off)",
                    )
                }
            }
        }
    }
}

@Composable
private fun DevicesPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val list = rememberRequest(session, Unit, { Request(list_devices = ListDevices()) }) { it.devices }
    Page(modifier) {
        item { Problem(list.error) }
        list.value?.let { item { Muted("This node: ${it.fingerprint}") } }
        items(list.value?.devices.orEmpty(), key = { it.id }) { device ->
            Item {
                Text(device.name, style = MaterialTheme.typography.titleMedium)
                Muted("${device.fingerprint} · ${if (device.connected) "connected" else "last seen ${time(device.last_seen_ms)}"}")
                TextButton(onClick = {
                    scope.launch {
                        run(session, Request(remove_device = RemoveDevice(id = device.id)))
                        list.reload()
                    }
                }) { Text("Unpair") }
            }
        }
    }
}

@Composable
private fun StatusPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val state by session.state.collectAsState()
    val status = state.status
    Page(modifier) {
        item {
            Item {
                Text(session.info.name, style = MaterialTheme.typography.titleMedium)
                if (status != null) {
                    Text("Daemon ${status.daemon_version}, ${if (status.mode == Mode.MODE_MONITOR) "monitoring" else "enforcing"}")
                    Muted("${status.rules} rules · ${status.decided} connections decided · ${status.clients} clients")
                    Muted("${status.pending_prompts} waiting · ${status.open_alerts} alerts not acknowledged")
                }
                Muted("You are ${session.info.role} here.")
            }
        }
    }
}

@Composable
private fun SettingsPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val policy = rememberRequest(session, Unit, { Request(get_policy = GetPolicy()) }) { it.policy }
    var error by remember { mutableStateOf<String?>(null) }

    fun set(change: SetPolicy) {
        scope.launch {
            error = run(session, Request(set_policy = change))
            policy.reload()
        }
    }
    Page(modifier) {
        item { Problem(policy.error ?: error) }
        policy.value?.let { current ->
            item {
                Item {
                    Text("Mode", style = MaterialTheme.typography.titleSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected = current.mode == Mode.MODE_ENFORCE, onClick = {
                            set(SetPolicy(mode = Mode.MODE_ENFORCE))
                        }, label = { Text("Enforce") })
                        FilterChip(selected = current.mode == Mode.MODE_MONITOR, onClick = {
                            set(SetPolicy(mode = Mode.MODE_MONITOR))
                        }, label = { Text("Monitor") })
                    }
                }
            }
            item {
                Item {
                    Text("Connections no rule decides", style = MaterialTheme.typography.titleSmall)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        for ((value, label) in listOf(
                            Policy.POLICY_ASK to "Ask",
                            Policy.POLICY_DENY to "Deny",
                            Policy.POLICY_REJECT to "Reject",
                            Policy.POLICY_ALLOW to "Allow",
                        )) {
                            FilterChip(
                                selected = current.no_match == value,
                                onClick = { set(SetPolicy(no_match = value)) },
                                label = { Text(label) },
                            )
                        }
                    }
                    Muted("Letting through what was blocked (monitor, allow) needs step-up: from a phone, an approval on the node.")
                }
            }
        }
    }
}
