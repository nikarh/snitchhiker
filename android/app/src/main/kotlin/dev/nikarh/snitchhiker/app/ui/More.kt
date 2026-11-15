package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.app.SnitchhikerApp
import kotlinx.coroutines.launch
import snitchhiker.v1.ChainPolicy
import snitchhiker.v1.DecideProposal
import snitchhiker.v1.Dimension
import snitchhiker.v1.EditedRule
import snitchhiker.v1.Explore
import snitchhiker.v1.ExploreFilter
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
import snitchhiker.v1.Role
import snitchhiker.v1.SetDeviceMuted
import snitchhiker.v1.SetPolicy
import snitchhiker.v1.SetSystemFirewall
import snitchhiker.v1.StartPairing
import snitchhiker.v1.Undo

private val pages =
    listOf(
        "Proposals",
        "Explorer",
        "Containers & VMs",
        "Live",
        "Connections",
        "History",
        "Rules check",
        "Alert rules",
        "Blocklists",
        "Firewall",
        "Devices",
        "Status",
        "Settings",
    )

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

        "Containers & VMs" -> {
            ExplorerPage(session, modifier, Dimension.DIMENSION_CONTAINER)
        }

        "Connections" -> {
            ConnectionsPage(session, modifier)
        }

        "Live" -> {
            LivePage(session, modifier)
        }

        "Rules check" -> {
            LintPage(session, modifier)
        }

        "Alert rules" -> {
            AlertRulesPage(session, modifier)
        }

        "Blocklists" -> {
            BlocklistsPage(session, modifier)
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
    val list =
        rememberRequest(session, state.proposals, { Request(list_proposals = ListProposals(limit = 50)) }) { it.proposals?.proposals }
    Page(modifier) {
        item { Problem(list.error) }
        items(list.value.orEmpty(), key = { it.id }) { proposal -> ProposalCard(session, proposal, list.reload) }
    }
}

private val proposalDurations =
    listOf(
        ProposalDuration.PROPOSAL_DURATION_SESSION to "While the agent runs",
        ProposalDuration.PROPOSAL_DURATION_HOUR to "1 hour",
        ProposalDuration.PROPOSAL_DURATION_TWELVE_HOURS to "12 hours",
        ProposalDuration.PROPOSAL_DURATION_FOREVER to "Forever",
    )

/** An agent's proposal: who, the agent's words, each rule (its hosts and ports narrowed before approving), and how long. */
@Composable
private fun ProposalCard(
    session: NodeSession,
    proposal: snitchhiker.v1.Proposal,
    changed: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var reason by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var duration by remember { mutableStateOf(ProposalDuration.PROPOSAL_DURATION_SESSION) }
    val hosts =
        remember {
            proposal.rules.map { r ->
                mutableStateOf((r.conditions?.host.orEmpty() + r.conditions?.net.orEmpty()).joinToString(", "))
            }
        }
    val ports =
        remember {
            proposal.rules.map { r ->
                mutableStateOf(
                    r.conditions
                        ?.port
                        .orEmpty()
                        .joinToString(", "),
                )
            }
        }
    val provenance = proposal.provenance

    fun decide(approve: Boolean) {
        val edited =
            proposal.rules.mapIndexed { index, rule ->
                val items =
                    hosts[index]
                        .value
                        .split(',', ' ')
                        .map(String::trim)
                        .filter(String::isNotEmpty)
                val (nets, names) = items.partition { it.firstOrNull()?.isDigit() == true || it.contains(':') }
                EditedRule(
                    index = index,
                    conditions =
                        (rule.conditions ?: snitchhiker.v1.Conditions()).copy(
                            host = names,
                            net = nets,
                            port =
                                ports[index]
                                    .value
                                    .split(',', ' ')
                                    .map(String::trim)
                                    .filter(String::isNotEmpty),
                        ),
                )
            }
        scope.launch {
            error =
                run(
                    session,
                    Request(
                        decide_proposal =
                            DecideProposal(
                                id = proposal.id,
                                approve = approve,
                                reason = reason,
                                duration = duration,
                                rules = if (approve) edited else emptyList(),
                            ),
                    ),
                )
            changed()
        }
    }
    Item {
        Text(provenance?.agent_exe ?: "an agent", style = MaterialTheme.typography.titleMedium)
        Muted("in ${provenance?.cwd ?: "?"} · ${provenance?.user ?: ""}")
        Muted("The agent says (not verified):")
        Text(proposal.justification)
        val pending = proposal.state == ProposalState.PROPOSAL_STATE_PENDING
        proposal.rules.forEachIndexed { index, rule ->
            Text(rule.conditions?.exe?.firstOrNull() ?: "Any program", style = MaterialTheme.typography.titleSmall)
            if (pending) {
                OutlinedTextField(value = hosts[index].value, onValueChange = {
                    hosts[index].value = it
                }, label = { Text("To") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = ports[index].value, onValueChange = {
                    ports[index].value = it
                }, label = { Text("Ports") }, modifier = Modifier.fillMaxWidth())
            } else {
                Text(summary(rule.conditions), style = MaterialTheme.typography.bodyMedium)
            }
            for (risk in rule.risks) Text(risk.description, color = MaterialTheme.colorScheme.tertiary)
            for (e in rule.evidence) Muted("refused: ${e.exe} → ${e.host.ifEmpty { address(e.address) }}:${e.port} ×${e.count}")
        }
        if (pending) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for ((value, label) in proposalDurations) {
                    FilterChip(
                        selected = duration == value,
                        onClick = { duration = value },
                        label = { Text(label) },
                    )
                }
            }
            OutlinedTextField(value = reason, onValueChange = {
                reason = it
            }, label = { Text("Reason, told to the agent") }, modifier = Modifier.fillMaxWidth())
            Problem(error)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { decide(true) }) { Text(if (proposal.broad) "Approve (needs step-up)" else "Approve") }
                OutlinedButton(onClick = { decide(false) }) { Text("Deny") }
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

@Composable
private fun ExplorerPage(
    session: NodeSession,
    modifier: Modifier,
    first: Dimension = Dimension.DIMENSION_PROGRAM,
) {
    var by by remember { mutableStateOf(first) }
    var hours by remember { mutableLongStateOf(24L) }
    // Drilled into: a row of another grouping, its connections grouped by `by`.
    var filter by remember { mutableStateOf<ExploreFilter?>(null) }
    val rows =
        rememberRequest(session, Triple(by, hours, filter), {
            val now = System.currentTimeMillis()
            Request(explore = Explore(from_ms = now - hours * 3_600_000, to_ms = now, group_by = by, filter = filter, limit = 100))
        }) { it.explored?.rows }
    Page(modifier) {
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for ((dimension, label) in listOf(
                    Dimension.DIMENSION_PROGRAM to "Programs",
                    Dimension.DIMENSION_HOST to "Hosts",
                    Dimension.DIMENSION_PORT to "Ports",
                    Dimension.DIMENSION_USER to "Users",
                    Dimension.DIMENSION_CONTAINER to "Containers",
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
        filter?.let { current ->
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Muted("Within ${shownKey(current.dimension, current.value_)}")
                    TextButton(onClick = { filter = null }) { Text("Back") }
                }
            }
        }
        item {
            val context = LocalContext.current
            OutlinedButton(onClick = {
                val table =
                    listOf(listOf("key", "allowed", "blocked", "bytes_out", "bytes_in")) +
                        rows.value.orEmpty().map {
                            listOf(it.key, it.allowed.toString(), it.blocked.toString(), it.bytes_out.toString(), it.bytes_in.toString())
                        }
                share(context, "${session.info.name} explorer.csv", csv(table), "text/csv")
            }) { Text("Share as CSV") }
        }
        item { Problem(rows.error) }
        items(rows.value.orEmpty()) { row ->
            // A program's row drills into where it connected; any other's, into which programs reached it.
            Item(
                Modifier.clickable {
                    filter = ExploreFilter(dimension = by, value_ = row.key)
                    by = if (by == Dimension.DIMENSION_PROGRAM) Dimension.DIMENSION_HOST else Dimension.DIMENSION_PROGRAM
                },
            ) {
                Text(shownKey(by, row.key), style = MaterialTheme.typography.titleSmall)
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
        item {
            val context = LocalContext.current
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = list.reload) { Text("Refresh") }
                OutlinedButton(onClick = {
                    val table =
                        listOf(
                            listOf(
                                "protocol",
                                "local",
                                "local_port",
                                "remote",
                                "remote_port",
                                "host",
                                "state",
                                "uid",
                                "exe",
                                "bytes_out",
                                "bytes_in",
                            ),
                        ) +
                            list.value.orEmpty().map { c ->
                                listOf(
                                    protocol(c.protocol),
                                    address(c.local),
                                    c.local_port.toString(),
                                    address(c.remote),
                                    c.remote_port.toString(),
                                    c.host,
                                    c.state,
                                    c.uid.toString(),
                                    c.exe,
                                    c.bytes_out.toString(),
                                    c.bytes_in.toString(),
                                )
                            }
                    share(context, "${session.info.name} connections.csv", csv(table), "text/csv")
                }) { Text("Share as CSV") }
            }
        }
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
private fun DevicesPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val list = rememberRequest(session, Unit, { Request(list_devices = ListDevices()) }) { it.devices }
    var pairing by remember { mutableStateOf(false) }
    if (pairing) {
        PairDeviceDialog(session) {
            pairing = false
            list.reload()
        }
    }
    Page(modifier) {
        item { Button(onClick = { pairing = true }) { Text("Pair a device") } }
        item { Problem(list.error) }
        list.value?.let { item { Muted("This node: ${it.fingerprint}") } }
        items(list.value?.devices.orEmpty(), key = { it.id }) { device ->
            Item {
                Text(device.name, style = MaterialTheme.typography.titleMedium)
                Muted(
                    "${device.fingerprint} · ${if (device.connected) "connected" else "last seen ${time(device.last_seen_ms)}"}" +
                        (if (device.push) " · woken by push" else "") +
                        if (device.muted) " · muted" else "",
                )
                Row {
                    TextButton(onClick = {
                        scope.launch {
                            run(session, Request(set_device_muted = SetDeviceMuted(id = device.id, muted = !device.muted)))
                            list.reload()
                        }
                    }) { Text(if (device.muted) "Unmute" else "Mute") }
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

/**
 * Pairing another device with this node, from the phone: a name and a role, then the node's one-time pairing as a code
 * to type, a QR code to scan and a link to share (one use, ten minutes). Pairing is a dangerous action: the node waits
 * for an approval on it.
 */
@Composable
private fun PairDeviceDialog(
    session: NodeSession,
    done: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var name by remember { mutableStateOf("") }
    var viewer by remember { mutableStateOf(false) }
    var pairing by remember { mutableStateOf<snitchhiker.v1.Pairing?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var waiting by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = done,
        title = { Text("Pair a device") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val current = pairing
                if (current == null) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text("Its name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(checked = viewer, onCheckedChange = { viewer = it })
                        Text("  Viewer only (it can't change anything)")
                    }
                    if (waiting) Muted("Waiting for an approval on the node…")
                } else {
                    Text("Code: ${current.code}", style = MaterialTheme.typography.titleMedium)
                    qrBitmap(current.link)?.let {
                        androidx.compose.foundation.Image(
                            it,
                            contentDescription = "The pairing QR code",
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Muted("Node: ${current.fingerprint} · valid until ${time(current.expires_ms)}")
                    TextButton(onClick = { share(context, "Pair with ${session.info.name}", current.link) }) { Text("Share the link") }
                }
                Problem(error)
            }
        },
        confirmButton = {
            if (pairing == null) {
                TextButton(enabled = !waiting, onClick = {
                    waiting = true
                    scope.launch {
                        runCatching {
                            session
                                .call(
                                    Request(
                                        start_pairing =
                                            StartPairing(
                                                name = name.trim(),
                                                role = if (viewer) Role.ROLE_VIEWER else Role.ROLE_ADMIN,
                                            ),
                                    ),
                                ).pairing
                        }.onSuccess { pairing = it }
                            .onFailure { error = it.message }
                        waiting = false
                    }
                }) { Text("Pair") }
            } else {
                TextButton(onClick = done) { Text("Done") }
            }
        },
        dismissButton = { if (pairing == null) TextButton(onClick = done) { Text("Cancel") } },
    )
}

/**
 * A group's key as shown: a container's identity (tab-separated runtime, id, name, image, Compose service) as people know
 * it, the host's connections for none; other keys as they are.
 */
fun shownKey(
    dimension: Dimension,
    key: String,
): String {
    if (dimension != Dimension.DIMENSION_CONTAINER) return key.ifEmpty { "(no name)" }
    if (key.isEmpty()) return "(the host)"
    val parts = key.split('\t')
    val runtime = parts.getOrElse(0) { "" }
    val name = parts.getOrElse(4) { "" }.ifEmpty { parts.getOrElse(2) { "" } }
    val image = parts.getOrElse(3) { "" }
    return "[$runtime] $name" + if (image.isEmpty()) "" else " ($image)"
}
