package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import kotlinx.coroutines.launch
import snitchhiker.v1.Action
import snitchhiker.v1.AlertRule
import snitchhiker.v1.ChainPolicy
import snitchhiker.v1.DeleteAlertRule
import snitchhiker.v1.GetPolicy
import snitchhiker.v1.GetSystemFirewall
import snitchhiker.v1.LintRules
import snitchhiker.v1.ListAlertRules
import snitchhiker.v1.Mode
import snitchhiker.v1.NodePolicy
import snitchhiker.v1.Policy
import snitchhiker.v1.PutAlertRule
import snitchhiker.v1.Request
import snitchhiker.v1.SetPolicy
import snitchhiker.v1.SetSystemFirewall

/** Choices in a row that scrolls sideways when it is wider than the screen. */
@Composable
private fun <T> Choices(
    options: List<Pair<T, String>>,
    selected: T,
    choose: (T) -> Unit,
) {
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for ((value, label) in options) FilterChip(selected = selected == value, onClick = { choose(value) }, label = { Text(label) })
    }
}

private val actions = listOf(Action.ACTION_DENY to "Deny", Action.ACTION_REJECT to "Reject", Action.ACTION_ALLOW to "Allow")

/** The node's policy, changed while it runs (recorded, undone from History). */
@Composable
fun SettingsPage(
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
        policy.value?.let { current -> policyItems(current, ::set) }
        item { Muted("Letting through what was blocked (monitor, allow) needs step-up: from a phone, an approval on the node.") }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.policyItems(
    current: NodePolicy,
    set: (SetPolicy) -> Unit,
) {
    item {
        Item {
            Text("Mode", style = MaterialTheme.typography.titleSmall)
            Choices(listOf(Mode.MODE_ENFORCE to "Enforce", Mode.MODE_MONITOR to "Monitor"), current.mode) { set(SetPolicy(mode = it)) }
        }
    }
    item {
        Item {
            Text("Connections no rule decides", style = MaterialTheme.typography.titleSmall)
            Choices(
                listOf(
                    Policy.POLICY_ASK to "Ask",
                    Policy.POLICY_DENY to "Deny",
                    Policy.POLICY_REJECT to "Reject",
                    Policy.POLICY_ALLOW to "Allow",
                ),
                current.no_match,
            ) { set(SetPolicy(no_match = it)) }
        }
    }
    item {
        Item {
            Text("With no client to ask", style = MaterialTheme.typography.titleSmall)
            Choices(actions, current.no_client) { set(SetPolicy(no_client = it)) }
        }
    }
    item {
        Item {
            Text("When nobody answers a prompt", style = MaterialTheme.typography.titleSmall)
            Choices(actions, current.on_timeout) { set(SetPolicy(on_timeout = it)) }
            Text("after", style = MaterialTheme.typography.labelMedium)
            Choices(
                listOf(15, 30, 60, 120, 300).map { it to "$it s" },
                current.prompt_timeout_secs,
            ) { set(SetPolicy(prompt_timeout_secs = it)) }
        }
    }
    item {
        Item {
            Text("History kept", style = MaterialTheme.typography.titleSmall)
            Choices(listOf(7, 30, 90, 365).map { it to "$it days" }, current.retention_days) { set(SetPolicy(retention_days = it)) }
        }
    }
    if (current.changed.isNotEmpty()) {
        item {
            Item {
                Muted("Changed here: ${current.changed.joinToString(", ")}")
                TextButton(onClick = { set(SetPolicy(reset = current.changed)) }) { Text("Use daemon.toml's") }
            }
        }
    }
}

/** The system firewall: on or off, its policies, and its rules switched on and off. */
@Composable
fun FirewallPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val firewall = rememberRequest(session, Unit, { Request(get_system_firewall = GetSystemFirewall()) }) { it.system_firewall }
    var error by remember { mutableStateOf<String?>(null) }

    fun set(changed: snitchhiker.v1.SystemFirewall) {
        scope.launch {
            error = run(session, Request(set_system_firewall = SetSystemFirewall(firewall = changed)))
            firewall.reload()
        }
    }
    val policies = listOf(ChainPolicy.CHAIN_POLICY_ACCEPT to "Accept", ChainPolicy.CHAIN_POLICY_DROP to "Drop")
    Page(modifier) {
        item { Problem(firewall.error ?: error) }
        firewall.value?.let { current ->
            item {
                Item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("System firewall", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        Switch(checked = current.enabled, onCheckedChange = { set(current.copy(enabled = it)) })
                    }
                    Text("Inbound", style = MaterialTheme.typography.labelMedium)
                    Choices(policies, current.input) { set(current.copy(input = it)) }
                    Text("Forwarded", style = MaterialTheme.typography.labelMedium)
                    Choices(policies, current.forward) { set(current.copy(forward = it)) }
                }
            }
            items(current.rules.size) { index ->
                val rule = current.rules[index]
                Item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            rule.description.ifEmpty { "(no description)" },
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f),
                        )
                        Switch(checked = rule.enabled, onCheckedChange = { on ->
                            set(current.copy(rules = current.rules.mapIndexed { i, r -> if (i == index) r.copy(enabled = on) else r }))
                        })
                    }
                    Muted(
                        "${rule.chain.name.removePrefix("SYSTEM_CHAIN_").lowercase()} ${rule.protocol} ${rule.destination_ports} " +
                            "→ ${rule.target.name.removePrefix("SYSTEM_TARGET_").lowercase()}",
                    )
                    TextButton(onClick = {
                        set(
                            current.copy(
                                rules =
                                    current.rules.filterIndexed {
                                        i,
                                        _,
                                        ->
                                        i != index
                                    },
                            ),
                        )
                    }) { Text("Delete") }
                }
            }
        }
    }
}

/** Alert rules: connections the query matches, so many within a window, raise an alert. */
@Composable
fun AlertRulesPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val rules = rememberRequest(session, Unit, { Request(list_alert_rules = ListAlertRules()) }) { it.alert_rules?.rules }
    var name by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun put(rule: AlertRule) {
        scope.launch {
            error = run(session, Request(put_alert_rule = PutAlertRule(rule = rule)))
            rules.reload()
        }
    }
    Page(modifier) {
        item {
            Item {
                Text("New alert rule", style = MaterialTheme.typography.titleSmall)
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Connections") },
                    placeholder = { Text("ip:imds  action:deny") },
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(onClick = {
                    put(AlertRule(name = name.trim(), enabled = true, query = query.trim(), threshold = 1))
                    name = ""
                    query = ""
                }) { Text("Add") }
            }
        }
        item { Problem(rules.error ?: error) }
        items(rules.value.orEmpty(), key = { it.id }) { rule ->
            Item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(rule.name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                    Switch(checked = rule.enabled, onCheckedChange = { put(rule.copy(enabled = it)) })
                }
                Muted(
                    if (rule.first_program) {
                        "Every program's first connection"
                    } else {
                        "${rule.threshold} × ${rule.query.ifEmpty {
                            "any connection"
                        }}"
                    },
                )
                TextButton(onClick = {
                    scope.launch {
                        error = run(session, Request(delete_alert_rule = DeleteAlertRule(id = rule.id)))
                        rules.reload()
                    }
                }) { Text("Delete") }
            }
        }
    }
}

/** The rules check: duplicates, redundant and shadowed rules, expired ones, and rules on missing or writable binaries. */
@Composable
fun LintPage(
    session: NodeSession,
    modifier: Modifier,
) {
    val findings = rememberRequest(session, Unit, { Request(lint_rules = LintRules(unused_days = 30)) }) { it.lint_report?.findings }
    Page(modifier) {
        item { Problem(findings.error) }
        if (findings.value?.isEmpty() == true) item { Muted("Nothing to report.") }
        items(findings.value.orEmpty()) { finding ->
            Item {
                Text(
                    finding.kind.name
                        .removePrefix("LINT_KIND_")
                        .lowercase()
                        .replace('_', ' '),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(finding.description)
            }
        }
    }
}
