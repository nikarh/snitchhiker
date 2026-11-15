package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.nikarh.snitchhiker.app.NodeSession
import kotlinx.coroutines.launch
import snitchhiker.v1.Action
import snitchhiker.v1.AddRule
import snitchhiker.v1.Conditions
import snitchhiker.v1.Context
import snitchhiker.v1.Request
import snitchhiker.v1.Rule
import snitchhiker.v1.Tier
import snitchhiker.v1.UpdateRule

private fun list(text: String): List<String> = text.split(',', ' ').map(String::trim).filter(String::isNotEmpty)

/**
 * A rule's editor: new (`rule` null) or an existing one. Every condition is a comma-separated list, as rule files
 * write them; the node checks them and says what is wrong.
 */
@Composable
fun RuleEditor(
    session: NodeSession,
    rule: Rule?,
    done: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val c = rule?.conditions ?: Conditions()
    var name by remember { mutableStateOf(rule?.name.orEmpty()) }
    var action by remember { mutableStateOf(rule?.action ?: Action.ACTION_ALLOW) }
    var tier by remember { mutableStateOf(rule?.tier ?: Tier.TIER_NORMAL) }
    var exe by remember { mutableStateOf(c.exe.joinToString(", ")) }
    var host by remember { mutableStateOf(c.host.joinToString(", ")) }
    var net by remember { mutableStateOf(c.net.joinToString(", ")) }
    var port by remember { mutableStateOf(c.port.joinToString(", ")) }
    var protocol by remember { mutableStateOf(c.protocol.joinToString(", ")) }
    var uid by remember { mutableStateOf(c.uid.joinToString(", ")) }
    var cmdline by remember { mutableStateOf(c.cmdline.joinToString(", ")) }
    var parent by remember { mutableStateOf(c.parent.joinToString(", ")) }
    var lists by remember { mutableStateOf(c.list.joinToString(", ")) }
    var anyContext by remember { mutableStateOf(c.context == Context.CONTEXT_ANY) }
    var error by remember { mutableStateOf<String?>(null) }

    fun save() {
        val conditions =
            c.copy(
                exe = list(exe),
                host = list(host),
                net = list(net),
                port = list(port),
                protocol = list(protocol),
                uid = list(uid).mapNotNull(String::toIntOrNull),
                cmdline = list(cmdline),
                parent = list(parent),
                list = list(lists),
                context = if (anyContext) Context.CONTEXT_ANY else Context.CONTEXT_UNSPECIFIED,
            )
        val edited =
            (rule ?: Rule(enabled = true)).copy(name = name.trim(), action = action, tier = tier, conditions = conditions)
        scope.launch {
            error =
                run(
                    session,
                    if (rule == null) Request(add_rule = AddRule(rule = edited)) else Request(update_rule = UpdateRule(rule = edited)),
                )
            if (error == null) done()
        }
    }
    Dialog(onDismissRequest = done, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(
                Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(if (rule == null) "New rule" else "Edit rule", style = MaterialTheme.typography.titleLarge)

                @Composable
                fun field(
                    label: String,
                    value: String,
                    hint: String,
                    set: (String) -> Unit,
                ) = OutlinedTextField(
                    value = value,
                    onValueChange = set,
                    label = { Text(label) },
                    placeholder = { Text(hint) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                field("Name", name, "What it allows or denies") { name = it }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (a in listOf(Action.ACTION_ALLOW, Action.ACTION_DENY, Action.ACTION_REJECT)) {
                        FilterChip(selected = action == a, onClick = { action = a }, label = { Text(actionName(a)) })
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for ((t, label) in listOf(
                        Tier.TIER_OVERRIDE to "Override",
                        Tier.TIER_NORMAL to "Normal",
                        Tier.TIER_FALLBACK to "Fallback",
                    )) {
                        FilterChip(selected = tier == t, onClick = { tier = t }, label = { Text(label) })
                    }
                }
                field("Program", exe, "/usr/bin/curl, glob:{home}/.cargo/bin/*") { exe = it }
                field("Host", host, "example.com, *.example.org, re:…") { host = it }
                field("Network", net, "192.0.2.0/24, lan, loopback") { net = it }
                field("Port", port, "443, 8000-8999") { port = it }
                field("Protocol", protocol, "tcp, udp") { protocol = it }
                field("User id", uid, "1000") { uid = it }
                field("Command line", cmdline, "re:.*--flag.*") { cmdline = it }
                field("Parent program", parent, "/usr/bin/sshd") { parent = it }
                field("Blocklist", lists, "ads (a blocklist's name)") { lists = it }
                FilterChip(selected = anyContext, onClick = { anyContext = !anyContext }, label = {
                    Text("Also in containers, VMs and other namespaces")
                })
                Problem(error)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = ::save) { Text("Save") }
                    OutlinedButton(onClick = done) { Text("Cancel") }
                }
            }
        }
    }
}
