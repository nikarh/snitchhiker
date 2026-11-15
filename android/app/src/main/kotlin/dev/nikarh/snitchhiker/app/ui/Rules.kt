package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.items
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
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.core.NodeState
import kotlinx.coroutines.launch
import snitchhiker.v1.Conditions
import snitchhiker.v1.DeleteRule
import snitchhiker.v1.Folder
import snitchhiker.v1.ListRules
import snitchhiker.v1.Request
import snitchhiker.v1.Rule
import snitchhiker.v1.SetRuleEnabled

/** What a rule's conditions say, briefly. */
fun summary(conditions: Conditions?): String {
    val c = conditions ?: return ""
    val parts =
        listOf(
            "exe" to c.exe,
            "app" to c.app,
            "host" to c.host,
            "net" to c.net,
            "port" to c.port,
            "protocol" to c.protocol,
            "uid" to c.uid.map(Int::toString),
            "parent" to c.parent,
            "session" to c.session,
        ).filter { it.second.isNotEmpty() }
            .map { (key, values) -> "$key=${values.joinToString(",")}" }
    return parts.joinToString(" ")
}

private fun path(
    folder: Long?,
    folders: Map<Long, Folder>,
): String {
    val names = mutableListOf<String>()
    var next = folder
    while (next != null && names.size < folders.size + 1) {
        val current = folders[next] ?: break
        names.add(0, current.name)
        next = current.parent
    }
    return names.joinToString("/")
}

/** The rules, searchable: each with its folder, its conditions, and switches to enable or delete it. */
@Composable
fun RulesPage(
    session: NodeSession,
    state: NodeState,
    modifier: Modifier,
) {
    val list = rememberRequest(session, state.rulesVersion, { Request(list_rules = ListRules()) }) { it.rules }
    var search by remember { mutableStateOf("") }
    val folders =
        list.value
            ?.folders
            .orEmpty()
            .associateBy { it.id }
    val rules =
        list.value?.rules.orEmpty().filter {
            search.isBlank() ||
                "${it.name} ${path(it.folder, folders)} ${summary(it.conditions)}".contains(search, ignoreCase = true)
        }
    Page(modifier) {
        item {
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                label = { Text("Search") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item { Problem(list.error) }
        items(rules, key = { it.id }) { rule -> RuleCard(session, rule, path(rule.folder, folders), list.reload) }
    }
}

@Composable
private fun RuleCard(
    session: NodeSession,
    rule: Rule,
    folder: String,
    changed: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    Item {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                listOf(folder, rule.name).filter(String::isNotEmpty).joinToString("/"),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
            )
            Text(actionName(rule.action), color = actionColor(rule.action), style = MaterialTheme.typography.labelLarge)
            if (!rule.locked) {
                Switch(checked = rule.enabled, onCheckedChange = { enabled ->
                    scope.launch {
                        error = run(session, Request(set_rule_enabled = SetRuleEnabled(id = rule.id, enabled = enabled)))
                        changed()
                    }
                })
            }
        }
        Muted(summary(rule.conditions))
        if (rule.locked) Muted("A default or managed rule: changed in its file.")
        Problem(error)
        if (!rule.locked) {
            TextButton(onClick = {
                scope.launch {
                    error = run(session, Request(delete_rule = DeleteRule(id = rule.id)))
                    changed()
                }
            }) { Text("Delete") }
        }
    }
}
