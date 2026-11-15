package dev.nikarh.snitchhiker.app.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.NodeSession
import dev.nikarh.snitchhiker.core.NodeState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import snitchhiker.v1.AddFolder
import snitchhiker.v1.Conditions
import snitchhiker.v1.DeleteFolder
import snitchhiker.v1.DeleteRule
import snitchhiker.v1.EditRules
import snitchhiker.v1.ExportRules
import snitchhiker.v1.Folder
import snitchhiker.v1.ImportRules
import snitchhiker.v1.ListRules
import snitchhiker.v1.MoveRules
import snitchhiker.v1.Request
import snitchhiker.v1.Rule
import snitchhiker.v1.SetRuleEnabled
import snitchhiker.v1.UpdateFolder

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

/** What the rules page asks for in a dialog. */
private sealed interface Asking {
    data object NewFolder : Asking

    data object Move : Asking

    data class DeleteFolder(
        val folder: Folder,
        val path: String,
    ) : Asking
}

/**
 * The rules, by folder: searchable; folders collapse, and are enabled or disabled as a whole. A long press selects
 * rules, for enabling, disabling, moving or deleting them together. Rules files come in and go out through the share
 * sheet.
 */
@Composable
fun RulesPage(
    session: NodeSession,
    state: NodeState,
    modifier: Modifier,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val list = rememberRequest(session, state.rulesVersion, { Request(list_rules = ListRules()) }) { it.rules }
    var search by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf<Rule?>(null) }
    var selected by remember { mutableStateOf(emptySet<Long>()) }
    var collapsed by remember { mutableStateOf(emptySet<Long>()) }
    var asking by remember { mutableStateOf<Asking?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    editing?.let { rule ->
        RuleEditor(session, rule.takeIf { it.id != 0L }) {
            editing = null
            list.reload()
        }
    }
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
    // The rules by folder path, top level first.
    val groups = rules.groupBy { it.folder }.toList().sortedBy { (folder, _) -> path(folder, folders) }

    fun act(request: Request) {
        scope.launch {
            error = run(session, request)
            list.reload()
        }
    }
    val import =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            uri ?: return@rememberLauncherForActivityResult
            scope.launch {
                val text =
                    withContext(Dispatchers.IO) {
                        runCatching { context.contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() } }.getOrNull()
                    }
                val name = uri.lastPathSegment?.substringAfterLast('/')?.substringBeforeLast('.') ?: "Imported"
                error =
                    if (text ==
                        null
                    ) {
                        "Couldn't read the file"
                    } else {
                        run(session, Request(import_rules = ImportRules(toml = text, folder = name)))
                    }
                list.reload()
            }
        }
    asking?.let { ask -> AskDialog(ask, folders, done = { asking = null }, act = ::act, selected = selected) { selected = emptySet() } }
    Page(modifier) {
        item {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { editing = Rule() }) { Text("New rule") }
                OutlinedButton(onClick = { asking = Asking.NewFolder }) { Text("New folder") }
                OutlinedButton(onClick = { import.launch(arrayOf("*/*")) }) { Text("Import") }
                OutlinedButton(onClick = { exportRules(scope, session, context) { error = it } }) { Text("Export") }
            }
        }
        item {
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                label = { Text("Search") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (selected.isNotEmpty()) {
            item {
                SelectionBar(selected.size, clear = { selected = emptySet() }) { edit ->
                    if (edit == null) {
                        asking = Asking.Move
                    } else {
                        act(Request(edit_rules = edit.copy(ids = selected.toList())))
                        selected = emptySet()
                    }
                }
            }
        }
        item { Problem(list.error ?: error) }
        for ((folderId, inFolder) in groups) {
            val folder = folderId?.let(folders::get)
            if (folder != null) {
                item(key = "folder-${folder.id}") {
                    FolderHeader(
                        folder,
                        path(folder.id, folders),
                        open = folder.id !in collapsed,
                        toggle = { collapsed = if (folder.id in collapsed) collapsed - folder.id else collapsed + folder.id },
                        enable = { act(Request(update_folder = UpdateFolder(folder = folder.copy(enabled = it)))) },
                        delete = { asking = Asking.DeleteFolder(folder, path(folder.id, folders)) },
                    )
                }
                if (folder.id in collapsed) continue
            }
            items(inFolder, key = { it.id }) { rule ->
                RuleCard(
                    session,
                    rule,
                    selected = rule.id in selected,
                    selecting = selected.isNotEmpty(),
                    select = { selected = if (rule.id in selected) selected - rule.id else selected + rule.id },
                    changed = list.reload,
                ) { editing = rule }
            }
        }
    }
}

private fun exportRules(
    scope: CoroutineScope,
    session: NodeSession,
    context: android.content.Context,
    failed: (String?) -> Unit,
) {
    scope.launch {
        runCatching { session.call(Request(export_rules = ExportRules())).rule_file?.toml }
            .onSuccess { toml -> toml?.let { share(context, "${session.info.name} rules.toml", it, "application/toml") } }
            .onFailure { failed(it.message) }
    }
}

/** The selected rules' actions; `null` asks where to move them. */
@Composable
private fun SelectionBar(
    count: Int,
    clear: () -> Unit,
    edit: (EditRules?) -> Unit,
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
        Column(Modifier.padding(12.dp)) {
            Text("$count selected", style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = { edit(EditRules(enabled = true)) }) { Text("Enable") }
                TextButton(onClick = { edit(EditRules(enabled = false)) }) { Text("Disable") }
                TextButton(onClick = { edit(null) }) { Text("Move") }
                TextButton(onClick = { edit(EditRules(delete = true)) }) { Text("Delete") }
                TextButton(onClick = clear) { Text("Clear") }
            }
        }
    }
}

@Composable
private fun FolderHeader(
    folder: Folder,
    path: String,
    open: Boolean,
    toggle: () -> Unit,
    enable: (Boolean) -> Unit,
    delete: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = toggle).padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            (if (open) "▾ " else "▸ ") + path,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f),
        )
        if (!folder.locked) {
            TextButton(onClick = delete) { Text("Delete") }
            Switch(checked = folder.enabled, onCheckedChange = enable)
        }
    }
}

@Composable
private fun AskDialog(
    asking: Asking,
    folders: Map<Long, Folder>,
    done: () -> Unit,
    act: (Request) -> Unit,
    selected: Set<Long>,
    moved: () -> Unit,
) {
    when (asking) {
        Asking.NewFolder -> {
            var name by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = done,
                title = { Text("New folder") },
                text = { OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true) },
                confirmButton = {
                    TextButton(enabled = name.isNotBlank(), onClick = {
                        act(Request(add_folder = AddFolder(folder = Folder(name = name.trim(), enabled = true))))
                        done()
                    }) { Text("Add") }
                },
                dismissButton = { TextButton(onClick = done) { Text("Cancel") } },
            )
        }

        Asking.Move -> {
            AlertDialog(
                onDismissRequest = done,
                title = { Text("Move ${selected.size} rules to") },
                text = {
                    Column {
                        val choices =
                            listOf<Pair<Long?, String>>(null to "The top level") +
                                folders.values
                                    .filter { !it.locked }
                                    .map { it.id to path(it.id, folders) }
                                    .sortedBy { it.second }
                        for ((id, name) in choices) {
                            Text(
                                name,
                                modifier =
                                    Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            act(Request(edit_rules = EditRules(ids = selected.toList(), move = MoveRules(folder = id))))
                                            moved()
                                            done()
                                        }.padding(vertical = 12.dp),
                            )
                        }
                    }
                },
                confirmButton = {},
                dismissButton = { TextButton(onClick = done) { Text("Cancel") } },
            )
        }

        is Asking.DeleteFolder -> {
            AlertDialog(
                onDismissRequest = done,
                title = { Text("Delete ${asking.path}?") },
                text = { Text("The folder goes with the folders inside it and all their rules.") },
                confirmButton = {
                    TextButton(onClick = {
                        act(Request(delete_folder = DeleteFolder(id = asking.folder.id)))
                        done()
                    }) { Text("Delete") }
                },
                dismissButton = { TextButton(onClick = done) { Text("Cancel") } },
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun RuleCard(
    session: NodeSession,
    rule: Rule,
    selected: Boolean,
    selecting: Boolean,
    select: () -> Unit,
    changed: () -> Unit,
    edit: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    Card(
        Modifier.fillMaxWidth().combinedClickable(
            enabled = !rule.locked,
            onClick = { if (selecting) select() else edit() },
            onLongClick = select,
        ),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                if (selecting && !rule.locked) Checkbox(checked = selected, onCheckedChange = { select() })
                Text(rule.name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
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
            if (!rule.locked && !selecting) {
                Row {
                    TextButton(onClick = edit) { Text("Edit") }
                    TextButton(onClick = {
                        scope.launch {
                            error = run(session, Request(delete_rule = DeleteRule(id = rule.id)))
                            changed()
                        }
                    }) { Text("Delete") }
                }
            }
        }
    }
}
