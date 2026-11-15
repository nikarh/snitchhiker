package dev.nikarh.snitchhiker.app.ui

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.nikarh.snitchhiker.app.DeviceKey
import dev.nikarh.snitchhiker.app.Native
import dev.nikarh.snitchhiker.app.NodeInfo
import dev.nikarh.snitchhiker.app.SnitchhikerApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Adding a node: its code, its link, or its QR code (scanned). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairScreen(
    app: SnitchhikerApp,
    prefill: String,
    done: (String?) -> Unit,
) {
    val context = LocalContext.current
    var linkOrCode by remember { mutableStateOf(prefill) }
    var name by remember { mutableStateOf(Build.MODEL ?: "phone") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    if (scanning) {
        ScanScreen(found = {
            linkOrCode = it
            scanning = false
        }, cancel = { scanning = false })
        return
    }
    Scaffold(topBar = { TopAppBar(title = { Text("Add a node") }) }) { padding ->
        Column(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                "On the node, run `sudo snitchhiker pair` (or Devices → Pair a device in its desktop app). Type the code it " +
                    "shows, paste its link, or scan its QR code.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = linkOrCode,
                onValueChange = { linkOrCode = it },
                label = { Text("Code or link") },
                placeholder = { Text("412-orbit-velvet-canyon") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("This device's name there") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = !busy && linkOrCode.isNotBlank(), onClick = {
                    busy = true
                    error = null
                    scope.launch {
                        val result =
                            withContext(Dispatchers.IO) {
                                runCatching { pair(context, app, linkOrCode.trim(), name.trim()) }
                            }
                        busy = false
                        result.fold(onSuccess = { done(it.id) }, onFailure = { error = it.message })
                    }
                }) { Text(if (busy) "Pairing…" else "Pair") }
                OutlinedButton(onClick = { scanning = true }) { Text("Scan QR code") }
                OutlinedButton(onClick = { done(null) }) { Text("Cancel") }
            }
        }
    }
}

/** Pairs, holding a multicast lock meanwhile (a code is looked for on the local network by mDNS). */
private fun pair(
    context: Context,
    app: SnitchhikerApp,
    linkOrCode: String,
    name: String,
): NodeInfo {
    val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
    val lock = wifi?.createMulticastLock("snitchhiker-pairing")?.apply { acquire() }
    try {
        val node = NodeInfo.fromJson(JSONObject(Native.pair(DeviceKey.get(context), linkOrCode, name, app.relays())))
        app.add(node)
        return node
    } finally {
        lock?.release()
    }
}
