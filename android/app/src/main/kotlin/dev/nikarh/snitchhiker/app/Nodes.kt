package dev.nikarh.snitchhiker.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** A node paired with this device: its JSON is what the Rust core takes to connect. */
data class NodeInfo(
    val name: String,
    val id: String,
    val relays: List<String>,
    val addrs: List<String>,
    val role: String,
) {
    fun toJson(): JSONObject =
        JSONObject()
            .put("name", name)
            .put("id", id)
            .put("relays", JSONArray(relays))
            .put("addrs", JSONArray(addrs))
            .put("role", role)

    companion object {
        fun fromJson(json: JSONObject): NodeInfo {
            fun list(key: String): List<String> {
                val array = json.optJSONArray(key) ?: return emptyList()
                return List(array.length()) { array.getString(it) }
            }
            return NodeInfo(
                name = json.getString("name"),
                id = json.getString("id"),
                relays = list("relays"),
                addrs = list("addrs"),
                role = json.optString("role", "admin"),
            )
        }
    }
}

/** The nodes paired, in the app's private files (excluded from backups). */
object NodeStore {
    private const val FILE = "nodes.json"

    @Synchronized
    fun load(context: Context): List<NodeInfo> {
        val file = File(context.noBackupFilesDir, FILE)
        if (!file.exists()) return emptyList()
        val array = JSONArray(file.readText())
        return List(array.length()) { NodeInfo.fromJson(array.getJSONObject(it)) }
    }

    @Synchronized
    fun save(
        context: Context,
        nodes: List<NodeInfo>,
    ) {
        val file = File(context.noBackupFilesDir, FILE)
        val temporary = File(context.noBackupFilesDir, "$FILE.new")
        temporary.writeText(JSONArray(nodes.map { it.toJson() }).toString())
        temporary.renameTo(file)
    }
}
