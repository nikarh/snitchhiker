package dev.nikarh.snitchhiker.app

/**
 * The Rust core (crates/mobile): keys, pairing, and connections to nodes over iroh. Requests and notices cross as the
 * protocol's messages, encoded. Every call blocks: callers are off the main thread. Errors are RuntimeExceptions.
 */
object Native {
    init {
        System.loadLibrary("snitchhiker_mobile")
    }

    @JvmStatic external fun generateKey(): ByteArray

    @JvmStatic external fun keyId(key: ByteArray): String

    /** Pairs by a link or a code; the node, as JSON. */
    @JvmStatic external fun pair(
        key: ByteArray,
        linkOrCode: String,
        name: String,
        relays: Array<String>,
    ): String

    @JvmStatic external fun connect(
        key: ByteArray,
        node: String,
    ): Long

    @JvmStatic external fun welcome(connection: Long): ByteArray

    @JvmStatic external fun call(
        connection: Long,
        request: ByteArray,
    ): ByteArray

    @JvmStatic external fun subscribe(
        connection: Long,
        topic: Int,
    ): Long

    @JvmStatic external fun nextNotice(
        connection: Long,
        timeoutMs: Long,
    ): ByteArray?

    @JvmStatic external fun close(connection: Long)
}
