package dev.nikarh.snitchhiker.app

import dev.nikarh.snitchhiker.core.Link

/** A connection to a node held by the Rust core. */
class RustLink(
    key: ByteArray,
    node: NodeInfo,
) : Link {
    private val handle: Long = Native.connect(key, node.toJson().toString())

    override val welcome: ByteArray = Native.welcome(handle)

    override fun call(request: ByteArray): ByteArray = Native.call(handle, request)

    override fun subscribe(topic: Int): Long = Native.subscribe(handle, topic)

    override fun nextNotice(timeoutMs: Long): ByteArray? = Native.nextNotice(handle, timeoutMs)

    override fun close() = Native.close(handle)
}
