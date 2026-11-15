package dev.nikarh.snitchhiker.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import snitchhiker.v1.Notice
import snitchhiker.v1.Request
import snitchhiker.v1.Response
import snitchhiker.v1.Topic
import snitchhiker.v1.Welcome
import java.io.IOException

/**
 * One connection to a node, as the Rust core holds it: the protocol's messages cross encoded. Blocking: called off the
 * main thread.
 */
interface Link {
    val welcome: ByteArray

    fun call(request: ByteArray): ByteArray

    fun subscribe(topic: Int): Long

    /** The next notice, or null when none came within [timeoutMs]. Throws when the connection is gone. */
    fun nextNotice(timeoutMs: Long): ByteArray?

    fun close()
}

/** A node error, as the node said it. */
class NodeError(
    val code: snitchhiker.v1.ErrorCode,
    message: String,
) : IOException(message)

/**
 * A node: one connection for requests and one for notices, so a slow request never holds the notices back (as the
 * desktop app does).
 */
class NodeClient(
    private val requests: Link,
    private val notices: Link,
) : AutoCloseable {
    val welcome: Welcome = Welcome.ADAPTER.decode(requests.welcome)

    /** Sends a request; its result, or a [NodeError]. */
    suspend fun call(request: Request): Response =
        withContext(Dispatchers.IO) {
            val response = Response.ADAPTER.decode(requests.call(Request.ADAPTER.encode(request)))
            response.error?.let { throw NodeError(it.code, it.message) }
            response
        }

    /** Subscribes the notices connection to [topics] and yields its notices until it closes. */
    fun notices(topics: List<Topic>): Flow<Notice> =
        flow {
            for (topic in topics) notices.subscribe(topic.value)
            while (currentCoroutineContext().isActive) {
                val bytes = notices.nextNotice(NOTICE_WAIT_MS) ?: continue
                emit(Notice.ADAPTER.decode(bytes))
            }
        }.flowOn(Dispatchers.IO)

    override fun close() {
        requests.close()
        notices.close()
    }

    private companion object {
        // How long one wait for a notice lasts: the loop checks for cancellation between waits.
        const val NOTICE_WAIT_MS = 1000L
    }
}
