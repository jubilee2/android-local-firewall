package com.localfirewall.app.vpn

import com.localfirewall.app.network.IPv4PacketParser
import com.localfirewall.app.network.TcpPacketParser
import com.localfirewall.app.network.UdpPacketParser
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/** A bounded packet source, separated from Android's TUN descriptor for unit testing. */
internal fun interface PacketSource : Closeable {
    fun read(buffer: ByteArray): Int

    override fun close() = Unit
}

internal class InputStreamPacketSource(
    private val input: InputStream,
) : PacketSource {
    override fun read(buffer: ByteArray): Int = input.read(buffer)

    override fun close() = input.close()
}

/** Consumes packets from a TUN source on a dedicated background coroutine. */
internal class PacketProcessor(
    private val source: PacketSource,
    private val packetHandler: (ByteArray) -> Unit = ::parsePacketMetadata,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
) : Closeable {
    private var worker: Job? = null
    private var stopped = false

    init {
        require(bufferSize > 0) { "bufferSize must be positive" }
    }

    @Synchronized
    fun start() {
        if (worker != null || stopped) return
        worker = Job().let { parent ->
            kotlinx.coroutines.CoroutineScope(parent + dispatcher).launch {
                readPackets()
            }
        }
    }

    private suspend fun readPackets() {
        val buffer = ByteArray(bufferSize)
        try {
            while (currentCoroutineContext().isActive) {
                val length = source.read(buffer)
                if (length < 0) break
                if (length == 0) continue
                packetHandler(buffer.copyOf(length))
            }
        } catch (_: IOException) {
            // Closing the packet source is the normal way to unblock a TUN read during shutdown.
        } catch (_: CancellationException) {
            // Cancellation is an expected shutdown signal.
        } catch (_: Exception) {
            // An unexpected parser or source failure ends this worker without crashing the service.
        }
    }

    override fun close() {
        val job = synchronized(this) {
            if (stopped) return
            stopped = true
            runCatching { source.close() }
            worker.also { worker = null }
        }
        runBlocking {
            job?.cancelAndJoin()
        }
    }

    internal fun isRunning(): Boolean = synchronized(this) { worker?.isActive == true }

    private companion object {
        const val DEFAULT_BUFFER_SIZE = 32 * 1024
    }
}

/** Parses header metadata only; packet bytes and parsed results are deliberately not retained. */
private fun parsePacketMetadata(packet: ByteArray) {
    val ipv4 = IPv4PacketParser.parse(packet) ?: return
    when (ipv4.protocol) {
        6 -> TcpPacketParser.parse(packet, ipv4)
        17 -> UdpPacketParser.parse(packet, ipv4)
    }
}
