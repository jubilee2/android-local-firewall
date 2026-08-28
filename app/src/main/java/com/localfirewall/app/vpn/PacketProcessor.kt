package com.localfirewall.app.vpn

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.localfirewall.app.network.IPv4PacketParser
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TcpPacketParser
import com.localfirewall.app.network.TransportProtocol
import com.localfirewall.app.network.UdpPacketParser
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** A bounded packet source, separated from Android's TUN descriptor for unit testing. */
internal fun interface PacketSource : Closeable {
    fun read(buffer: ByteArray): Int

    override fun close() = Unit
}

/** Polls the non-blocking TUN descriptor so cancellation is observed within [pollTimeoutMillis]. */
internal class PollingTunPacketSource(
    private val descriptor: FileDescriptor,
    private val pollTimeoutMillis: Int = DEFAULT_POLL_TIMEOUT_MILLIS,
) : PacketSource {
    init {
        require(pollTimeoutMillis > 0) { "pollTimeoutMillis must be positive" }
    }

    override fun read(buffer: ByteArray): Int {
        val pollDescriptor = StructPollfd().apply {
            fd = descriptor
            events = OsConstants.POLLIN.toShort()
        }
        return try {
            if (Os.poll(arrayOf(pollDescriptor), pollTimeoutMillis) == 0) {
                NO_PACKET
            } else {
                val length = Os.read(descriptor, buffer, 0, buffer.size)
                if (length == 0) END_OF_STREAM else length
            }
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.EAGAIN) {
                NO_PACKET
            } else {
                throw IOException("TUN polling or read failed", error)
            }
        }
    }

    private companion object {
        const val DEFAULT_POLL_TIMEOUT_MILLIS = 200
        const val NO_PACKET = 0
        const val END_OF_STREAM = -1
    }
}

/** Consumes packets from a TUN source on a dedicated background coroutine. */
internal class PacketProcessor(
    private val source: PacketSource,
    private val packetHandler: (ByteArray) -> Unit = {},
    private val metadataHandler: (PacketMetadata) -> Unit = {},
    private val onUnexpectedTermination: (PacketProcessor) -> Unit = {},
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val bufferSize: Int = DEFAULT_BUFFER_SIZE,
) : Closeable {
    private var worker: Job? = null
    @Volatile
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
        var terminatedUnexpectedly = false
        try {
            while (currentCoroutineContext().isActive) {
                val length = source.read(buffer)
                if (length < 0) {
                    terminatedUnexpectedly = !stopped
                    break
                }
                if (length == 0) continue
                val packet = buffer.copyOf(length)
                packetHandler(packet)
                parsePacketMetadata(packet)?.let(metadataHandler)
            }
        } catch (_: IOException) {
            // Descriptor closure is expected during shutdown; other I/O failures stop the VPN.
            terminatedUnexpectedly = !stopped
        } catch (_: CancellationException) {
            // Cancellation is an expected shutdown signal.
        } catch (_: Exception) {
            // An unexpected parser or source failure ends this worker without crashing the service.
            terminatedUnexpectedly = !stopped
        } finally {
            runCatching { source.close() }
            if (terminatedUnexpectedly && !stopped) {
                runCatching { onUnexpectedTermination(this) }
            }
        }
    }

    /** Signals cancellation without waiting for a potentially blocked descriptor read. */
    override fun close() {
        synchronized(this) {
            if (stopped) return
            stopped = true
            worker?.cancel()
        }
    }

    internal fun isRunning(): Boolean = synchronized(this) { worker?.isActive == true }

    private companion object {
        const val DEFAULT_BUFFER_SIZE = 32 * 1024
    }
}

/** Parses header metadata only; packet bytes and parsed results are deliberately not retained. */
private fun parsePacketMetadata(packet: ByteArray): PacketMetadata? {
    val ipv4 = IPv4PacketParser.parse(packet) ?: return null
    val protocol = when (ipv4.protocol) {
        6 -> TransportProtocol.TCP
        17 -> TransportProtocol.UDP
        else -> TransportProtocol.ANY
    }
    val transport = when (protocol) {
        TransportProtocol.TCP -> TcpPacketParser.parse(packet, ipv4)
        TransportProtocol.UDP -> UdpPacketParser.parse(packet, ipv4)
        TransportProtocol.ANY -> null
    }
    return PacketMetadata(
        sourceAddress = ipv4.sourceAddress,
        destinationAddress = ipv4.destinationAddress,
        protocol = protocol,
        sourcePort = transport?.sourcePort,
        destinationPort = transport?.destinationPort,
    )
}
