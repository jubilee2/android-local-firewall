package com.localfirewall.app.firewall

import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import com.localfirewall.app.network.FlowKey
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetSocketAddress
import java.util.LinkedHashMap

/** Injectable boundary around Android's connection-owner API. */
fun interface ConnectionOwnerLookup {
    fun getConnectionOwnerUid(
        protocol: Int,
        localAddress: InetSocketAddress,
        remoteAddress: InetSocketAddress,
    ): Int
}

/** Production implementation of [ConnectionOwnerLookup]. */
class AndroidConnectionOwnerLookup(
    private val connectivityManager: ConnectivityManager,
) : ConnectionOwnerLookup {
    override fun getConnectionOwnerUid(
        protocol: Int,
        localAddress: InetSocketAddress,
        remoteAddress: InetSocketAddress,
    ): Int = connectivityManager.getConnectionOwnerUid(protocol, localAddress, remoteAddress)
}

/** Cache contract kept separate so eviction behavior can be tested independently. */
interface FlowUidCache {
    fun get(flow: FlowKey): Int?
    fun put(flow: FlowKey, uid: Int)
}

/** Supplies elapsed monotonic time in nanoseconds. */
fun interface MonotonicClock {
    fun nanoTime(): Long
}

/** Thread-safe, expiring, access-ordered LRU cache with a fixed maximum number of flows. */
class BoundedFlowUidCache(
    private val maximumSize: Int = DEFAULT_MAXIMUM_SIZE,
    private val ttlNanos: Long = DEFAULT_TTL_NANOS,
    private val clock: MonotonicClock = MonotonicClock(System::nanoTime),
) : FlowUidCache {
    private data class Entry(val uid: Int, val cachedAtNanos: Long)

    private val entries = object : LinkedHashMap<FlowKey, Entry>(maximumSize, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, Entry>?): Boolean =
            size > maximumSize
    }

    init {
        require(maximumSize > 0) { "maximumSize must be positive" }
        require(ttlNanos > 0) { "ttlNanos must be positive" }
    }

    @Synchronized
    override fun get(flow: FlowKey): Int? {
        val entry = entries[flow] ?: return null
        if (clock.nanoTime() - entry.cachedAtNanos >= ttlNanos) {
            entries.remove(flow)
            return null
        }
        return entry.uid
    }

    @Synchronized
    override fun put(flow: FlowKey, uid: Int) {
        entries[flow] = Entry(uid = uid, cachedAtNanos = clock.nanoTime())
    }

    private companion object {
        const val DEFAULT_MAXIMUM_SIZE = 1_024
        const val DEFAULT_TTL_NANOS = 30_000_000_000L
    }
}

/** Resolves Android ownership only for complete, first-fragment TCP/UDP metadata. */
class ConnectionOwnerResolver(
    private val lookup: ConnectionOwnerLookup,
    private val cache: FlowUidCache = BoundedFlowUidCache(),
) {
    fun resolve(packet: PacketMetadata): Int? {
        val sourcePort = packet.sourcePort ?: return null
        val destinationPort = packet.destinationPort ?: return null
        if (packet.fragmentOffset != 0) return null
        val androidProtocol = when (packet.protocol) {
            TransportProtocol.TCP -> OsConstants.IPPROTO_TCP
            TransportProtocol.UDP -> OsConstants.IPPROTO_UDP
            TransportProtocol.ANY -> return null
        }
        val flow = FlowKey(
            protocol = packet.protocol,
            sourceAddress = packet.sourceAddress,
            sourcePort = sourcePort,
            destinationAddress = packet.destinationAddress,
            destinationPort = destinationPort,
        )
        cache.get(flow)?.let { return it }

        val uid = try {
            lookup.getConnectionOwnerUid(
                protocol = androidProtocol,
                localAddress = InetSocketAddress(packet.sourceAddress, sourcePort),
                remoteAddress = InetSocketAddress(packet.destinationAddress, destinationPort),
            )
        } catch (_: SecurityException) {
            return null
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (uid == Process.INVALID_UID) return null
        cache.put(flow, uid)
        return uid
    }
}
