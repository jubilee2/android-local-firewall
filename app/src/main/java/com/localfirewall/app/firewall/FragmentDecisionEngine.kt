package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.io.Closeable
import java.net.InetAddress

/**
 * Reuses a first fragment's firewall result for the rest of its IPv4 datagram.
 *
 * This does not reassemble fragments. A non-first fragment whose first-fragment decision is
 * unknown or expired is evaluated normally by [RuleEngine]. Consequently IP/CIDR-only rules can
 * still match, while rules requiring an unavailable port cannot match.
 */
class FragmentDecisionEngine(
    private val ruleEngine: RuleEngine,
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val entryLifetimeMillis: Long = DEFAULT_ENTRY_LIFETIME_MILLIS,
    private val elapsedRealtimeMillis: () -> Long = { System.nanoTime() / NANOS_PER_MILLISECOND },
) : Closeable {
    private data class FragmentIdentity(
        val sourceAddress: InetAddress,
        val destinationAddress: InetAddress,
        val protocol: TransportProtocol,
        val identification: Int,
    )

    private data class CachedDecision(
        val action: FirewallAction,
        val expiresAtMillis: Long,
    )

    private val decisions = LinkedHashMap<FragmentIdentity, CachedDecision>()

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(entryLifetimeMillis > 0) { "entryLifetimeMillis must be positive" }
    }

    @Synchronized
    fun evaluate(packet: PacketMetadata): FirewallAction {
        val now = elapsedRealtimeMillis()
        removeExpired(now)
        val identity = packet.fragmentIdentity()

        if (packet.fragmentOffset != 0) {
            decisions[identity]?.let { return it.action }
            return ruleEngine.evaluate(packet)
        }

        val action = ruleEngine.evaluate(packet)
        if (packet.moreFragments) {
            if (decisions.size >= maxEntries && identity !in decisions) {
                decisions.remove(decisions.keys.first())
            }
            decisions[identity] = CachedDecision(action, now + entryLifetimeMillis)
        }
        return action
    }

    @Synchronized
    override fun close() {
        decisions.clear()
    }

    internal fun cachedDecisionCount(): Int = synchronized(this) { decisions.size }

    private fun removeExpired(now: Long) {
        decisions.entries.removeAll { it.value.expiresAtMillis <= now }
    }

    private fun PacketMetadata.fragmentIdentity() = FragmentIdentity(
        sourceAddress = sourceAddress,
        destinationAddress = destinationAddress,
        protocol = protocol,
        identification = identification,
    )

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 1_024
        const val DEFAULT_ENTRY_LIFETIME_MILLIS = 30_000L
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
