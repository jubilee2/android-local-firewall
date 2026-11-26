package com.localfirewall.app.vpn

import android.content.pm.PackageManager
import android.os.Build
import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.data.TrafficLogEntry
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.FragmentDecisionEngine
import com.localfirewall.app.firewall.RuleEngine
import com.localfirewall.app.network.PacketMetadata
import java.io.Closeable
import java.util.LinkedHashMap
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/** Application display metadata resolved for an Android UID. */
data class UidApplicationInfo(
    val packageName: String,
    val applicationName: String,
)

/** Injectable boundary mapping an Android UID to package/label metadata for traffic logs. */
fun interface UidApplicationLookup {
    fun lookup(uid: Int): UidApplicationInfo?
}

/** Cached [UidApplicationLookup] backed by Android's [PackageManager]. */
class PackageManagerUidApplicationLookup(
    private val packageManager: PackageManager,
    private val cacheCapacity: Int = DEFAULT_CACHE_CAPACITY,
) : UidApplicationLookup {
    private val cache = object : LinkedHashMap<Int, UidApplicationInfo?>(cacheCapacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, UidApplicationInfo?>?): Boolean =
            size > cacheCapacity
    }

    init {
        require(cacheCapacity > 0) { "cacheCapacity must be positive" }
    }

    @Synchronized
    override fun lookup(uid: Int): UidApplicationInfo? {
        if (cache.containsKey(uid)) return cache[uid]
        val resolved = resolveUncached(uid)
        cache[uid] = resolved
        return resolved
    }

    private fun resolveUncached(uid: Int): UidApplicationInfo? {
        val packageName = packageManager.getPackagesForUid(uid)
            ?.sorted()
            ?.firstOrNull()
            ?: return null
        val appLabel = runCatching {
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(packageName, 0)
            }
            packageManager.getApplicationLabel(appInfo).toString().trim().ifEmpty { packageName }
        }.getOrDefault(packageName)
        return UidApplicationInfo(packageName = packageName, applicationName = appLabel)
    }

    private companion object {
        const val DEFAULT_CACHE_CAPACITY = 256
    }
}

/**
 * Synchronizes persisted rules into [FragmentDecisionEngine] and asynchronously records bounded,
 * metadata-only packet decisions without blocking the TUN packet-reading loop.
 */
internal class PacketDecisionCoordinator(
    private val repository: FirewallRepository,
    private val failClosedOnUnknownUid: Boolean = false,
    private val fragmentDecisionEngine: FragmentDecisionEngine = FragmentDecisionEngine(
        RuleEngine(emptyList(), failClosedOnUnknownUid = failClosedOnUnknownUid),
    ),
    private val uidApplicationLookup: UidApplicationLookup = UidApplicationLookup { null },
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val currentTimeMillis: () -> Long = System::currentTimeMillis,
    logBufferCapacity: Int = DEFAULT_LOG_BUFFER_CAPACITY,
) : Closeable {
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val logChannel = Channel<TrafficLogEntry>(
        capacity = logBufferCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private var started = false
    private var closed = false

    init {
        require(logBufferCapacity > 0) { "logBufferCapacity must be positive" }
    }

    @Synchronized
    fun start() {
        if (started || closed) return
        started = true
        scope.launch {
            repository.activeFirewallRules.collect { activeRules ->
                fragmentDecisionEngine.updateRuleEngine(
                    RuleEngine(activeRules, failClosedOnUnknownUid = failClosedOnUnknownUid),
                )
            }
        }
        scope.launch {
            for (entry in logChannel) {
                runCatching { repository.recordTrafficLog(entry) }
            }
        }
    }

    fun evaluateAndRecord(metadata: PacketMetadata): FirewallAction {
        val action = fragmentDecisionEngine.evaluate(metadata)
        if (metadata.fragmentOffset == 0) {
            val appInfo = metadata.uid?.let(uidApplicationLookup::lookup)
            val sourceHost = metadata.sourceAddress.hostAddress ?: metadata.sourceAddress.toString()
            val destinationHost = metadata.destinationAddress.hostAddress ?: metadata.destinationAddress.toString()
            logChannel.trySend(
                TrafficLogEntry(
                    timestampMillis = currentTimeMillis(),
                    uid = metadata.uid,
                    applicationName = appInfo?.applicationName,
                    packageName = appInfo?.packageName,
                    protocol = metadata.protocol,
                    sourceAddress = sourceHost,
                    destinationAddress = destinationHost,
                    sourcePort = metadata.sourcePort,
                    destinationPort = metadata.destinationPort,
                    action = action,
                ),
            )
        }
        return action
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        logChannel.close()
        scope.cancel()
        fragmentDecisionEngine.close()
    }

    private companion object {
        const val DEFAULT_LOG_BUFFER_CAPACITY = 256
    }
}
