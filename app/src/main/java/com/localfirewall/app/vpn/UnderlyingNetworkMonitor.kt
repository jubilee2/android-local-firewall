package com.localfirewall.app.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.Closeable

/**
 * Pure state tracker determining which non-VPN underlying networks should be reported to
 * [android.net.VpnService.setUnderlyingNetworks].
 *
 * Explicitly excludes VPN networks so the local firewall never treats its own TUN interface as an
 * underlying upstream network.
 */
internal class UnderlyingNetworkTracker<N : Any>(
    private val onSelectionChanged: (List<N>) -> Unit,
) {
    private val eligibleNetworks = LinkedHashSet<N>()
    private var lastReported: List<N>? = null

    @Synchronized
    fun onCapabilitiesChanged(
        network: N,
        isNotVpn: Boolean,
        hasInternet: Boolean,
    ) {
        if (isNotVpn && hasInternet) {
            eligibleNetworks.add(network)
        } else {
            eligibleNetworks.remove(network)
        }
        emitIfChanged()
    }

    @Synchronized
    fun onLost(network: N) {
        if (eligibleNetworks.remove(network)) {
            emitIfChanged()
        }
    }

    @Synchronized
    fun reset() {
        eligibleNetworks.clear()
        lastReported = null
    }

    private fun emitIfChanged() {
        val snapshot = eligibleNetworks.toList()
        if (snapshot != lastReported) {
            lastReported = snapshot
            onSelectionChanged(snapshot)
        }
    }
}

/** Observes Android default network changes and updates `VpnService.setUnderlyingNetworks`. */
internal class AndroidUnderlyingNetworkMonitor(
    private val connectivityManager: ConnectivityManager,
    private val applyUnderlyingNetworks: (Array<Network>?) -> Unit,
) : Closeable {
    private val tracker = UnderlyingNetworkTracker<Network> { networks ->
        // Empty array signals no upstream connectivity; non-empty reports active upstream network(s).
        applyUnderlyingNetworks(networks.toTypedArray())
    }
    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            tracker.onCapabilitiesChanged(
                network = network,
                isNotVpn = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
                hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            )
        }

        override fun onLost(network: Network) {
            tracker.onLost(network)
        }
    }

    @Synchronized
    fun start() {
        if (registered) return
        runCatching {
            connectivityManager.registerDefaultNetworkCallback(callback)
            registered = true
        }
    }

    @Synchronized
    override fun close() {
        if (!registered) return
        registered = false
        tracker.reset()
        runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        runCatching { applyUnderlyingNetworks(null) }
    }
}
