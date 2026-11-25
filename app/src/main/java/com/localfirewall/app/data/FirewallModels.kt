package com.localfirewall.app.data

import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.FirewallRule
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.network.TransportProtocol
import java.net.Inet4Address

/** Persisted network-level firewall rule with ordering and enablement metadata. */
data class StoredNetworkRule(
    val id: Long = 0,
    val action: FirewallAction,
    val destinationAddress: Inet4Address? = null,
    val destinationCidr: IPv4Cidr? = null,
    val protocol: TransportProtocol = TransportProtocol.ANY,
    val destinationPort: Int? = null,
    val enabled: Boolean = true,
    val priority: Int = 0,
    val createdAtMillis: Long = 0L,
) {
    init {
        require(destinationAddress == null || destinationCidr == null) {
            "Specify either an exact destination or a CIDR, not both"
        }
        require(destinationPort == null || destinationPort in 0..65535) {
            "Destination port must be between 0 and 65535"
        }
        require(
            destinationAddress != null ||
                destinationCidr != null ||
                protocol != TransportProtocol.ANY ||
                destinationPort != null,
        ) {
            "Network rule must specify at least one destination, protocol, or port criterion"
        }
    }

    fun toFirewallRule(): FirewallRule = FirewallRule(
        action = action,
        destinationAddress = destinationAddress,
        destinationCidr = destinationCidr,
        protocol = protocol,
        destinationPort = destinationPort,
    )
}

/** Locally persisted user settings for firewall display and bounded traffic logging. */
data class FirewallSettings(
    val trafficLoggingEnabled: Boolean = true,
    val includeSystemApps: Boolean = false,
    val maxTrafficLogEntries: Int = DEFAULT_MAX_TRAFFIC_LOG_ENTRIES,
) {
    init {
        require(maxTrafficLogEntries in MIN_TRAFFIC_LOG_ENTRIES..MAX_TRAFFIC_LOG_ENTRIES) {
            "maxTrafficLogEntries must be between $MIN_TRAFFIC_LOG_ENTRIES and $MAX_TRAFFIC_LOG_ENTRIES"
        }
    }

    companion object {
        const val DEFAULT_MAX_TRAFFIC_LOG_ENTRIES = 500
        const val MIN_TRAFFIC_LOG_ENTRIES = 10
        const val MAX_TRAFFIC_LOG_ENTRIES = 10_000
    }
}

/**
 * Locally persisted packet decision record.
 *
 * Strictly restricted to connection header metadata and decision outcome; packet payload bytes and
 * application-layer content are never captured or stored.
 */
data class TrafficLogEntry(
    val id: Long = 0,
    val timestampMillis: Long,
    val uid: Int?,
    val applicationName: String?,
    val packageName: String?,
    val protocol: TransportProtocol,
    val sourceAddress: String,
    val destinationAddress: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val action: FirewallAction,
) {
    init {
        require(uid == null || uid >= 0) { "uid must be non-negative" }
        require(sourceAddress.isNotBlank()) { "sourceAddress must not be blank" }
        require(destinationAddress.isNotBlank()) { "destinationAddress must not be blank" }
        require(sourcePort == null || sourcePort in 0..65535) {
            "sourcePort must be between 0 and 65535"
        }
        require(destinationPort == null || destinationPort in 0..65535) {
            "destinationPort must be between 0 and 65535"
        }
    }
}
