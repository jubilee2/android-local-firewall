package com.localfirewall.app.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import com.localfirewall.app.data.FirewallSettings
import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.data.TrafficLogEntry
import com.localfirewall.app.firewall.AppFirewallRule
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.firewall.IPv6Cidr
import com.localfirewall.app.firewall.IpAddressLiteral
import com.localfirewall.app.network.TransportProtocol

@Entity(
    tableName = "app_rules",
    indices = [Index(value = ["uid"])],
)
data class AppRuleEntity(
    @PrimaryKey
    val packageName: String,
    val uid: Int,
    val action: String,
    val updatedAtMillis: Long,
) {
    fun toDomain(): AppFirewallRule = AppFirewallRule(
        uid = uid,
        packageName = packageName,
        action = FirewallAction.valueOf(action),
    )
}

fun AppFirewallRule.toEntity(updatedAtMillis: Long): AppRuleEntity = AppRuleEntity(
    packageName = packageName,
    uid = uid,
    action = action.name,
    updatedAtMillis = updatedAtMillis,
)

@Entity(
    tableName = "network_rules",
    indices = [Index(value = ["priority", "createdAtMillis"])],
)
data class NetworkRuleEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val action: String,
    val destinationAddress: String?,
    val destinationCidr: String?,
    val protocol: String,
    val destinationPort: Int?,
    val enabled: Boolean,
    val priority: Int,
    val createdAtMillis: Long,
) {
    fun toDomain(): StoredNetworkRule {
        val ipv4Cidr = destinationCidr?.takeIf { ':' !in it }?.let(IPv4Cidr::parse)
        val ipv6Cidr = destinationCidr?.takeIf { ':' in it }?.let(IPv6Cidr::parse)
        return StoredNetworkRule(
            id = id,
            action = FirewallAction.valueOf(action),
            destinationAddress = destinationAddress?.let(IpAddressLiteral::parse),
            destinationCidr = ipv4Cidr,
            destinationIpv6Cidr = ipv6Cidr,
            protocol = TransportProtocol.valueOf(protocol),
            destinationPort = destinationPort,
            enabled = enabled,
            priority = priority,
            createdAtMillis = createdAtMillis,
        )
    }
}

fun StoredNetworkRule.toEntity(): NetworkRuleEntity = NetworkRuleEntity(
    id = id,
    action = action.name,
    destinationAddress = destinationAddress?.let(IpAddressLiteral::format),
    destinationCidr = destinationCidr?.format() ?: destinationIpv6Cidr?.format(),
    protocol = protocol.name,
    destinationPort = destinationPort,
    enabled = enabled,
    priority = priority,
    createdAtMillis = createdAtMillis,
)

@Entity(tableName = "firewall_settings")
data class FirewallSettingsEntity(
    @PrimaryKey
    val singletonId: Int = SINGLETON_ID,
    val trafficLoggingEnabled: Boolean,
    val includeSystemApps: Boolean,
    val maxTrafficLogEntries: Int,
) {
    fun toDomain(): FirewallSettings = FirewallSettings(
        trafficLoggingEnabled = trafficLoggingEnabled,
        includeSystemApps = includeSystemApps,
        maxTrafficLogEntries = maxTrafficLogEntries.coerceIn(
            FirewallSettings.MIN_TRAFFIC_LOG_ENTRIES,
            FirewallSettings.MAX_TRAFFIC_LOG_ENTRIES,
        ),
    )

    companion object {
        const val SINGLETON_ID = 1
    }
}

fun FirewallSettings.toEntity(): FirewallSettingsEntity = FirewallSettingsEntity(
    singletonId = FirewallSettingsEntity.SINGLETON_ID,
    trafficLoggingEnabled = trafficLoggingEnabled,
    includeSystemApps = includeSystemApps,
    maxTrafficLogEntries = maxTrafficLogEntries,
)

@Entity(
    tableName = "traffic_logs",
    indices = [Index(value = ["timestampMillis"])],
)
data class TrafficLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestampMillis: Long,
    val uid: Int?,
    val applicationName: String?,
    val packageName: String?,
    val protocol: String,
    val sourceAddress: String,
    val destinationAddress: String,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val action: String,
) {
    fun toDomain(): TrafficLogEntry = TrafficLogEntry(
        id = id,
        timestampMillis = timestampMillis,
        uid = uid,
        applicationName = applicationName,
        packageName = packageName,
        protocol = TransportProtocol.valueOf(protocol),
        sourceAddress = sourceAddress,
        destinationAddress = destinationAddress,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        action = FirewallAction.valueOf(action),
    )
}

fun TrafficLogEntry.toEntity(): TrafficLogEntity = TrafficLogEntity(
    id = id,
    timestampMillis = timestampMillis,
    uid = uid,
    applicationName = applicationName,
    packageName = packageName,
    protocol = protocol.name,
    sourceAddress = sourceAddress,
    destinationAddress = destinationAddress,
    sourcePort = sourcePort,
    destinationPort = destinationPort,
    action = action.name,
)
