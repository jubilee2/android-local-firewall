package com.localfirewall.app.data

import com.localfirewall.app.data.local.NetworkRuleEntity
import com.localfirewall.app.data.local.toEntity
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.firewall.RuleEngine
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class FirewallRepositoryTest {
    @Test
    fun `network rule entity round trips and rejects non-literal hostnames`() {
        val original = StoredNetworkRule(
            id = 7L,
            action = FirewallAction.BLOCK,
            destinationCidr = IPv4Cidr.parse("192.168.5.99/16"),
            protocol = TransportProtocol.TCP,
            destinationPort = 443,
            enabled = true,
            priority = 2,
            createdAtMillis = 1_234L,
        )

        val entity = original.toEntity()
        assertEquals("192.168.0.0/16", entity.destinationCidr)
        assertEquals(original, entity.toDomain())

        val invalidHostnameEntity = NetworkRuleEntity(
            id = 1L,
            action = "BLOCK",
            destinationAddress = "dns.google",
            destinationCidr = null,
            protocol = "TCP",
            destinationPort = 443,
            enabled = true,
            priority = 0,
            createdAtMillis = 100L,
        )
        assertThrows(IllegalArgumentException::class.java) {
            invalidHostnameEntity.toDomain()
        }
    }

    @Test
    fun `blocked app rule takes precedence over permissive network rule while allowed app obeys network block`() = runTest {
        val repository = FirewallRepository(
            store = InMemoryFirewallLocalStore(),
            currentTimeMillis = { 10_000L },
        )

        repository.setAppRule(uid = 10200, packageName = "com.blocked.browser", action = FirewallAction.BLOCK)
        repository.setAppRule(uid = 10300, packageName = "com.allowed.browser", action = FirewallAction.ALLOW)

        repository.addOrUpdateNetworkRule(
            StoredNetworkRule(
                action = FirewallAction.ALLOW,
                protocol = TransportProtocol.UDP,
                destinationPort = 53,
                priority = 1,
            ),
        )
        val disabledBlockId = repository.addOrUpdateNetworkRule(
            StoredNetworkRule(
                action = FirewallAction.BLOCK,
                destinationAddress = IPv4Cidr.parseAddress("1.1.1.1"),
                priority = 2,
            ),
        )
        repository.setNetworkRuleEnabled(id = disabledBlockId, enabled = false)
        repository.addOrUpdateNetworkRule(
            StoredNetworkRule(
                action = FirewallAction.BLOCK,
                destinationAddress = IPv4Cidr.parseAddress("8.8.8.8"),
                priority = 3,
            ),
        )

        val engine = RuleEngine(rules = repository.activeFirewallRules.first())

        // Blocked app cannot bypass via ALLOW UDP 53.
        assertEquals(
            FirewallAction.BLOCK,
            engine.evaluate(packet(destination = "8.8.4.4", protocol = TransportProtocol.UDP, port = 53, uid = 10200)),
        )
        // Allowed app is still blocked when contacting 8.8.8.8 on non-DNS TCP 443.
        assertEquals(
            FirewallAction.BLOCK,
            engine.evaluate(packet(destination = "8.8.8.8", protocol = TransportProtocol.TCP, port = 443, uid = 10300)),
        )
        // Disabled rule for 1.1.1.1 is ignored.
        assertEquals(
            FirewallAction.ALLOW,
            engine.evaluate(packet(destination = "1.1.1.1", protocol = TransportProtocol.TCP, port = 443, uid = 10300)),
        )

        // Switching blocked app back to ALLOW removes the block.
        repository.setAppRule(uid = 10200, packageName = "com.blocked.browser", action = FirewallAction.ALLOW)
        val updatedEngine = RuleEngine(rules = repository.activeFirewallRules.first())
        assertEquals(
            FirewallAction.ALLOW,
            updatedEngine.evaluate(packet(destination = "8.8.4.4", protocol = TransportProtocol.UDP, port = 53, uid = 10200)),
        )
    }

    @Test
    fun `traffic log enforces max retention settings and respects logging toggle`() = runTest {
        val repository = FirewallRepository(
            store = InMemoryFirewallLocalStore(),
            currentTimeMillis = { 50_000L },
        )
        repository.updateSettings(
            FirewallSettings(
                trafficLoggingEnabled = true,
                includeSystemApps = true,
                maxTrafficLogEntries = 10,
            ),
        )

        for (index in 1..15) {
            repository.recordTrafficLog(logEntry(timestampMillis = index * 100L, destinationPort = 1000 + index))
        }

        val logs = repository.trafficLogs.first()
        assertEquals(10, logs.size)
        assertEquals(1500L, logs.first().timestampMillis)
        assertEquals(600L, logs.last().timestampMillis)

        // Disabling logging prevents recording new entries.
        repository.updateSettings(
            FirewallSettings(
                trafficLoggingEnabled = false,
                includeSystemApps = true,
                maxTrafficLogEntries = 10,
            ),
        )
        assertNull(repository.recordTrafficLog(logEntry(timestampMillis = 9999L, destinationPort = 8443)))
        assertEquals(10, repository.trafficLogs.first().size)

        repository.clearTrafficLogs()
        assertEquals(emptyList<TrafficLogEntry>(), repository.trafficLogs.first())
    }

    private fun packet(
        destination: String,
        protocol: TransportProtocol,
        port: Int,
        uid: Int,
    ) = PacketMetadata(
        sourceAddress = InetAddress.getByName("192.0.2.10"),
        destinationAddress = InetAddress.getByName(destination),
        protocol = protocol,
        sourcePort = 51000,
        destinationPort = port,
        identification = 1,
        fragmentOffset = 0,
        moreFragments = false,
        uid = uid,
    )

    private fun logEntry(
        timestampMillis: Long,
        destinationPort: Int,
    ) = TrafficLogEntry(
        timestampMillis = timestampMillis,
        uid = 10150,
        applicationName = "Example App",
        packageName = "com.example.app",
        protocol = TransportProtocol.TCP,
        sourceAddress = "10.0.0.2",
        destinationAddress = "93.184.216.34",
        sourcePort = 49152,
        destinationPort = destinationPort,
        action = FirewallAction.ALLOW,
    )
}
