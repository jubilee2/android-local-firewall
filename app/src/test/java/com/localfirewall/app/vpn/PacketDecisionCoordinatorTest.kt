package com.localfirewall.app.vpn

import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.data.InMemoryFirewallLocalStore
import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PacketDecisionCoordinatorTest {
    @Test
    fun `synchronizes repository rules and records first-fragment traffic metadata`() = runTest {
        val testDispatcher = StandardTestDispatcher(testScheduler)
        val repository = FirewallRepository(
            store = InMemoryFirewallLocalStore(),
            currentTimeMillis = { 20_000L },
        )
        val coordinator = PacketDecisionCoordinator(
            repository = repository,
            uidApplicationLookup = UidApplicationLookup { uid ->
                if (uid == 10420) {
                    UidApplicationInfo(
                        packageName = "org.example.browser",
                        applicationName = "Example Browser",
                    )
                } else {
                    null
                }
            },
            dispatcher = testDispatcher,
            currentTimeMillis = { 30_000L },
        )

        try {
            coordinator.start()
            advanceUntilIdle()

            // Initially allowed by default policy.
            val initialPacket = packet(destination = "8.8.8.8", uid = 10420, moreFragments = true)
            assertEquals(FirewallAction.ALLOW, coordinator.evaluateAndRecord(initialPacket))
            // Second fragment reuses cached decision and does not emit a second log row.
            val secondFragment = initialPacket.copy(
                sourcePort = null,
                destinationPort = null,
                fragmentOffset = 1,
                moreFragments = false,
                uid = null,
            )
            assertEquals(FirewallAction.ALLOW, coordinator.evaluateAndRecord(secondFragment))
            advanceUntilIdle()

            val initialLogs = repository.trafficLogs.first()
            assertEquals(1, initialLogs.size)
            assertEquals("Example Browser", initialLogs.single().applicationName)
            assertEquals("org.example.browser", initialLogs.single().packageName)
            assertEquals(FirewallAction.ALLOW, initialLogs.single().action)

            // Updating repository rules dynamically updates future packet evaluations.
            repository.addOrUpdateNetworkRule(
                StoredNetworkRule(
                    action = FirewallAction.BLOCK,
                    destinationAddress = IPv4Cidr.parseAddress("8.8.8.8"),
                ),
            )
            advanceUntilIdle()

            val blockedPacket = packet(destination = "8.8.8.8", uid = 10420, moreFragments = false)
            assertEquals(FirewallAction.BLOCK, coordinator.evaluateAndRecord(blockedPacket))
            advanceUntilIdle()

            val updatedLogs = repository.trafficLogs.first()
            assertEquals(2, updatedLogs.size)
            assertEquals(FirewallAction.BLOCK, updatedLogs.first().action)
        } finally {
            coordinator.close()
        }
    }

    private fun packet(
        destination: String,
        uid: Int?,
        moreFragments: Boolean,
    ) = PacketMetadata(
        sourceAddress = InetAddress.getByName("10.0.0.2"),
        destinationAddress = InetAddress.getByName(destination),
        protocol = TransportProtocol.TCP,
        sourcePort = 52345,
        destinationPort = 443,
        identification = 99,
        fragmentOffset = 0,
        moreFragments = moreFragments,
        uid = uid,
    )
}
