package com.localfirewall.app.ui

import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.data.InMemoryFirewallLocalStore
import com.localfirewall.app.data.TrafficLogEntry
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.InstalledAppsProvider
import com.localfirewall.app.firewall.InstalledPackageScanner
import com.localfirewall.app.firewall.RawInstalledPackage
import com.localfirewall.app.network.TransportProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class FirewallStateHolderTest {
    @Test
    fun `NetworkRuleInputParser parses REQUIREMENTS examples and rejects invalid inputs`() {
        val blockIp = NetworkRuleInputParser.parse(
            action = FirewallAction.BLOCK,
            destinationInput = "8.8.8.8",
            protocol = TransportProtocol.ANY,
            portInput = "",
        ) as NetworkRuleParseResult.Valid
        assertEquals("8.8.8.8", blockIp.rule.destinationAddress?.hostAddress)

        val blockCidr = NetworkRuleInputParser.parse(
            action = FirewallAction.BLOCK,
            destinationInput = "192.168.0.0/16",
            protocol = TransportProtocol.ANY,
            portInput = "",
        ) as NetworkRuleParseResult.Valid
        assertEquals("192.168.0.0/16", blockCidr.rule.destinationCidr?.format())

        val blockTcp443 = NetworkRuleInputParser.parse(
            action = FirewallAction.BLOCK,
            destinationInput = "",
            protocol = TransportProtocol.TCP,
            portInput = "443",
        ) as NetworkRuleParseResult.Valid
        assertEquals(TransportProtocol.TCP, blockTcp443.rule.protocol)
        assertEquals(443, blockTcp443.rule.destinationPort)

        val allowUdp53 = NetworkRuleInputParser.parse(
            action = FirewallAction.ALLOW,
            destinationInput = "",
            protocol = TransportProtocol.UDP,
            portInput = "53",
        ) as NetworkRuleParseResult.Valid
        assertEquals(FirewallAction.ALLOW, allowUdp53.rule.action)
        assertEquals(TransportProtocol.UDP, allowUdp53.rule.protocol)
        assertEquals(53, allowUdp53.rule.destinationPort)

        assertTrue(
            NetworkRuleInputParser.parse(
                action = FirewallAction.BLOCK,
                destinationInput = "",
                protocol = TransportProtocol.ANY,
                portInput = "",
            ) is NetworkRuleParseResult.Invalid,
        )
        assertTrue(
            NetworkRuleInputParser.parse(
                action = FirewallAction.BLOCK,
                destinationInput = "dns.google",
                protocol = TransportProtocol.TCP,
                portInput = "443",
            ) is NetworkRuleParseResult.Invalid,
        )
        assertTrue(
            NetworkRuleInputParser.parse(
                action = FirewallAction.BLOCK,
                destinationInput = "8.8.8.8",
                protocol = TransportProtocol.TCP,
                portInput = "70000",
            ) is NetworkRuleParseResult.Invalid,
        )
    }

    @Test
    fun `state holder coordinates apps, network rules, search, settings, and traffic logs`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val holderScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + dispatcher)
        val repository = FirewallRepository(
            store = InMemoryFirewallLocalStore(),
            currentTimeMillis = { 100_000L },
        )
        val appsProvider = InstalledAppsProvider(
            scanner = InstalledPackageScanner {
                listOf(
                    RawInstalledPackage(
                        uid = 10101,
                        packageName = "org.example.chat",
                        label = "Signal Chat",
                        isSystemApp = false,
                        hasInternetPermission = true,
                    ),
                    RawInstalledPackage(
                        uid = 10020,
                        packageName = "com.android.shell",
                        label = "Android Shell",
                        isSystemApp = true,
                        hasInternetPermission = true,
                    ),
                )
            },
        )

        try {
            val holder = FirewallStateHolder(
                scope = holderScope,
                repository = repository,
                installedAppsProvider = appsProvider,
                ioDispatcher = dispatcher,
            )
            advanceUntilIdle()

            // Default settings exclude system apps.
            assertEquals(1, holder.uiState.value.apps.size)
            val chatApp = holder.uiState.value.apps.single().app
            assertEquals("Signal Chat", chatApp.appName)

            // Blocking app updates blockedAppCount and app item state.
            holder.setAppAction(chatApp, FirewallAction.BLOCK)
            advanceUntilIdle()
            assertEquals(1, holder.uiState.value.blockedAppCount)
            assertEquals(FirewallAction.BLOCK, holder.uiState.value.apps.single().action)

            // Enabling system apps reveals Android Shell, and search narrows results.
            holder.setIncludeSystemApps(true)
            advanceUntilIdle()
            assertEquals(2, holder.uiState.value.apps.size)

            holder.updateAppSearchQuery("shell")
            advanceUntilIdle()
            assertEquals(1, holder.uiState.value.apps.size)
            assertEquals("com.android.shell", holder.uiState.value.apps.single().app.packageName)

            // Invalid network rule sets error; valid rule clears error and persists.
            assertFalse(holder.addNetworkRule(FirewallAction.BLOCK, "", TransportProtocol.ANY, ""))
            advanceUntilIdle()
            assertNotNull(holder.uiState.value.ruleInputError)

            assertTrue(holder.addNetworkRule(FirewallAction.BLOCK, "8.8.8.8", TransportProtocol.TCP, "443"))
            advanceUntilIdle()
            assertNull(holder.uiState.value.ruleInputError)
            assertEquals(1, holder.uiState.value.networkRules.size)

            // Traffic logs display and clear cleanly.
            repository.recordTrafficLog(
                TrafficLogEntry(
                    timestampMillis = 123_456L,
                    uid = 10101,
                    applicationName = "Signal Chat",
                    packageName = "org.example.chat",
                    protocol = TransportProtocol.TCP,
                    sourceAddress = "10.0.0.2",
                    destinationAddress = "8.8.8.8",
                    sourcePort = 50000,
                    destinationPort = 443,
                    action = FirewallAction.BLOCK,
                ),
            )
            advanceUntilIdle()
            assertEquals(1, holder.uiState.value.trafficLogs.size)

            holder.clearTrafficLogs()
            advanceUntilIdle()
            assertEquals(0, holder.uiState.value.trafficLogs.size)
        } finally {
            holderScope.cancel()
        }
    }
}
