package com.localfirewall.app.vpn

import com.localfirewall.app.network.PacketForwarder
import java.io.Closeable
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallVpnSessionOrchestratorTest {
    @Test
    fun `vpn route configuration installs IPv4 default route without bypass or uncaptured IPv6`() {
        assertEquals(1500, FirewallVpnService.VPN_MTU)
        assertEquals("10.0.0.2", FirewallVpnService.VPN_ADDRESS)
        assertEquals(32, FirewallVpnService.VPN_PREFIX_LENGTH)
        assertEquals("0.0.0.0", FirewallVpnService.IPV4_DEFAULT_ROUTE_ADDRESS)
        assertEquals(0, FirewallVpnService.IPV4_DEFAULT_ROUTE_PREFIX)

        val serviceSource = sequenceOf(
            File("src/main/java/com/localfirewall/app/vpn/FirewallVpnService.kt"),
            File("app/src/main/java/com/localfirewall/app/vpn/FirewallVpnService.kt"),
        ).first(File::isFile).readText()
        // Extract non-comment code lines to verify forbidden VpnService.Builder calls are absent.
        val codeLines = serviceSource.lines()
            .map { it.trim() }
            .filterNot { it.startsWith("//") || it.startsWith("*") || it.startsWith("/*") }
            .joinToString("\n")
        assertFalse(codeLines.contains("allowBypass"))
        assertFalse(codeLines.contains("addDisallowedApplication"))
        assertFalse(codeLines.contains("allowFamily"))
        assertTrue(codeLines.contains(".addRoute(IPV4_DEFAULT_ROUTE_ADDRESS, IPV4_DEFAULT_ROUTE_PREFIX)"))
    }

    @Test
    fun `starts session idempotently and stops forwarder before closing coordinator monitor and tun`() {
        val events = mutableListOf<String>()
        val stateTransitions = mutableListOf<Boolean>()
        var forwarderCreations = 0

        val orchestrator = FirewallVpnSessionOrchestrator(
            establishTun = {
                events += "tun:establish"
                Closeable { events += "tun:close" }
            },
            startDecisionCoordinator = {
                events += "coordinator:start"
                Closeable { events += "coordinator:close" }
            },
            startNetworkMonitor = {
                events += "monitor:start"
                Closeable { events += "monitor:close" }
            },
            createForwarder = { _, _ ->
                forwarderCreations++
                object : PacketForwarder {
                    override fun start() {
                        events += "forwarder:start"
                    }

                    override fun stop() {
                        events += "forwarder:stop"
                    }
                }
            },
            onStartedChanged = { stateTransitions += it },
        )

        assertTrue(orchestrator.startSession())
        // Repeated start while active reuses existing TUN, coordinator, forwarder, and monitor.
        assertTrue(orchestrator.startSession())
        assertEquals(1, forwarderCreations)
        assertEquals(
            listOf("tun:establish", "coordinator:start", "forwarder:start", "monitor:start"),
            events,
        )

        orchestrator.stopSession()
        // Repeated stop is idempotent.
        orchestrator.stopSession()

        assertEquals(
            listOf(
                "tun:establish",
                "coordinator:start",
                "forwarder:start",
                "monitor:start",
                "forwarder:stop",
                "coordinator:close",
                "monitor:close",
                "tun:close",
            ),
            events,
        )
        assertEquals(listOf(true, true, false, false), stateTransitions)
    }

    @Test
    fun `null tun handle tears down cleanly without starting coordinator or forwarder`() {
        val events = mutableListOf<String>()
        var startedState = true

        val orchestrator = FirewallVpnSessionOrchestrator<Closeable, Closeable>(
            establishTun = { null },
            startDecisionCoordinator = {
                events += "coordinator:start"
                Closeable {}
            },
            startNetworkMonitor = {
                events += "monitor:start"
                Closeable {}
            },
            createForwarder = { _, _ ->
                events += "forwarder:create"
                object : PacketForwarder {
                    override fun start() = Unit
                    override fun stop() = Unit
                }
            },
            onStartedChanged = { startedState = it },
        )

        assertFalse(orchestrator.startSession())
        assertTrue(events.isEmpty())
        assertFalse(startedState)
    }

    @Test
    fun `forwarder startup failure rolls back forwarder and closes tun capture route fail-closed`() {
        val events = mutableListOf<String>()
        val stateTransitions = mutableListOf<Boolean>()

        val orchestrator = FirewallVpnSessionOrchestrator(
            establishTun = {
                events += "tun:establish"
                Closeable { events += "tun:close" }
            },
            startDecisionCoordinator = {
                events += "coordinator:start"
                Closeable { events += "coordinator:close" }
            },
            startNetworkMonitor = {
                events += "monitor:start"
                Closeable { events += "monitor:close" }
            },
            createForwarder = { _, _ ->
                object : PacketForwarder {
                    override fun start() {
                        events += "forwarder:start-failed"
                        throw IllegalStateException("JNI pin mismatch")
                    }

                    override fun stop() {
                        events += "forwarder:rollback-stop"
                    }
                }
            },
            onStartedChanged = { stateTransitions += it },
        )

        assertFalse(orchestrator.startSession())
        assertEquals(
            listOf(
                "tun:establish",
                "coordinator:start",
                "forwarder:start-failed",
                "forwarder:rollback-stop",
                "coordinator:close",
                "tun:close",
            ),
            events,
        )
        assertEquals(listOf(false), stateTransitions)
    }

    @Test
    fun `failed forwarder cleanup still releases tun route and blocks replacement forwarder until cleanup succeeds`() {
        val events = mutableListOf<String>()
        var failStop = true
        var createdForwarders = 0

        val orchestrator = FirewallVpnSessionOrchestrator(
            establishTun = {
                events += "tun:establish"
                Closeable { events += "tun:close" }
            },
            startDecisionCoordinator = {
                events += "coordinator:start"
                Closeable { events += "coordinator:close" }
            },
            startNetworkMonitor = { null },
            createForwarder = { _, _ ->
                createdForwarders++
                val id = createdForwarders
                object : PacketForwarder {
                    override fun start() {
                        events += "forwarder#$id:start"
                    }

                    override fun stop() {
                        if (failStop) {
                            events += "forwarder#$id:stop-failed"
                            throw IllegalStateException("worker join timed out")
                        }
                        events += "forwarder#$id:stop-ok"
                    }
                }
            },
            onStartedChanged = {},
        )

        assertTrue(orchestrator.startSession())
        // Stop fails inside forwarder#1, retaining CleanupPending, yet TUN route is still closed.
        orchestrator.stopSession()
        assertTrue("tun:close" in events)

        // While CleanupPending is retained and stop still fails, a new startSession fails closed
        // without instantiating forwarder#2.
        assertFalse(orchestrator.startSession())
        assertEquals(1, createdForwarders)

        // Once cleanup succeeds on stopSession, a fresh session can start cleanly.
        failStop = false
        orchestrator.stopSession()
        assertTrue(orchestrator.startSession())
        assertEquals(2, createdForwarders)
        orchestrator.stopSession()
    }
}
