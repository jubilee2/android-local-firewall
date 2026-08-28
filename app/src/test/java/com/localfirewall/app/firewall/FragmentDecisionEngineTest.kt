package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test

class FragmentDecisionEngineTest {
    @Test
    fun `blocked TCP first fragment blocks later fragments`() {
        val engine = engine(FirewallAction.BLOCK, TransportProtocol.TCP, 443)

        assertEquals(FirewallAction.BLOCK, engine.evaluate(firstFragment(TransportProtocol.TCP, 443)))
        assertEquals(FirewallAction.BLOCK, engine.evaluate(laterFragment(TransportProtocol.TCP)))
    }

    @Test
    fun `allowed TCP first fragment allows later fragments`() {
        val engine = engine(FirewallAction.ALLOW, TransportProtocol.TCP, 443, default = FirewallAction.BLOCK)

        assertEquals(FirewallAction.ALLOW, engine.evaluate(firstFragment(TransportProtocol.TCP, 443)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(laterFragment(TransportProtocol.TCP)))
    }

    @Test
    fun `UDP fragments reuse first fragment decision`() {
        val engine = engine(FirewallAction.BLOCK, TransportProtocol.UDP, 53)

        assertEquals(FirewallAction.BLOCK, engine.evaluate(firstFragment(TransportProtocol.UDP, 53)))
        assertEquals(FirewallAction.BLOCK, engine.evaluate(laterFragment(TransportProtocol.UDP)))
    }

    @Test
    fun `unrelated fragment identifications do not share decisions`() {
        val engine = engine(FirewallAction.BLOCK, TransportProtocol.TCP, 443)
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443, identification = 10))

        assertEquals(
            FirewallAction.ALLOW,
            engine.evaluate(laterFragment(TransportProtocol.TCP, identification = 11)),
        )
    }

    @Test
    fun `expired entry uses deterministic normal-evaluation fallback`() {
        var now = 1_000L
        val ruleEngine = RuleEngine(
            listOf(FirewallRule(FirewallAction.BLOCK, protocol = TransportProtocol.TCP, destinationPort = 443)),
        )
        val engine = FragmentDecisionEngine(
            ruleEngine = ruleEngine,
            entryLifetimeMillis = 100,
            elapsedRealtimeMillis = { now },
        )
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443))
        now += 100

        // Normal evaluation cannot match the port rule because a later fragment has no ports.
        assertEquals(FirewallAction.ALLOW, engine.evaluate(laterFragment(TransportProtocol.TCP)))
    }

    @Test
    fun `unknown fragment still applies IP-only rules`() {
        val ruleEngine = RuleEngine(
            listOf(
                FirewallRule(
                    action = FirewallAction.BLOCK,
                    destinationCidr = IPv4Cidr.parse("198.51.100.0/24"),
                ),
            ),
        )

        assertEquals(
            FirewallAction.BLOCK,
            FragmentDecisionEngine(ruleEngine).evaluate(laterFragment(TransportProtocol.UDP)),
        )
    }

    @Test
    fun `cache remains bounded and evicts oldest decision`() {
        val engine = FragmentDecisionEngine(
            ruleEngine = RuleEngine(emptyList()),
            maxEntries = 2,
        )
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443, identification = 1))
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443, identification = 2))
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443, identification = 3))

        assertEquals(2, engine.cachedDecisionCount())
    }

    @Test
    fun `shutdown clears fragment decisions`() {
        val engine = engine(FirewallAction.BLOCK, TransportProtocol.TCP, 443)
        engine.evaluate(firstFragment(TransportProtocol.TCP, 443))

        engine.close()

        assertEquals(0, engine.cachedDecisionCount())
        assertEquals(FirewallAction.ALLOW, engine.evaluate(laterFragment(TransportProtocol.TCP)))
    }

    private fun engine(
        action: FirewallAction,
        protocol: TransportProtocol,
        port: Int,
        default: FirewallAction = FirewallAction.ALLOW,
    ) = FragmentDecisionEngine(
        RuleEngine(
            rules = listOf(FirewallRule(action, protocol = protocol, destinationPort = port)),
            defaultAction = default,
        ),
    )

    private fun firstFragment(
        protocol: TransportProtocol,
        port: Int,
        identification: Int = 7,
    ) = packet(protocol, port, identification, fragmentOffset = 0, moreFragments = true)

    private fun laterFragment(
        protocol: TransportProtocol,
        identification: Int = 7,
    ) = packet(protocol, null, identification, fragmentOffset = 1, moreFragments = false)

    private fun packet(
        protocol: TransportProtocol,
        destinationPort: Int?,
        identification: Int,
        fragmentOffset: Int,
        moreFragments: Boolean,
    ) = PacketMetadata(
        sourceAddress = InetAddress.getByName("192.0.2.1"),
        destinationAddress = InetAddress.getByName("198.51.100.2"),
        protocol = protocol,
        sourcePort = destinationPort?.let { 12345 },
        destinationPort = destinationPort,
        identification = identification,
        fragmentOffset = fragmentOffset,
        moreFragments = moreFragments,
    )
}
