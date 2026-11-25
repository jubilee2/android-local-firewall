package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.Inet4Address
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RuleEngineTest {
    @Test
    fun `unknown UID does not affect rule evaluation`() {
        val engine = RuleEngine(emptyList(), defaultAction = FirewallAction.ALLOW)

        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet().copy(uid = null)))
    }

    @Test
    fun `fail closed on unknown UID blocks unattributed packet even when allow rule exists`() {
        val engine = RuleEngine(
            rules = listOf(FirewallRule(FirewallAction.ALLOW, protocol = TransportProtocol.UDP, destinationPort = 53)),
            defaultAction = FirewallAction.ALLOW,
            failClosedOnUnknownUid = true,
        )

        assertEquals(
            FirewallAction.BLOCK,
            engine.evaluate(packet(protocol = TransportProtocol.UDP, port = 53, uid = null)),
        )
        assertEquals(
            FirewallAction.ALLOW,
            engine.evaluate(packet(protocol = TransportProtocol.UDP, port = 53, uid = 10100)),
        )
    }

    @Test
    fun `negative UID is rejected by FirewallRule`() {
        assertThrows(IllegalArgumentException::class.java) {
            FirewallRule(action = FirewallAction.BLOCK, uid = -1)
        }
    }

    @Test
    fun `per-app UID rule matches only target UID and ignores unknown or other UIDs`() {
        val engine = RuleEngine(
            listOf(FirewallRule(action = FirewallAction.BLOCK, uid = 10234)),
        )

        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet(uid = 10234)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet(uid = 10235)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet(uid = null)))
    }

    @Test
    fun `combined UID and destination port rule requires both to match`() {
        val engine = RuleEngine(
            listOf(
                FirewallRule(
                    action = FirewallAction.BLOCK,
                    protocol = TransportProtocol.TCP,
                    destinationPort = 443,
                    uid = 10234,
                ),
            ),
        )

        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet(protocol = TransportProtocol.TCP, port = 443, uid = 10234)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet(protocol = TransportProtocol.TCP, port = 443, uid = 10999)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet(protocol = TransportProtocol.TCP, port = 80, uid = 10234)))
    }

    @Test
    fun `default policy allows packet`() {
        assertEquals(FirewallAction.ALLOW, RuleEngine(emptyList()).evaluate(packet()))
    }

    @Test
    fun `exact destination address blocks`() {
        val rule = FirewallRule(FirewallAction.BLOCK, destinationAddress = ipv4("8.8.8.8"))
        assertEquals(FirewallAction.BLOCK, RuleEngine(listOf(rule)).evaluate(packet("8.8.8.8")))
    }

    @Test
    fun `CIDR blocks address in subnet but not address outside it`() {
        val engine = RuleEngine(
            listOf(FirewallRule(FirewallAction.BLOCK, destinationCidr = IPv4Cidr.parse("192.168.0.0/16"))),
        )

        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet("192.168.4.2")))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet("192.169.4.2")))
    }

    @Test
    fun `TCP destination port rule only matches TCP`() {
        val engine = RuleEngine(listOf(portRule(TransportProtocol.TCP, 443)))

        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet(protocol = TransportProtocol.TCP, port = 443)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet(protocol = TransportProtocol.UDP, port = 443)))
    }

    @Test
    fun `UDP destination port rule matches UDP`() {
        val engine = RuleEngine(listOf(portRule(TransportProtocol.UDP, 53)))
        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet(protocol = TransportProtocol.UDP, port = 53)))
    }

    @Test
    fun `combined rule requires destination protocol and port`() {
        val rule = FirewallRule(
            action = FirewallAction.BLOCK,
            destinationCidr = IPv4Cidr.parse("203.0.113.0/24"),
            protocol = TransportProtocol.TCP,
            destinationPort = 443,
        )
        val engine = RuleEngine(listOf(rule))

        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet("203.0.113.5", TransportProtocol.TCP, 443)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet("203.0.114.5", TransportProtocol.TCP, 443)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packet("203.0.113.5", TransportProtocol.TCP, 80)))
    }

    @Test
    fun `first matching rule wins`() {
        val rules = listOf(
            FirewallRule(FirewallAction.ALLOW, protocol = TransportProtocol.UDP, destinationPort = 53),
            FirewallRule(FirewallAction.BLOCK, destinationPort = 53),
        )
        assertEquals(
            FirewallAction.ALLOW,
            RuleEngine(rules).evaluate(packet(protocol = TransportProtocol.UDP, port = 53)),
        )
    }

    @Test
    fun `missing transport port cannot match port rule`() {
        val engine = RuleEngine(listOf(portRule(TransportProtocol.TCP, 443)))
        assertEquals(
            FirewallAction.ALLOW,
            engine.evaluate(packet(protocol = TransportProtocol.TCP, port = null)),
        )
    }

    @Test
    fun `non-first fragment without ports can still match IP-only rule`() {
        val engine = RuleEngine(
            listOf(FirewallRule(FirewallAction.BLOCK, destinationCidr = IPv4Cidr.parse("198.51.100.0/24"))),
        )
        assertEquals(FirewallAction.BLOCK, engine.evaluate(packet(port = null)))
    }

    private fun portRule(protocol: TransportProtocol, port: Int) = FirewallRule(
        action = FirewallAction.BLOCK,
        protocol = protocol,
        destinationPort = port,
    )

    private fun packet(
        destination: String = "198.51.100.2",
        protocol: TransportProtocol = TransportProtocol.TCP,
        port: Int? = 80,
        uid: Int? = null,
    ) = PacketMetadata(
        sourceAddress = InetAddress.getByName("192.0.2.1"),
        destinationAddress = InetAddress.getByName(destination),
        protocol = protocol,
        sourcePort = if (port == null) null else 12345,
        destinationPort = port,
        identification = 1,
        fragmentOffset = 0,
        moreFragments = false,
        uid = uid,
    )

    private fun ipv4(value: String): Inet4Address = InetAddress.getByName(value) as Inet4Address
}
