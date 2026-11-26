package com.localfirewall.app.firewall

import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.data.local.toEntity
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import com.localfirewall.app.ui.NetworkRuleInputParser
import com.localfirewall.app.ui.NetworkRuleParseResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IPv6CidrTest {
    @Test
    fun `matches prefix boundary masks across 0 32 64 65 127 and 128`() {
        val all = IPv6Cidr.parse("::/0")
        assertTrue(all.contains(IPv6Cidr.parseAddress("::")))
        assertTrue(all.contains(IPv6Cidr.parseAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))

        val slash32 = IPv6Cidr.parse("2001:db8:abcd::1/32")
        assertEquals("2001:db8::/32", slash32.format())
        assertTrue(slash32.contains(IPv6Cidr.parseAddress("2001:db8:ffff::99")))
        assertFalse(slash32.contains(IPv6Cidr.parseAddress("2001:db9::1")))

        val slash64 = IPv6Cidr.parse("2001:db8:1:2:ffff:ffff:ffff:ffff/64")
        assertEquals("2001:db8:1:2::/64", slash64.format())
        assertTrue(slash64.contains(IPv6Cidr.parseAddress("2001:db8:1:2::1")))
        assertFalse(slash64.contains(IPv6Cidr.parseAddress("2001:db8:1:3::1")))

        val slash65 = IPv6Cidr.parse("2001:db8:1:2:8000::/65")
        assertTrue(slash65.contains(IPv6Cidr.parseAddress("2001:db8:1:2:ffff::1")))
        assertFalse(slash65.contains(IPv6Cidr.parseAddress("2001:db8:1:2:7fff::1")))

        val slash127 = IPv6Cidr.parse("2001:db8::fe/127")
        assertTrue(slash127.contains(IPv6Cidr.parseAddress("2001:db8::ff")))
        assertFalse(slash127.contains(IPv6Cidr.parseAddress("2001:db8::fc")))

        val slash128 = IPv6Cidr.parse("2001:4860:4860::8888/128")
        assertTrue(slash128.contains(IPv6Cidr.parseAddress("2001:4860:4860:0:0:0:0:8888")))
        assertFalse(slash128.contains(IPv6Cidr.parseAddress("2001:4860:4860::8844")))
    }

    @Test
    fun `parses embedded IPv4 and rejects hostnames zone IDs and malformed literals without DNS`() {
        val mapped = IPv6Cidr.parseAddress("::ffff:192.0.2.128")
        assertEquals(16, mapped.address.size)

        listOf(
            "dns.google",
            "fe80::1%wlan0",
            "2001:::1",
            ":2001:db8::1",
            "2001:db8::1:",
            "2001:db8::1::2",
            "2001:db8:1:2:3:4:5:6:7",
            "2001:db8:1:2:3",
            "2001:db8::12345",
            "2001:db8::zzzz",
        ).forEach { invalid ->
            assertThrows("Expected failure for $invalid", IllegalArgumentException::class.java) {
                IPv6Cidr.parseAddress(invalid)
            }
        }
    }

    @Test
    fun `RuleEngine Room entity and NetworkRuleInputParser evaluate and round-trip IPv6 rules`() {
        val parsedRule = NetworkRuleInputParser.parse(
            action = FirewallAction.BLOCK,
            destinationInput = "2001:db8:42::/48",
            protocol = TransportProtocol.TCP,
            portInput = "443",
        ) as NetworkRuleParseResult.Valid

        val roundTripped: StoredNetworkRule = parsedRule.rule.toEntity().toDomain()
        assertEquals("2001:db8:42::/48", roundTripped.destinationIpv6Cidr?.format())

        val engine = RuleEngine(listOf(roundTripped.toFirewallRule()))
        val matchingPacket = PacketMetadata(
            sourceAddress = IPv6Cidr.parseAddress("2001:db8:1::10"),
            destinationAddress = IPv6Cidr.parseAddress("2001:db8:42:99::1"),
            protocol = TransportProtocol.TCP,
            sourcePort = 51000,
            destinationPort = 443,
            identification = 0,
            fragmentOffset = 0,
            moreFragments = false,
            uid = 10200,
        )
        val nonMatchingPacket = matchingPacket.copy(
            destinationAddress = IPv6Cidr.parseAddress("2001:db8:43::1"),
        )

        assertEquals(FirewallAction.BLOCK, engine.evaluate(matchingPacket))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(nonMatchingPacket))
    }
}
