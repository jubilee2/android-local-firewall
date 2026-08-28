package com.localfirewall.app.firewall

import java.net.InetAddress
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IPv4CidrTest {
    @Test
    fun `zero prefix matches every IPv4 address`() {
        val cidr = IPv4Cidr.parse("0.0.0.0/0")

        assertTrue(cidr.contains(InetAddress.getByName("0.0.0.0")))
        assertTrue(cidr.contains(InetAddress.getByName("8.8.8.8")))
        assertTrue(cidr.contains(InetAddress.getByName("255.255.255.255")))
    }

    @Test
    fun `thirty-two prefix matches only its exact IPv4 address`() {
        val cidr = IPv4Cidr.parse("203.0.113.7/32")

        assertTrue(cidr.contains(InetAddress.getByName("203.0.113.7")))
        assertFalse(cidr.contains(InetAddress.getByName("203.0.113.8")))
    }
}
