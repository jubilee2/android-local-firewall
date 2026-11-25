package com.localfirewall.app.firewall

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
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

    @Test
    fun `format outputs canonical masked network and round trips cleanly`() {
        val cidr = IPv4Cidr.parse("192.168.42.9/16")

        assertEquals("192.168.0.0/16", cidr.format())
        assertEquals(cidr, IPv4Cidr.parse(cidr.format()))
    }

    @Test
    fun `parseAddress rejects hostnames and leading zeros without DNS lookup`() {
        assertEquals("8.8.8.8", IPv4Cidr.parseAddress("8.8.8.8").hostAddress)
        assertThrows(IllegalArgumentException::class.java) {
            IPv4Cidr.parseAddress("example.com")
        }
        assertThrows(IllegalArgumentException::class.java) {
            IPv4Cidr.parseAddress("01.2.3.4")
        }
    }
}
