package com.localfirewall.app.firewall

import android.os.Process
import android.system.OsConstants
import com.localfirewall.app.network.FlowKey
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ConnectionOwnerResolverTest {
    @Test
    fun `TCP UID is found with source and destination endpoints`() {
        val resolver = ConnectionOwnerResolver { protocol, local, remote ->
            assertEquals(OsConstants.IPPROTO_TCP, protocol)
            assertEquals(InetSocketAddress(address("10.0.0.2"), 43210), local)
            assertEquals(InetSocketAddress(address("93.184.216.34"), 443), remote)
            10042
        }

        assertEquals(10042, resolver.resolve(packet(TransportProtocol.TCP)))
    }

    @Test
    fun `UDP UID is found`() {
        val resolver = ConnectionOwnerResolver { protocol, _, _ ->
            assertEquals(OsConstants.IPPROTO_UDP, protocol)
            10043
        }

        assertEquals(10043, resolver.resolve(packet(TransportProtocol.UDP)))
    }

    @Test
    fun `invalid UID is unknown`() {
        val resolver = ConnectionOwnerResolver { _, _, _ -> Process.INVALID_UID }

        assertNull(resolver.resolve(packet()))
    }

    @Test
    fun `unsupported protocol and missing ports skip lookup`() {
        val calls = AtomicInteger()
        val resolver = ConnectionOwnerResolver { _, _, _ -> calls.incrementAndGet() }

        assertNull(resolver.resolve(packet(protocol = TransportProtocol.ANY)))
        assertNull(resolver.resolve(packet().copy(sourcePort = null)))
        assertNull(resolver.resolve(packet().copy(destinationPort = null)))
        assertEquals(0, calls.get())
    }

    @Test
    fun `non-first fragment skips lookup`() {
        val calls = AtomicInteger()
        val resolver = ConnectionOwnerResolver { _, _, _ -> calls.incrementAndGet() }

        assertNull(resolver.resolve(packet().copy(fragmentOffset = 1)))
        assertEquals(0, calls.get())
    }

    @Test
    fun `platform lookup failures are unknown`() {
        val securityFailure = ConnectionOwnerResolver { _, _, _ -> throw SecurityException() }
        val argumentFailure = ConnectionOwnerResolver { _, _, _ -> throw IllegalArgumentException() }

        assertNull(securityFailure.resolve(packet()))
        assertNull(argumentFailure.resolve(packet()))
    }

    @Test
    fun `resolved flow is served from cache`() {
        val calls = AtomicInteger()
        val resolver = ConnectionOwnerResolver { _, _, _ ->
            calls.incrementAndGet()
            10044
        }

        assertEquals(10044, resolver.resolve(packet()))
        assertEquals(10044, resolver.resolve(packet()))
        assertEquals(1, calls.get())
    }

    @Test
    fun `bounded cache evicts least recently used flow`() {
        val cache = BoundedFlowUidCache(maximumSize = 2)
        val first = flow(1)
        val second = flow(2)
        val third = flow(3)
        cache.put(first, 1)
        cache.put(second, 2)
        assertEquals(1, cache.get(first)) // Make second the least recently used.

        cache.put(third, 3)

        assertNull(cache.get(second))
        assertEquals(1, cache.get(first))
        assertEquals(3, cache.get(third))
    }

    private fun packet(protocol: TransportProtocol = TransportProtocol.TCP) = PacketMetadata(
        sourceAddress = address("10.0.0.2"),
        destinationAddress = address("93.184.216.34"),
        protocol = protocol,
        sourcePort = 43210,
        destinationPort = 443,
        identification = 1,
        fragmentOffset = 0,
        moreFragments = false,
    )

    private fun flow(port: Int) = FlowKey(
        protocol = TransportProtocol.TCP,
        sourceAddress = address("10.0.0.2"),
        sourcePort = port,
        destinationAddress = address("93.184.216.34"),
        destinationPort = 443,
    )

    private fun address(value: String): InetAddress = InetAddress.getByName(value)
}
