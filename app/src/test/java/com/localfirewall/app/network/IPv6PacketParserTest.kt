package com.localfirewall.app.network

import com.localfirewall.app.firewall.ConnectionOwnerLookup
import com.localfirewall.app.firewall.ConnectionOwnerResolver
import com.localfirewall.app.vpn.PacketProcessor
import com.localfirewall.app.vpn.PacketSource
import java.net.Inet6Address
import java.net.InetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
class IPv6PacketParserTest {
    @Test
    fun `parses IPv6 TCP packet and transport ports`() {
        val tcpHeader = ByteArray(20).apply {
            this[0] = 0xc3.toByte()
            this[1] = 0x50.toByte() // source port 50000
            this[2] = 0x01.toByte()
            this[3] = 0xbb.toByte() // dest port 443
            this[12] = 0x50.toByte() // data offset 5 (20 bytes)
            this[13] = 0x02.toByte() // SYN
        }
        val packet = buildIpv6Packet(
            nextHeader = 6,
            payload = tcpHeader,
        )

        val ipv6 = requireNotNull(IPv6PacketParser.parse(packet))
        assertEquals(6, ipv6.version)
        assertEquals(40, ipv6.transportOffset)
        assertEquals(60, ipv6.totalLength)
        assertEquals(6, ipv6.protocol)
        assertFalse(ipv6.isFragmented)
        assertTrue(ipv6.canParseTransportHeader)

        val tcp = requireNotNull(TcpPacketParser.parse(packet))
        assertEquals(50000, tcp.sourcePort)
        assertEquals(443, tcp.destinationPort)
        assertTrue(tcp.syn)
    }

    @Test
    fun `skips HopByHop and DestinationOptions headers before UDP header`() {
        // Hop-by-Hop (8 bytes) -> Destination Options (8 bytes) -> UDP (8 bytes)
        val hopByHop = ByteArray(8).apply {
            this[0] = 60 // next header = Destination Options
            this[1] = 0 // hdrExtLen = 0 -> 8 bytes
        }
        val destinationOpts = ByteArray(8).apply {
            this[0] = 17 // next header = UDP
            this[1] = 0 // hdrExtLen = 0 -> 8 bytes
        }
        val udpHeader = ByteArray(8).apply {
            this[0] = 0xd0.toByte()
            this[1] = 0x01.toByte() // source port 53249
            this[2] = 0x00.toByte()
            this[3] = 0x35.toByte() // dest port 53
            this[4] = 0x00.toByte()
            this[5] = 0x08.toByte() // length 8
        }
        val packet = buildIpv6Packet(
            nextHeader = 0,
            payload = hopByHop + destinationOpts + udpHeader,
        )

        val ipv6 = requireNotNull(IPv6PacketParser.parse(packet))
        assertEquals(56, ipv6.transportOffset)
        assertEquals(17, ipv6.protocol)

        val udp = requireNotNull(UdpPacketParser.parse(packet))
        assertEquals(53249, udp.sourcePort)
        assertEquals(53, udp.destinationPort)
    }

    @Test
    fun `parses IPv6 fragment header for initial and non-initial fragments`() {
        val udpHeader = ByteArray(8).apply {
            this[0] = 0xc0.toByte()
            this[1] = 0x00.toByte()
            this[2] = 0x00.toByte()
            this[3] = 0x35.toByte()
            this[4] = 0x00.toByte()
            this[5] = 0x20.toByte() // total UDP datagram length 32 across fragments
        }
        val firstFragmentHeader = byteArrayOf(
            17, // next header = UDP
            0, // reserved
            0x00,
            0x01, // offset = 0, M = 1
            0x12,
            0x34,
            0x56,
            0x78, // identification
        )
        val firstPacket = buildIpv6Packet(
            nextHeader = 44,
            payload = firstFragmentHeader + udpHeader,
        )
        val parsedFirst = requireNotNull(IPv6PacketParser.parse(firstPacket))
        assertEquals(0, parsedFirst.fragmentOffset)
        assertTrue(parsedFirst.moreFragments)
        assertEquals(0x12345678, parsedFirst.identification)
        assertNotNull(UdpPacketParser.parse(firstPacket, parsedFirst))

        val secondFragmentHeader = byteArrayOf(
            17,
            0,
            0x00,
            0x08, // offset = 1 (in 8-byte units), M = 0
            0x12,
            0x34,
            0x56,
            0x78,
        )
        val secondPacket = buildIpv6Packet(
            nextHeader = 44,
            payload = secondFragmentHeader + ByteArray(8),
        )
        val parsedSecond = requireNotNull(IPv6PacketParser.parse(secondPacket))
        assertEquals(1, parsedSecond.fragmentOffset)
        assertFalse(parsedSecond.moreFragments)
        assertFalse(parsedSecond.canParseTransportHeader)
        assertNull(UdpPacketParser.parse(secondPacket, parsedSecond))
    }

    @Test
    fun `rejects truncated payloads duplicate fragment headers and excessive extension chains`() {
        assertNull(IPv6PacketParser.parse(ByteArray(39)))

        // Declared payload length 20 with only 8 bytes present.
        val truncated = buildIpv6Packet(nextHeader = 17, payload = ByteArray(8)).apply {
            this[4] = 0x00
            this[5] = 0x14
        }
        assertNull(IPv6PacketParser.parse(truncated))

        // Duplicate Fragment Headers must be rejected.
        val dupFrag = byteArrayOf(44, 0, 0, 1, 0, 0, 0, 1) + byteArrayOf(17, 0, 0, 0, 0, 0, 0, 1)
        assertNull(IPv6PacketParser.parse(buildIpv6Packet(nextHeader = 44, payload = dupFrag)))

        // 9 Hop-by-Hop headers exceed MAX_EXTENSION_HEADERS (8).
        val chain = ByteArray(9 * 8)
        for (i in 0 until 8) {
            chain[i * 8] = 0 // Hop-by-Hop
        }
        chain[8 * 8] = 17 // UDP
        assertNull(IPv6PacketParser.parse(buildIpv6Packet(nextHeader = 0, payload = chain + ByteArray(8))))
    }

    @Test
    fun `PacketProcessor extracts IPv6 metadata and resolves connection owner UID`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val udpHeader = ByteArray(8).apply {
            this[0] = 0xc3.toByte()
            this[1] = 0x50.toByte() // 50000
            this[2] = 0x00.toByte()
            this[3] = 0x35.toByte() // 53
            this[4] = 0x00.toByte()
            this[5] = 0x08.toByte()
        }
        val rawPacket = buildIpv6Packet(nextHeader = 17, payload = udpHeader)
        val captured = ArrayList<PacketMetadata>()
        var emitted = false

        val processor = PacketProcessor(
            source = PacketSource { buffer ->
                if (!emitted) {
                    emitted = true
                    rawPacket.copyInto(buffer)
                    rawPacket.size
                } else {
                    -1
                }
            },
            metadataHandler = captured::add,
            connectionOwnerResolver = ConnectionOwnerResolver(
                lookup = ConnectionOwnerLookup { _, _, _ -> 10777 },
            ),
            dispatcher = dispatcher,
        )

        processor.start()
        advanceUntilIdle()
        processor.close()

        assertEquals(1, captured.size)
        val metadata = captured.single()
        assertTrue(metadata.destinationAddress is Inet6Address)
        assertEquals(TransportProtocol.UDP, metadata.protocol)
        assertEquals(50000, metadata.sourcePort)
        assertEquals(53, metadata.destinationPort)
        assertEquals(10777, metadata.uid)
    }

    private fun buildIpv6Packet(
        nextHeader: Int,
        payload: ByteArray,
    ): ByteArray {
        val source = InetAddress.getByName("2001:db8::1").address
        val destination = InetAddress.getByName("2001:4860:4860::8888").address
        return ByteArray(40 + payload.size).apply {
            this[0] = 0x60.toByte() // version 6
            this[4] = ((payload.size ushr 8) and 0xff).toByte()
            this[5] = (payload.size and 0xff).toByte()
            this[6] = (nextHeader and 0xff).toByte()
            this[7] = 64 // hop limit
            source.copyInto(this, destinationOffset = 8)
            destination.copyInto(this, destinationOffset = 24)
            payload.copyInto(this, destinationOffset = 40)
        }
    }
}
