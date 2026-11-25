package com.localfirewall.app.network

/** Extracts metadata from a UDP header carried by an IPv4 or IPv6 packet. */
object UdpPacketParser {
    private const val UDP_PROTOCOL = 17
    private const val HEADER_LENGTH = 8

    /** Parses the IPv4 or IPv6 header before extracting UDP metadata. */
    fun parse(packet: ByteArray): UdpMetadata? {
        if (packet.isEmpty()) return null
        return when ((packet[0].toInt() and 0xff) ushr 4) {
            4 -> IPv4PacketParser.parse(packet)?.let { parse(packet, it) }
            6 -> IPv6PacketParser.parse(packet)?.let { parse(packet, it) }
            else -> null
        }
    }

    /** Returns null for non-UDP packets, non-first fragments, or malformed UDP headers. */
    fun parse(packet: ByteArray, ipv4: IPv4PacketMetadata): UdpMetadata? {
        if (ipv4.protocol != UDP_PROTOCOL || !ipv4.canParseTransportHeader) return null
        return parseAtOffset(
            packet = packet,
            offset = ipv4.headerLength,
            totalLength = ipv4.totalLength,
            moreFragments = ipv4.moreFragments,
        )
    }

    /** Returns null for non-UDP packets, non-first fragments, or malformed UDP headers. */
    fun parse(packet: ByteArray, ipv6: IPv6PacketMetadata): UdpMetadata? {
        if (ipv6.protocol != UDP_PROTOCOL || !ipv6.canParseTransportHeader) return null
        return parseAtOffset(
            packet = packet,
            offset = ipv6.transportOffset,
            totalLength = ipv6.totalLength,
            moreFragments = ipv6.moreFragments,
        )
    }

    private fun parseAtOffset(
        packet: ByteArray,
        offset: Int,
        totalLength: Int,
        moreFragments: Boolean,
    ): UdpMetadata? {
        if (!hasBytes(totalLength, packet, offset, HEADER_LENGTH)) return null

        val udpLength = unsignedShort(packet, offset + 4)
        if (udpLength < HEADER_LENGTH) return null

        // A first fragment can legitimately contain only the beginning of a longer UDP datagram.
        if (!moreFragments && !hasBytes(totalLength, packet, offset, udpLength)) return null

        return UdpMetadata(
            sourcePort = unsignedShort(packet, offset),
            destinationPort = unsignedShort(packet, offset + 2),
            length = udpLength,
        )
    }
}
