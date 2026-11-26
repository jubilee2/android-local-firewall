package com.localfirewall.app.network

/** Extracts metadata from a complete TCP header carried by an IPv4 or IPv6 packet. */
object TcpPacketParser {
    private const val TCP_PROTOCOL = 6
    private const val MINIMUM_HEADER_LENGTH = 20
    private const val DATA_OFFSET_BYTE = 12
    private const val FLAGS_BYTE = 13
    private const val FIN_MASK = 0x01
    private const val SYN_MASK = 0x02
    private const val RST_MASK = 0x04
    private const val ACK_MASK = 0x10

    /** Parses the IPv4 or IPv6 header before extracting TCP metadata. */
    fun parse(packet: ByteArray): TcpMetadata? {
        if (packet.isEmpty()) return null
        return when ((packet[0].toInt() and 0xff) ushr 4) {
            4 -> IPv4PacketParser.parse(packet)?.let { parse(packet, it) }
            6 -> IPv6PacketParser.parse(packet)?.let { parse(packet, it) }
            else -> null
        }
    }

    /** Returns null for non-TCP packets, non-first fragments, or malformed TCP headers. */
    fun parse(packet: ByteArray, ipv4: IPv4PacketMetadata): TcpMetadata? {
        if (ipv4.protocol != TCP_PROTOCOL || !ipv4.canParseTransportHeader) return null
        return parseAtOffset(packet, offset = ipv4.headerLength, totalLength = ipv4.totalLength)
    }

    /** Returns null for non-TCP packets, non-first fragments, or malformed TCP headers. */
    fun parse(packet: ByteArray, ipv6: IPv6PacketMetadata): TcpMetadata? {
        if (ipv6.protocol != TCP_PROTOCOL || !ipv6.canParseTransportHeader) return null
        return parseAtOffset(packet, offset = ipv6.transportOffset, totalLength = ipv6.totalLength)
    }

    private fun parseAtOffset(packet: ByteArray, offset: Int, totalLength: Int): TcpMetadata? {
        if (!hasBytes(totalLength, packet, offset, MINIMUM_HEADER_LENGTH)) return null

        val headerLength = ((packet[offset + DATA_OFFSET_BYTE].toInt() and 0xff) ushr 4) * 4
        if (headerLength < MINIMUM_HEADER_LENGTH || !hasBytes(totalLength, packet, offset, headerLength)) {
            return null
        }

        val flags = packet[offset + FLAGS_BYTE].toInt() and 0xff
        return TcpMetadata(
            sourcePort = unsignedShort(packet, offset),
            destinationPort = unsignedShort(packet, offset + 2),
            headerLength = headerLength,
            syn = flags and SYN_MASK != 0,
            ack = flags and ACK_MASK != 0,
            fin = flags and FIN_MASK != 0,
            rst = flags and RST_MASK != 0,
        )
    }
}

internal fun unsignedShort(packet: ByteArray, offset: Int): Int =
    ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

internal fun hasBytes(
    ipv4: IPv4PacketMetadata,
    packet: ByteArray,
    offset: Int,
    length: Int,
): Boolean = hasBytes(ipv4.totalLength, packet, offset, length)

internal fun hasBytes(
    totalLength: Int,
    packet: ByteArray,
    offset: Int,
    length: Int,
): Boolean = offset >= 0 && length >= 0 && offset <= totalLength - length &&
    offset <= packet.size - length
