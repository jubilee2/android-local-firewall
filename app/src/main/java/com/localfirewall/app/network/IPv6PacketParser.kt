package com.localfirewall.app.network

import java.net.Inet6Address

/**
 * Parses IPv6 fixed headers and RFC 8200 extension headers without retaining or inspecting
 * upper-layer packet payloads.
 */
object IPv6PacketParser {
    private const val FIXED_HEADER_LENGTH = 40
    private const val IPV6_VERSION = 6
    private const val NEXT_HEADER_HOP_BY_HOP = 0
    private const val NEXT_HEADER_ROUTING = 43
    private const val NEXT_HEADER_FRAGMENT = 44
    private const val NEXT_HEADER_DESTINATION_OPTIONS = 60
    private const val FRAGMENT_HEADER_LENGTH = 8
    private const val MAX_EXTENSION_HEADERS = 8
    private const val MORE_FRAGMENTS_MASK = 0x01

    /** Returns null when [packet] is truncated, malformed, or is not IPv6. */
    fun parse(packet: ByteArray): IPv6PacketMetadata? {
        if (packet.size < FIXED_HEADER_LENGTH) return null

        val version = (packet[0].toInt() and 0xff) ushr 4
        if (version != IPV6_VERSION) return null

        val payloadLength = unsignedShort(packet, 4)
        val totalLength = FIXED_HEADER_LENGTH + payloadLength
        if (totalLength > packet.size) return null

        val sourceAddress = Inet6Address.getByAddress(null, packet.copyOfRange(8, 24), -1)
        val destinationAddress = Inet6Address.getByAddress(null, packet.copyOfRange(24, 40), -1)

        var nextHeader = packet[6].toInt() and 0xff
        var offset = FIXED_HEADER_LENGTH
        var identification = 0
        var fragmentOffset = 0
        var moreFragments = false
        var seenFragmentHeader = false
        var extensionCount = 0

        while (isExtensionHeader(nextHeader)) {
            if (extensionCount >= MAX_EXTENSION_HEADERS) return null
            extensionCount += 1

            if (nextHeader == NEXT_HEADER_FRAGMENT) {
                if (seenFragmentHeader) return null
                if (offset + FRAGMENT_HEADER_LENGTH > totalLength) return null
                seenFragmentHeader = true
                nextHeader = packet[offset].toInt() and 0xff
                val fragOffsetAndFlags = unsignedShort(packet, offset + 2)
                fragmentOffset = fragOffsetAndFlags ushr 3
                moreFragments = (fragOffsetAndFlags and MORE_FRAGMENTS_MASK) != 0
                identification = readIntBigEndian(packet, offset + 4)
                offset += FRAGMENT_HEADER_LENGTH
                // Non-initial fragments carry raw continuation bytes rather than extension headers.
                if (fragmentOffset != 0) break
            } else {
                if (offset + 2 > totalLength) return null
                val followingHeader = packet[offset].toInt() and 0xff
                val extensionLength = ((packet[offset + 1].toInt() and 0xff) + 1) * 8
                if (offset + extensionLength > totalLength) return null
                nextHeader = followingHeader
                offset += extensionLength
            }
        }

        return IPv6PacketMetadata(
            version = version,
            transportOffset = offset,
            totalLength = totalLength,
            identification = identification,
            protocol = nextHeader,
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            fragmentOffset = fragmentOffset,
            moreFragments = moreFragments,
        )
    }

    private fun isExtensionHeader(protocol: Int): Boolean =
        protocol == NEXT_HEADER_HOP_BY_HOP ||
            protocol == NEXT_HEADER_ROUTING ||
            protocol == NEXT_HEADER_FRAGMENT ||
            protocol == NEXT_HEADER_DESTINATION_OPTIONS

    private fun readIntBigEndian(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)
}
