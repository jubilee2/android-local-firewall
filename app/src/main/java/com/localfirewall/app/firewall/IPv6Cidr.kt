package com.localfirewall.app.firewall

import java.net.Inet6Address
import java.net.InetAddress

/** An IPv6 subnet with a canonical 128-bit masked network address. */
@ConsistentCopyVisibility
data class IPv6Cidr private constructor(
    private val networkHigh: Long,
    private val networkLow: Long,
    val prefixLength: Int,
) {
    fun contains(address: InetAddress): Boolean {
        if (address !is Inet6Address) return false
        val bytes = address.address
        val high = readLongBigEndian(bytes, 0) and highPrefixMask(prefixLength)
        val low = readLongBigEndian(bytes, 8) and lowPrefixMask(prefixLength)
        return high == networkHigh && low == networkLow
    }

    /** Canonical compressed IPv6 `/prefix` representation of this subnet. */
    fun format(): String {
        val bytes = ByteArray(16)
        writeLongBigEndian(bytes, 0, networkHigh)
        writeLongBigEndian(bytes, 8, networkLow)
        return "${formatCompressedIpv6(bytes)}/$prefixLength"
    }

    companion object {
        fun parse(value: String): IPv6Cidr {
            val parts = value.split('/')
            require(parts.size == 2) { "CIDR must contain one '/'" }
            val address = parseAddress(parts[0])
            val prefixLength = parts[1].toIntOrNull()
            require(prefixLength != null && prefixLength in 0..128) {
                "IPv6 prefix length must be between 0 and 128"
            }
            val bytes = address.address
            val high = readLongBigEndian(bytes, 0) and highPrefixMask(prefixLength)
            val low = readLongBigEndian(bytes, 8) and lowPrefixMask(prefixLength)
            return IPv6Cidr(networkHigh = high, networkLow = low, prefixLength = prefixLength)
        }

        /** Parses a strict numeric IPv6 literal without performing any DNS resolution. */
        fun parseAddress(value: String): Inet6Address {
            require(value.isNotEmpty() && '%' !in value && ":::" !in value) {
                "Invalid IPv6 address"
            }
            if (value.startsWith(':') && !value.startsWith("::")) {
                throw IllegalArgumentException("Invalid IPv6 address")
            }
            if (value.endsWith(':') && !value.endsWith("::")) {
                throw IllegalArgumentException("Invalid IPv6 address")
            }

            val doubleColonParts = value.split("::")
            require(doubleColonParts.size <= 2) { "Invalid IPv6 address" }

            val headGroups = parseGroupList(doubleColonParts[0], allowEmbeddedIpv4 = doubleColonParts.size == 1)
            val tailGroups = if (doubleColonParts.size == 2) {
                parseGroupList(doubleColonParts[1], allowEmbeddedIpv4 = true)
            } else {
                emptyList()
            }

            val hextets = if (doubleColonParts.size == 2) {
                val missing = 8 - (headGroups.size + tailGroups.size)
                require(missing >= 1) { "Invalid IPv6 address" }
                buildList(8) {
                    addAll(headGroups)
                    repeat(missing) { add(0) }
                    addAll(tailGroups)
                }
            } else {
                require(headGroups.size == 8) { "Invalid IPv6 address" }
                headGroups
            }

            val bytes = ByteArray(16)
            hextets.forEachIndexed { index, hextet ->
                bytes[index * 2] = ((hextet ushr 8) and 0xff).toByte()
                bytes[index * 2 + 1] = (hextet and 0xff).toByte()
            }
            return Inet6Address.getByAddress(null, bytes, -1)
        }

        private fun parseGroupList(segment: String, allowEmbeddedIpv4: Boolean): List<Int> {
            if (segment.isEmpty()) return emptyList()
            val rawTokens = segment.split(':')
            val result = ArrayList<Int>(rawTokens.size + 1)
            rawTokens.forEachIndexed { index, token ->
                require(token.isNotEmpty()) { "Invalid IPv6 address" }
                if (allowEmbeddedIpv4 && index == rawTokens.lastIndex && '.' in token) {
                    val ipv4Bytes = IPv4Cidr.parseAddress(token).address
                    result.add(((ipv4Bytes[0].toInt() and 0xff) shl 8) or (ipv4Bytes[1].toInt() and 0xff))
                    result.add(((ipv4Bytes[2].toInt() and 0xff) shl 8) or (ipv4Bytes[3].toInt() and 0xff))
                } else {
                    require(token.length in 1..4 && token.all(::isHexDigit)) {
                        "Invalid IPv6 address"
                    }
                    result.add(token.toInt(16))
                }
            }
            return result
        }

        private fun isHexDigit(char: Char): Boolean =
            char in '0'..'9' || char in 'a'..'f' || char in 'A'..'F'
    }
}

/** DNS-free numeric IPv4 or IPv6 literal parser. */
object IpAddressLiteral {
    fun parse(value: String): InetAddress =
        if (':' in value) IPv6Cidr.parseAddress(value) else IPv4Cidr.parseAddress(value)

    fun format(address: InetAddress): String =
        if (address is Inet6Address) {
            formatCompressedIpv6(address.address)
        } else {
            requireNotNull(address.hostAddress)
        }
}

internal fun formatCompressedIpv6(bytes: ByteArray): String {
    val hextets = IntArray(8) { index ->
        ((bytes[index * 2].toInt() and 0xff) shl 8) or (bytes[index * 2 + 1].toInt() and 0xff)
    }
    var bestStart = -1
    var bestLength = 0
    var currentStart = -1
    var currentLength = 0

    for (index in hextets.indices) {
        if (hextets[index] == 0) {
            if (currentStart == -1) currentStart = index
            currentLength += 1
            if (currentLength > 1 && currentLength > bestLength) {
                bestStart = currentStart
                bestLength = currentLength
            }
        } else {
            currentStart = -1
            currentLength = 0
        }
    }

    if (bestStart == -1) {
        return hextets.joinToString(":") { it.toString(16) }
    }

    val builder = StringBuilder()
    var index = 0
    while (index < 8) {
        if (index == bestStart) {
            builder.append("::")
            index += bestLength
        } else {
            if (index > 0 && index != bestStart + bestLength) {
                builder.append(':')
            }
            builder.append(hextets[index].toString(16))
            index += 1
        }
    }
    return builder.toString()
}

private fun highPrefixMask(prefixLength: Int): Long = when {
    prefixLength == 0 -> 0L
    prefixLength >= 64 -> -1L
    else -> -1L shl (64 - prefixLength)
}

private fun lowPrefixMask(prefixLength: Int): Long = when {
    prefixLength <= 64 -> 0L
    prefixLength == 128 -> -1L
    else -> -1L shl (128 - prefixLength)
}

private fun readLongBigEndian(bytes: ByteArray, offset: Int): Long {
    var result = 0L
    for (i in 0 until 8) {
        result = (result shl 8) or (bytes[offset + i].toLong() and 0xffL)
    }
    return result
}

private fun writeLongBigEndian(bytes: ByteArray, offset: Int, value: Long) {
    for (i in 0 until 8) {
        bytes[offset + i] = ((value ushr ((7 - i) * 8)) and 0xffL).toByte()
    }
}
