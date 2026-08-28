package com.localfirewall.app.firewall

import java.net.Inet4Address
import java.net.InetAddress

/** An IPv4 subnet with a canonical network address. */
data class IPv4Cidr private constructor(
    private val network: Int,
    val prefixLength: Int,
) {
    fun contains(address: InetAddress): Boolean {
        if (address !is Inet4Address) return false
        val mask = prefixMask(prefixLength)
        return address.toInt() and mask == network
    }

    companion object {
        fun parse(value: String): IPv4Cidr {
            val parts = value.split('/')
            require(parts.size == 2) { "CIDR must contain one '/'" }
            val address = parseIPv4(parts[0])
            val prefixLength = parts[1].toIntOrNull()
            require(prefixLength in 0..32) { "IPv4 prefix length must be between 0 and 32" }
            val mask = prefixMask(requireNotNull(prefixLength))
            return IPv4Cidr(address.toInt() and mask, prefixLength)
        }

        private fun parseIPv4(value: String): Inet4Address {
            val octets = value.split('.')
            require(octets.size == 4) { "CIDR address must be IPv4" }
            val bytes = octets.map { octet ->
                val number = octet.toIntOrNull()
                require(number in 0..255) { "Invalid IPv4 address" }
                require(octet == number.toString()) { "Invalid IPv4 address" }
                requireNotNull(number).toByte()
            }.toByteArray()
            return InetAddress.getByAddress(bytes) as Inet4Address
        }
    }
}

private fun InetAddress.toInt(): Int = address.fold(0) { result, byte ->
    (result shl 8) or (byte.toInt() and 0xff)
}

private fun prefixMask(prefixLength: Int): Int =
    if (prefixLength == 0) 0 else -1 shl (32 - prefixLength)
