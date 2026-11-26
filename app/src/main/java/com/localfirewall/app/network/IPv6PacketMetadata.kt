package com.localfirewall.app.network

import java.net.Inet6Address

/** Header metadata extracted from a validated IPv6 packet and its extension header chain. */
data class IPv6PacketMetadata(
    val version: Int,
    /** Byte offset where the upper-layer payload (or non-initial fragment body) begins. */
    val transportOffset: Int,
    val totalLength: Int,
    /** 32-bit Fragment Header identification when fragmented, or 0 for unfragmented packets. */
    val identification: Int,
    /** Upper-layer protocol number from the final parsed Next Header field. */
    val protocol: Int,
    val sourceAddress: Inet6Address,
    val destinationAddress: Inet6Address,
    /** Fragment offset in eight-byte units from an IPv6 Fragment Header, or 0 when unfragmented. */
    val fragmentOffset: Int,
    val moreFragments: Boolean,
) {
    val isFirstFragment: Boolean
        get() = fragmentOffset == 0

    val isNonFirstFragment: Boolean
        get() = fragmentOffset != 0

    val isFragmented: Boolean
        get() = moreFragments || fragmentOffset != 0

    /** Transport headers can only begin in an unfragmented packet or its first fragment. */
    val canParseTransportHeader: Boolean
        get() = !isNonFirstFragment
}
