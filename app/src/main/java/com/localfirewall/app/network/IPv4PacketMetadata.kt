package com.localfirewall.app.network

import java.net.InetAddress

/** Header metadata extracted from a validated IPv4 packet. */
data class IPv4PacketMetadata(
    val version: Int,
    val headerLength: Int,
    val totalLength: Int,
    val protocol: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    /** The fragment offset in eight-byte units, as encoded in the IPv4 header. */
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
