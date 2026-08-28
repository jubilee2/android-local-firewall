package com.localfirewall.app.network

import java.net.InetAddress

/** Transport protocols understood by the firewall decision layer. */
enum class TransportProtocol {
    TCP,
    UDP,
    ANY,
}

/** Parsed packet headers used for firewall decisions. Packet payload is never retained. */
data class PacketMetadata(
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val protocol: TransportProtocol,
    val sourcePort: Int?,
    val destinationPort: Int?,
)
