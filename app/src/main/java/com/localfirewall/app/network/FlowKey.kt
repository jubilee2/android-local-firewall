package com.localfirewall.app.network

import java.net.InetAddress

/** Directional identity of an outbound TCP or UDP flow. */
data class FlowKey(
    val protocol: TransportProtocol,
    val sourceAddress: InetAddress,
    val sourcePort: Int,
    val destinationAddress: InetAddress,
    val destinationPort: Int,
)
