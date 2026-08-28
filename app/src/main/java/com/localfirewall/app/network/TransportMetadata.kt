package com.localfirewall.app.network

/** Transport-layer metadata extracted without reading packet payload contents. */
sealed interface TransportMetadata {
    val sourcePort: Int
    val destinationPort: Int
}

data class TcpMetadata(
    override val sourcePort: Int,
    override val destinationPort: Int,
    val headerLength: Int,
    val syn: Boolean,
    val ack: Boolean,
    val fin: Boolean,
    val rst: Boolean,
) : TransportMetadata

data class UdpMetadata(
    override val sourcePort: Int,
    override val destinationPort: Int,
    val length: Int,
) : TransportMetadata
