package com.localfirewall.app.firewall

import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress

data class FirewallRule(
    val action: FirewallAction,
    val destinationAddress: InetAddress? = null,
    val destinationCidr: IPv4Cidr? = null,
    val destinationIpv6Cidr: IPv6Cidr? = null,
    val protocol: TransportProtocol = TransportProtocol.ANY,
    val destinationPort: Int? = null,
    val uid: Int? = null,
) {
    init {
        val destinationSpecifiers = listOfNotNull(
            destinationAddress,
            destinationCidr,
            destinationIpv6Cidr,
        ).size
        require(destinationSpecifiers <= 1) {
            "Specify at most one exact destination or CIDR"
        }
        require(destinationPort == null || destinationPort in 0..65535) {
            "Destination port must be between 0 and 65535"
        }
        require(uid == null || uid >= 0) {
            "UID must be non-negative"
        }
    }
}
