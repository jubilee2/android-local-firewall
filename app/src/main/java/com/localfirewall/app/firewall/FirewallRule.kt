package com.localfirewall.app.firewall

import com.localfirewall.app.network.TransportProtocol
import java.net.Inet4Address

data class FirewallRule(
    val action: FirewallAction,
    val destinationAddress: Inet4Address? = null,
    val destinationCidr: IPv4Cidr? = null,
    val protocol: TransportProtocol = TransportProtocol.ANY,
    val destinationPort: Int? = null,
) {
    init {
        require(destinationAddress == null || destinationCidr == null) {
            "Specify either an exact destination or a CIDR, not both"
        }
        require(destinationPort == null || destinationPort in 0..65535) {
            "Destination port must be between 0 and 65535"
        }
    }
}
