package dev.jokelbaf.netcap.core

/** Layer-4 protocol carried by a captured packet. */
enum class TransportProtocol(val number: Int, val label: String) {
    TCP(6, "TCP"),
    UDP(17, "UDP");

    companion object {
        fun fromNumber(number: Int): TransportProtocol? = when (number) {
            TCP.number -> TCP
            UDP.number -> UDP
            else -> null
        }
    }
}

/** IP version of a captured packet. */
enum class IpVersion(val label: String) {
    IPV4("IPv4"),
    IPV6("IPv6"),
}

/** Direction of a captured packet relative to the capturing host. */
enum class PacketDirection {
    /** Produced locally, heading out. */
    OUTBOUND,

    /** Arriving from the network. */
    INBOUND,

    /** Couldn't be determined (e.g. desktop traffic between two other hosts). */
    UNKNOWN,
}
