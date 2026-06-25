package dev.jokelbaf.netcap.core.protocol

/**
 * Ergonomic lazy traversal of a packet's [Payload] chain. Each accessor walks down from
 * [Packet.payload] (decoding layers on demand) to the first layer of the requested type,
 * or null. Users rarely need to hand-walk the chain.
 */

val Packet.ethernet: EthernetFrame? get() = payload as? EthernetFrame
val Packet.ip: IpPacket? get() = firstLayer()
val Packet.ipv4: Ipv4Packet? get() = firstLayer()
val Packet.ipv6: Ipv6Packet? get() = firstLayer()
val Packet.transport: TransportSegment? get() = firstLayer()
val Packet.tcp: TcpSegment? get() = firstLayer()
val Packet.udp: UdpDatagram? get() = firstLayer()

private inline fun <reified T : Payload> Packet.firstLayer(): T? {
    var layer: Payload? = payload
    while (layer != null) {
        if (layer is T) return layer
        layer = layer.next()
    }
    return null
}

private fun Payload.next(): Payload? = when (this) {
    is EthernetFrame -> payload
    is IpPacket -> payload
    is TransportSegment -> payload
    is RawPayload -> null
}
