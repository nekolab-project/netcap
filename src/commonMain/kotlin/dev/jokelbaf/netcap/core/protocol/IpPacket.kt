package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.IpVersion
import dev.jokelbaf.netcap.core.readUByte

/**
 * A [Payload] layer for an IP packet (IPv4 or IPv6). All offsets are absolute into the
 * owning frame buffer; the transport header begins at [transportOffset] and [payload]
 * lazily decodes the TCP/UDP layer beneath it.
 */
sealed interface IpPacket : Payload {
    val version: IpVersion

    /** Layer-4 protocol number (the final next-header after any IPv6 extensions). */
    val protocolNumber: Int

    /** Raw address bytes - 4 for IPv4, 16 for IPv6 - as used to build reply packets. */
    val sourceBytes: ByteArray
    val destinationBytes: ByteArray
    val sourceAddress: String
    val destinationAddress: String

    /** Absolute offset of the transport header in the frame buffer. */
    val transportOffset: Int
    val transportLength: Int

    /** Total size of the IP packet on the wire, in bytes. */
    val totalLength: Int

    /** The transport layer beneath, decoded lazily (TCP/UDP/raw). */
    val payload: Payload

    companion object {
        /** Parses the IP packet starting at [offset] in [buffer], dispatching on the version nibble. */
        fun parse(buffer: ByteArray, offset: Int, available: Int): IpPacket? {
            if (available < 1) return null
            return when (buffer.readUByte(offset) ushr 4) {
                Ipv4Packet.VERSION -> Ipv4Packet.parse(buffer, offset, available)
                Ipv6Packet.VERSION -> Ipv6Packet.parse(buffer, offset, available)
                else -> null
            }
        }

        /** Convenience for callers whose IP packet starts at offset 0 (e.g. the mobile TUN). */
        fun parse(buffer: ByteArray, length: Int): IpPacket? = parse(buffer, 0, length)
    }
}

/** A [Payload] layer for a transport segment (TCP or UDP). */
sealed interface TransportSegment : Payload {
    val sourcePort: Int
    val destinationPort: Int

    /** The application data beneath, as a [RawPayload]. */
    val payload: Payload
}

/** Decodes the transport layer at [offset] for the given IP [protocolNumber]; falls back to [RawPayload]. */
internal fun decodeTransport(buffer: ByteArray, offset: Int, length: Int, protocolNumber: Int): Payload {
    val segment = when (protocolNumber) {
        dev.jokelbaf.netcap.core.TransportProtocol.TCP.number -> TcpSegment.parse(buffer, offset, length)
        dev.jokelbaf.netcap.core.TransportProtocol.UDP.number -> UdpDatagram.parse(buffer, offset, length)
        else -> null
    }
    return segment ?: RawPayload(buffer, offset, length)
}

/**
 * Computes the TCP/UDP checksum of a transport [segment] using the IPv4 or IPv6
 * pseudo-header, selected by the address length (4 vs 16 bytes).
 */
internal fun transportChecksum(
    sourceBytes: ByteArray,
    destinationBytes: ByteArray,
    protocol: Int,
    segment: ByteArray,
): Int {
    val pseudo = if (sourceBytes.size == 16) {
        Checksum.pseudoHeaderSumV6(sourceBytes, destinationBytes, protocol, segment.size)
    } else {
        Checksum.pseudoHeaderSum(sourceBytes, destinationBytes, protocol, segment.size)
    }
    return Checksum.compute(segment, 0, segment.size, pseudo)
}

/** Wraps a ready transport [segment] in an IPv4 or IPv6 header, selected by the address length. */
internal fun buildIpPacket(
    sourceBytes: ByteArray,
    destinationBytes: ByteArray,
    protocol: Int,
    segment: ByteArray,
): ByteArray = if (sourceBytes.size == 16) {
    Ipv6Packet.build(sourceBytes, destinationBytes, protocol, segment)
} else {
    Ipv4Packet.build(sourceBytes, destinationBytes, protocol, segment)
}
