package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.IpVersion
import dev.jokelbaf.netcap.core.readIpv4Address
import dev.jokelbaf.netcap.core.readUByte
import dev.jokelbaf.netcap.core.readUShort
import dev.jokelbaf.netcap.core.writeUByte
import dev.jokelbaf.netcap.core.writeUShort

/**
 * A read-only [IpPacket] view over an IPv4 packet starting at [headerOffset] in [buffer].
 * Header fields are computed on access and [payload] decodes the transport layer lazily.
 */
class Ipv4Packet private constructor(
    private val buffer: ByteArray,
    private val headerOffset: Int,
    val headerLength: Int,
    override val totalLength: Int,
    override val protocolNumber: Int,
    override val sourceBytes: ByteArray,
    override val destinationBytes: ByteArray,
) : IpPacket, Sliceable {
    override val version: IpVersion = IpVersion.IPV4
    override val sourceAddress: String = sourceBytes.readIpv4Address(0)
    override val destinationAddress: String = destinationBytes.readIpv4Address(0)
    override val transportOffset: Int get() = headerOffset + headerLength
    override val transportLength: Int get() = totalLength - headerLength
    override val payload: Payload by lazy { decodeTransport(buffer, transportOffset, transportLength, protocolNumber) }

    override fun slice(): ByteArray = buffer.copyOfRange(headerOffset, headerOffset + totalLength)

    companion object {
        const val VERSION = 4
        const val MIN_HEADER_LENGTH = 20
        private const val PROTOCOL_OFFSET = 9
        private const val SOURCE_OFFSET = 12
        private const val DESTINATION_OFFSET = 16

        /**
         * Parses the IPv4 packet starting at [offset] in [buffer], with [available] bytes present.
         * Returns null for anything we don't handle: non-IPv4, truncated, fragmented, or malformed.
         */
        fun parse(buffer: ByteArray, offset: Int, available: Int): Ipv4Packet? {
            if (available < MIN_HEADER_LENGTH) return null
            val versionAndIhl = buffer.readUByte(offset)
            if ((versionAndIhl ushr 4) != VERSION) return null
            val headerLength = (versionAndIhl and 0x0F) * 4
            if (headerLength < MIN_HEADER_LENGTH || headerLength > available) return null

            val totalLength = buffer.readUShort(offset + 2)
            if (totalLength < headerLength || totalLength > available) return null

            // Drop fragments: the MF flag (0x2000) or a non-zero fragment offset.
            val flagsAndOffset = buffer.readUShort(offset + 6)
            if ((flagsAndOffset and 0x2000) != 0 || (flagsAndOffset and 0x1FFF) != 0) return null

            val source = buffer.copyOfRange(offset + SOURCE_OFFSET, offset + SOURCE_OFFSET + 4)
            val destination = buffer.copyOfRange(offset + DESTINATION_OFFSET, offset + DESTINATION_OFFSET + 4)
            return Ipv4Packet(
                buffer = buffer,
                headerOffset = offset,
                headerLength = headerLength,
                totalLength = totalLength,
                protocolNumber = buffer.readUByte(offset + PROTOCOL_OFFSET),
                sourceBytes = source,
                destinationBytes = destination,
            )
        }

        /** Convenience for an IPv4 packet that starts at offset 0. */
        fun parse(buffer: ByteArray, length: Int): Ipv4Packet? = parse(buffer, 0, length)

        /**
         * Assembles a complete IPv4 packet from a ready-made transport segment (already
         * checksummed), filling in the IPv4 header and its checksum. Used to build the
         * inbound packets the NAT writes back into the TUN.
         */
        fun build(
            sourceBytes: ByteArray,
            destinationBytes: ByteArray,
            protocol: Int,
            transport: ByteArray,
        ): ByteArray {
            val totalLength = MIN_HEADER_LENGTH + transport.size
            val packet = ByteArray(totalLength)
            packet.writeUByte(0, (VERSION shl 4) or (MIN_HEADER_LENGTH / 4)) // version + IHL
            packet.writeUByte(1, 0) // DSCP/ECN
            packet.writeUShort(2, totalLength)
            packet.writeUShort(4, 0) // identification
            packet.writeUShort(6, 0x4000) // don't fragment
            packet.writeUByte(8, 64) // TTL
            packet.writeUByte(9, protocol)
            packet.writeUShort(10, 0) // checksum placeholder
            sourceBytes.copyInto(packet, 12, 0, 4)
            destinationBytes.copyInto(packet, 16, 0, 4)
            val checksum = Checksum.compute(packet, 0, MIN_HEADER_LENGTH)
            packet.writeUShort(10, checksum)
            transport.copyInto(packet, MIN_HEADER_LENGTH)
            return packet
        }
    }
}
