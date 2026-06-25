package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.IpVersion
import dev.jokelbaf.netcap.core.readIpv6Address
import dev.jokelbaf.netcap.core.readUByte
import dev.jokelbaf.netcap.core.readUShort
import dev.jokelbaf.netcap.core.writeUByte
import dev.jokelbaf.netcap.core.writeUShort

/**
 * A read-only [IpPacket] view over an IPv6 packet starting at [headerOffset] in [buffer].
 * The 40-byte fixed header is followed by an optional chain of extension headers, which
 * parsing walks to locate the transport layer; [payload] decodes it lazily.
 */
class Ipv6Packet private constructor(
    private val buffer: ByteArray,
    private val headerOffset: Int,
    override val protocolNumber: Int,
    override val sourceBytes: ByteArray,
    override val destinationBytes: ByteArray,
    override val transportOffset: Int,
    override val transportLength: Int,
    override val totalLength: Int,
) : IpPacket, Sliceable {
    override val version: IpVersion = IpVersion.IPV6
    override val sourceAddress: String = sourceBytes.readIpv6Address(0)
    override val destinationAddress: String = destinationBytes.readIpv6Address(0)
    override val payload: Payload by lazy { decodeTransport(buffer, transportOffset, transportLength, protocolNumber) }

    override fun slice(): ByteArray = buffer.copyOfRange(headerOffset, headerOffset + totalLength)

    companion object {
        const val VERSION = 6
        const val HEADER_LENGTH = 40

        private const val PAYLOAD_LENGTH_OFFSET = 4
        private const val NEXT_HEADER_OFFSET = 6
        private const val SOURCE_OFFSET = 8
        private const val DESTINATION_OFFSET = 24

        // Extension headers we skip over to reach the transport header. Fragment (44) is
        // deliberately excluded: we don't reassemble, so fragmented packets are dropped.
        private val EXTENSION_HEADERS = setOf(0, 43, 60, 51) // Hop-by-Hop, Routing, Dest-Opts, AH

        /** Parses the IPv6 packet starting at [offset] in [buffer], with [available] bytes present. */
        fun parse(buffer: ByteArray, offset: Int, available: Int): Ipv6Packet? {
            if (available < HEADER_LENGTH) return null
            val payloadLength = buffer.readUShort(offset + PAYLOAD_LENGTH_OFFSET)
            val totalLength = HEADER_LENGTH + payloadLength
            if (totalLength > available) return null
            val end = offset + totalLength

            var nextHeader = buffer.readUByte(offset + NEXT_HEADER_OFFSET)
            var cursor = offset + HEADER_LENGTH
            while (nextHeader in EXTENSION_HEADERS) {
                if (cursor + 2 > end) return null
                val extLength = if (nextHeader == 51) {
                    (buffer.readUByte(cursor + 1) + 2) * 4 // Authentication Header: 4-octet units, +2
                } else {
                    (buffer.readUByte(cursor + 1) + 1) * 8
                }
                nextHeader = buffer.readUByte(cursor)
                cursor += extLength
                if (cursor > end) return null
            }

            return Ipv6Packet(
                buffer = buffer,
                headerOffset = offset,
                protocolNumber = nextHeader,
                sourceBytes = buffer.copyOfRange(offset + SOURCE_OFFSET, offset + SOURCE_OFFSET + 16),
                destinationBytes = buffer.copyOfRange(offset + DESTINATION_OFFSET, offset + DESTINATION_OFFSET + 16),
                transportOffset = cursor,
                transportLength = end - cursor,
                totalLength = totalLength,
            )
        }

        /** Convenience for an IPv6 packet that starts at offset 0. */
        fun parse(buffer: ByteArray, length: Int): Ipv6Packet? = parse(buffer, 0, length)

        /**
         * Assembles a complete IPv6 packet from a ready-made transport segment (already
         * checksummed). IPv6 has no header checksum. Used to build inbound NAT packets.
         */
        fun build(
            sourceBytes: ByteArray,
            destinationBytes: ByteArray,
            nextHeader: Int,
            transport: ByteArray,
        ): ByteArray {
            val packet = ByteArray(HEADER_LENGTH + transport.size)
            packet.writeUByte(0, (VERSION shl 4)) // version 6, traffic class + flow label 0
            packet.writeUShort(PAYLOAD_LENGTH_OFFSET, transport.size)
            packet.writeUByte(NEXT_HEADER_OFFSET, nextHeader)
            packet.writeUByte(7, 64) // hop limit
            sourceBytes.copyInto(packet, SOURCE_OFFSET, 0, 16)
            destinationBytes.copyInto(packet, DESTINATION_OFFSET, 0, 16)
            transport.copyInto(packet, HEADER_LENGTH)
            return packet
        }
    }
}
