package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.TransportProtocol
import dev.jokelbaf.netcap.core.readUShort
import dev.jokelbaf.netcap.core.writeUShort

/**
 * A read-only [TransportSegment] view over a UDP datagram at [segmentOffset] in [buffer].
 * [payload] exposes the application data; all offsets are absolute into the frame buffer.
 */
class UdpDatagram private constructor(
    private val buffer: ByteArray,
    private val segmentOffset: Int,
    private val segmentLength: Int,
    override val sourcePort: Int,
    override val destinationPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) : TransportSegment, Sliceable {
    override val payload: Payload by lazy { RawPayload(buffer, payloadOffset, payloadLength) }

    override fun slice(): ByteArray = buffer.copyOfRange(segmentOffset, segmentOffset + segmentLength)

    companion object {
        const val HEADER_LENGTH = 8

        /** Parses the UDP header at [offset] in [buffer]; [transportLength] is the bytes available. */
        fun parse(buffer: ByteArray, offset: Int, transportLength: Int): UdpDatagram? {
            if (transportLength < HEADER_LENGTH) return null
            val udpLength = buffer.readUShort(offset + 4)
            // The UDP length field covers header + data; clamp to what's actually present.
            val available = minOf(udpLength, transportLength)
            if (available < HEADER_LENGTH) return null
            return UdpDatagram(
                buffer = buffer,
                segmentOffset = offset,
                segmentLength = available,
                sourcePort = buffer.readUShort(offset),
                destinationPort = buffer.readUShort(offset + 2),
                payloadOffset = offset + HEADER_LENGTH,
                payloadLength = available - HEADER_LENGTH,
            )
        }

        /**
         * Builds a full inbound IPv4/IPv6 + UDP packet carrying [payload], with a valid UDP
         * checksum. The IP version is chosen by the address length (4 vs 16 bytes).
         */
        fun build(
            sourceBytes: ByteArray,
            destinationBytes: ByteArray,
            sourcePort: Int,
            destinationPort: Int,
            payload: ByteArray,
        ): ByteArray {
            val udpLength = HEADER_LENGTH + payload.size
            val segment = ByteArray(udpLength)
            segment.writeUShort(0, sourcePort)
            segment.writeUShort(2, destinationPort)
            segment.writeUShort(4, udpLength)
            segment.writeUShort(6, 0) // checksum placeholder
            payload.copyInto(segment, HEADER_LENGTH)

            var checksum = transportChecksum(sourceBytes, destinationBytes, TransportProtocol.UDP.number, segment)
            // A computed UDP checksum of zero must be transmitted as 0xFFFF.
            if (checksum == 0) checksum = 0xFFFF
            segment.writeUShort(6, checksum)

            return buildIpPacket(sourceBytes, destinationBytes, TransportProtocol.UDP.number, segment)
        }
    }
}
