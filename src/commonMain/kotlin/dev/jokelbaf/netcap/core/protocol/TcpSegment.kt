package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.TransportProtocol
import dev.jokelbaf.netcap.core.readUByte
import dev.jokelbaf.netcap.core.readUInt
import dev.jokelbaf.netcap.core.readUShort
import dev.jokelbaf.netcap.core.writeUByte
import dev.jokelbaf.netcap.core.writeUInt
import dev.jokelbaf.netcap.core.writeUShort

/** TCP control flag bits. */
object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

/**
 * A read-only [TransportSegment] view over a TCP segment at [segmentOffset] in [buffer].
 * Header fields are parsed at construction (cheap); [payload] exposes the application data.
 * All offsets are absolute into the frame buffer.
 */
class TcpSegment private constructor(
    private val buffer: ByteArray,
    private val segmentOffset: Int,
    private val segmentLength: Int,
    override val sourcePort: Int,
    override val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgementNumber: Long,
    val flags: Int,
    val windowSize: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) : TransportSegment, Sliceable {
    val isSyn: Boolean get() = flags and TcpFlags.SYN != 0
    val isAck: Boolean get() = flags and TcpFlags.ACK != 0
    val isFin: Boolean get() = flags and TcpFlags.FIN != 0
    val isRst: Boolean get() = flags and TcpFlags.RST != 0

    override val payload: Payload by lazy { RawPayload(buffer, payloadOffset, payloadLength) }

    override fun slice(): ByteArray = buffer.copyOfRange(segmentOffset, segmentOffset + segmentLength)

    companion object {
        const val HEADER_LENGTH = 20

        /** Parses the TCP header at [offset] in [buffer]; [transportLength] is the whole segment length. */
        fun parse(buffer: ByteArray, offset: Int, transportLength: Int): TcpSegment? {
            if (transportLength < HEADER_LENGTH) return null
            val dataOffset = (buffer.readUByte(offset + 12) ushr 4) * 4
            if (dataOffset < HEADER_LENGTH || dataOffset > transportLength) return null
            return TcpSegment(
                buffer = buffer,
                segmentOffset = offset,
                segmentLength = transportLength,
                sourcePort = buffer.readUShort(offset),
                destinationPort = buffer.readUShort(offset + 2),
                sequenceNumber = buffer.readUInt(offset + 4),
                acknowledgementNumber = buffer.readUInt(offset + 8),
                flags = buffer.readUByte(offset + 13),
                windowSize = buffer.readUShort(offset + 14),
                payloadOffset = offset + dataOffset,
                payloadLength = transportLength - dataOffset,
            )
        }

        /**
         * Builds a full inbound IPv4/IPv6 + TCP packet (20-byte header, no options) with the
         * given control fields and [payload], computing a valid checksum. The IP version is
         * chosen by the address length (4 vs 16 bytes).
         */
        fun build(
            sourceBytes: ByteArray,
            destinationBytes: ByteArray,
            sourcePort: Int,
            destinationPort: Int,
            sequenceNumber: Long,
            acknowledgementNumber: Long,
            flags: Int,
            windowSize: Int,
            payload: ByteArray = EMPTY,
        ): ByteArray {
            val segment = ByteArray(HEADER_LENGTH + payload.size)
            segment.writeUShort(0, sourcePort)
            segment.writeUShort(2, destinationPort)
            segment.writeUInt(4, sequenceNumber and 0xFFFFFFFFL)
            segment.writeUInt(8, acknowledgementNumber and 0xFFFFFFFFL)
            segment.writeUByte(12, (HEADER_LENGTH / 4) shl 4) // data offset, no options
            segment.writeUByte(13, flags)
            segment.writeUShort(14, windowSize)
            segment.writeUShort(16, 0) // checksum placeholder
            segment.writeUShort(18, 0) // urgent pointer
            payload.copyInto(segment, HEADER_LENGTH)

            segment.writeUShort(16, transportChecksum(sourceBytes, destinationBytes, TransportProtocol.TCP.number, segment))
            return buildIpPacket(sourceBytes, destinationBytes, TransportProtocol.TCP.number, segment)
        }

        private val EMPTY = ByteArray(0)
    }
}
