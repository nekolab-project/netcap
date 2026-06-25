package dev.jokelbaf.netcap.core.format

import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import dev.jokelbaf.netcap.core.readUInt
import dev.jokelbaf.netcap.core.readUShort
import kotlin.time.Instant

/**
 * Decodes the classic libpcap savefile format incrementally. Feed it the bytes you read from a file
 * in any chunk sizes via [decode]; it returns the packets it can fully decode and buffers a partial
 * trailing record until the next call. Byte order and timestamp resolution are detected from the
 * file's magic number.
 *
 * Decoded packets are lazily layered like live captures. The format stores no direction or interface,
 * so [Packet.direction] is [PacketDirection.UNKNOWN] and [Packet.interfaceName] is [interfaceName].
 *
 * @param interfaceName an optional label applied to every decoded packet (e.g. the file name).
 */
class PcapReader(private val interfaceName: String? = null) {

    /** The global header, available once enough bytes have been fed to parse it. */
    var header: PcapFileHeader? = null
        private set

    private var littleEndian = false
    private var buffer = ByteArray(0)

    /** Feeds the next chunk of file bytes and returns every newly completed packet. */
    fun decode(chunk: ByteArray): List<Packet> {
        buffer = if (buffer.isEmpty()) chunk.copyOf() else buffer + chunk

        var pos = 0
        if (header == null) {
            if (buffer.size < GLOBAL_HEADER_SIZE) return emptyList()
            parseHeader()
            pos = GLOBAL_HEADER_SIZE
        }
        val hdr = header ?: return emptyList()

        val packets = mutableListOf<Packet>()
        while (buffer.size - pos >= RECORD_HEADER_SIZE) {
            val seconds = buffer.u32(pos, littleEndian)
            val subsecond = buffer.u32(pos + 4, littleEndian)
            val inclLen = buffer.u32(pos + 8, littleEndian)
            if (inclLen > MAX_RECORD_LENGTH) {
                throw PcapFormatException("Implausible record length: $inclLen")
            }
            val length = inclLen.toInt()
            if (buffer.size - pos - RECORD_HEADER_SIZE < length) break

            val start = pos + RECORD_HEADER_SIZE
            val frame = buffer.copyOfRange(start, start + length)
            val nanos = when (hdr.resolution) {
                PcapTimestampResolution.MICROSECONDS -> subsecond * 1000
                PcapTimestampResolution.NANOSECONDS -> subsecond
            }
            val timestamp = Instant.fromEpochSeconds(seconds, nanos)
            packets += decodedPacket(frame, timestamp, PacketDirection.UNKNOWN, interfaceName, hdr.linkType)
            pos = start + length
        }

        if (pos > 0) buffer = buffer.copyOfRange(pos, buffer.size)
        return packets
    }

    private fun parseHeader() {
        val resolution: PcapTimestampResolution
        when (buffer.readUInt(0)) {
            MAGIC_MICROS -> { littleEndian = false; resolution = PcapTimestampResolution.MICROSECONDS }
            MAGIC_NANOS -> { littleEndian = false; resolution = PcapTimestampResolution.NANOSECONDS }
            MAGIC_MICROS_SWAPPED -> { littleEndian = true; resolution = PcapTimestampResolution.MICROSECONDS }
            MAGIC_NANOS_SWAPPED -> { littleEndian = true; resolution = PcapTimestampResolution.NANOSECONDS }
            else -> throw PcapFormatException("Not a pcap savefile (bad magic number)")
        }
        header = PcapFileHeader(
            linkType = LinkType.fromFileLinkType(buffer.u32(20, littleEndian).toInt()),
            snapLength = buffer.u32(16, littleEndian).toInt(),
            resolution = resolution,
            versionMajor = buffer.u16(4, littleEndian),
            versionMinor = buffer.u16(6, littleEndian),
        )
    }

    companion object {
        private const val MAGIC_MICROS_SWAPPED = 0xD4C3B2A1L
        private const val MAGIC_NANOS_SWAPPED = 0x4D3CB2A1L

        /** Decodes a complete in-memory savefile in one shot. A truncated trailing record is ignored. */
        fun read(bytes: ByteArray, interfaceName: String? = null): List<Packet> =
            PcapReader(interfaceName).decode(bytes)
    }
}

private fun ByteArray.u16(offset: Int, littleEndian: Boolean): Int =
    if (littleEndian) (this[offset].toInt() and 0xFF) or ((this[offset + 1].toInt() and 0xFF) shl 8)
    else readUShort(offset)

private fun ByteArray.u32(offset: Int, littleEndian: Boolean): Long =
    if (littleEndian) {
        (this[offset].toLong() and 0xFF) or
            ((this[offset + 1].toLong() and 0xFF) shl 8) or
            ((this[offset + 2].toLong() and 0xFF) shl 16) or
            ((this[offset + 3].toLong() and 0xFF) shl 24)
    } else {
        readUInt(offset)
    }
