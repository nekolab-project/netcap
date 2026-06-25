package dev.jokelbaf.netcap.core.format

import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.writeUInt
import dev.jokelbaf.netcap.core.writeUShort

/**
 * Encodes [Packet]s into the classic libpcap savefile format. It produces bytes only — the caller
 * writes them to a file. Emit [fileHeader] once, then a [record] per packet (or use [write] for a
 * complete in-memory file).
 *
 * Capture direction and interface name are not part of the format and are silently dropped, as in
 * every `.pcap` tool. Output is big-endian; Wireshark reads either byte order via the magic number.
 *
 * @param linkType the frames' link layer, written into the header. Must not be [LinkType.UNKNOWN].
 * @param snapLength the capture snap length recorded in the header.
 * @param resolution timestamp precision; [PcapTimestampResolution.MICROSECONDS] is the most
 *   broadly compatible.
 */
class PcapWriter(
    private val linkType: LinkType,
    private val snapLength: Int = 65_536,
    private val resolution: PcapTimestampResolution = PcapTimestampResolution.MICROSECONDS,
) {
    init {
        require(linkType != LinkType.UNKNOWN) {
            "Cannot write a pcap file for LinkType.UNKNOWN; specify a concrete link type"
        }
    }

    /** The 24-byte global header. Write it once, before any [record]. */
    fun fileHeader(): ByteArray {
        val header = ByteArray(GLOBAL_HEADER_SIZE)
        val magic = if (resolution == PcapTimestampResolution.NANOSECONDS) MAGIC_NANOS else MAGIC_MICROS
        header.writeUInt(0, magic)
        header.writeUShort(4, PCAP_VERSION_MAJOR)
        header.writeUShort(6, PCAP_VERSION_MINOR)
        header.writeUInt(8, 0)
        header.writeUInt(12, 0)
        header.writeUInt(16, snapLength.toLong())
        header.writeUInt(20, linkType.fileLinkType.toLong())
        return header
    }

    /**
     * One packet record: the 16-byte record header followed by the captured frame bytes.
     *
     * @param originalLength the packet's length on the wire before any snap truncation; defaults to
     *   the captured size (correct unless the frame was snap-limited at capture time).
     */
    fun record(packet: Packet, originalLength: Int = packet.frame.bytes.size): ByteArray {
        val data = packet.frame.bytes
        val record = ByteArray(RECORD_HEADER_SIZE + data.size)
        val subsecond = when (resolution) {
            PcapTimestampResolution.MICROSECONDS -> packet.timestamp.nanosecondsOfSecond / 1000
            PcapTimestampResolution.NANOSECONDS -> packet.timestamp.nanosecondsOfSecond
        }
        record.writeUInt(0, packet.timestamp.epochSeconds)
        record.writeUInt(4, subsecond.toLong())
        record.writeUInt(8, data.size.toLong())
        record.writeUInt(12, originalLength.toLong())
        data.copyInto(record, RECORD_HEADER_SIZE)
        return record
    }

    /** A complete savefile in one buffer: the [fileHeader] followed by a [record] per packet. */
    fun write(packets: Iterable<Packet>): ByteArray {
        val records = packets.map { record(it) }
        val out = ByteArray(GLOBAL_HEADER_SIZE + records.sumOf { it.size })
        var pos = 0
        fileHeader().copyInto(out, pos); pos += GLOBAL_HEADER_SIZE
        for (record in records) {
            record.copyInto(out, pos); pos += record.size
        }
        return out
    }
}
