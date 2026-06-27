package dev.jokelbaf.netcap.core.format

import dev.jokelbaf.netcap.core.protocol.LinkType

/**
 * Read/write support for the classic libpcap savefile format (`.pcap`) - the format `tcpdump -w`
 * produces and Wireshark reads natively.
 *
 * The library only ever encodes and decodes bytes; it never opens, reads or writes files. Feed
 * [PcapReader] the bytes you read from a file and hand the bytes from [PcapWriter] to your own
 * writer, using whatever I/O your platform provides.
 */

/** Timestamp precision of a pcap savefile, selected by its magic number. */
enum class PcapTimestampResolution { MICROSECONDS, NANOSECONDS }

/** The 24-byte global header at the start of a pcap savefile. */
data class PcapFileHeader(
    val linkType: LinkType,
    val snapLength: Int,
    val resolution: PcapTimestampResolution,
    val versionMajor: Int = PCAP_VERSION_MAJOR,
    val versionMinor: Int = PCAP_VERSION_MINOR,
)

/** Thrown when bytes handed to [PcapReader] are not a valid pcap savefile. */
class PcapFormatException(message: String) : RuntimeException(message)

internal const val PCAP_VERSION_MAJOR = 2
internal const val PCAP_VERSION_MINOR = 4

internal const val GLOBAL_HEADER_SIZE = 24
internal const val RECORD_HEADER_SIZE = 16

/** Magic for microsecond timestamps, big-endian. The little-endian file starts with the reverse. */
internal const val MAGIC_MICROS = 0xA1B2C3D4L

/** Magic for nanosecond timestamps (RFC: 0xa1b23c4d). */
internal const val MAGIC_NANOS = 0xA1B23C4DL

/** Guards against allocating on a corrupt record length. */
internal const val MAX_RECORD_LENGTH = 1 shl 24
