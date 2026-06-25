package dev.jokelbaf.netcap.core.protocol

/**
 * The link layer a captured frame starts at, which determines how its first [Payload] layer
 * is decoded. Desktop backends derive it from the pcap datalink type; the mobile TUN delivers
 * raw IP packets ([RAW_IP]).
 */
enum class LinkType {
    ETHERNET,
    RAW_IP,
    LINUX_SLL,
    LINUX_SLL2,
    NULL,
    LOOP,
    UNKNOWN;

    /**
     * The `LINKTYPE_*` value written to a pcap savefile's header. These differ from the live
     * `pcap_datalink` (DLT) values for some types — notably raw IP, which is `LINKTYPE_RAW` (101)
     * in a savefile but DLT 12/14 live. [UNKNOWN] has no representation and must not be written.
     */
    val fileLinkType: Int
        get() = when (this) {
            ETHERNET -> 1
            NULL -> 0
            LOOP -> 108
            RAW_IP -> 101
            LINUX_SLL -> 113
            LINUX_SLL2 -> 276
            UNKNOWN -> error("LinkType.UNKNOWN has no savefile LINKTYPE")
        }

    companion object {
        /** Maps a libpcap/npcap `pcap_datalink` value to a [LinkType]. */
        fun fromPcapDatalink(datalink: Int): LinkType = when (datalink) {
            1 -> ETHERNET
            0 -> NULL
            108 -> LOOP
            12, 14, 101 -> RAW_IP
            113 -> LINUX_SLL
            276 -> LINUX_SLL2
            else -> UNKNOWN
        }

        /** Maps a pcap savefile header's `LINKTYPE_*` value to a [LinkType]. */
        fun fromFileLinkType(linkType: Int): LinkType = when (linkType) {
            1 -> ETHERNET
            0 -> NULL
            108 -> LOOP
            12, 14, 101 -> RAW_IP
            113 -> LINUX_SLL
            276 -> LINUX_SLL2
            else -> UNKNOWN
        }
    }
}

/** Decodes the first [Payload] layer of a frame at [offset] in [buffer], per its [linkType]. */
internal fun decodeLink(buffer: ByteArray, offset: Int, length: Int, linkType: LinkType): Payload {
    val end = offset + length
    fun ip(start: Int): Payload {
        if (start > end) return RawPayload(buffer, offset, length)
        return IpPacket.parse(buffer, start, end - start) ?: RawPayload(buffer, start, end - start)
    }
    return when (linkType) {
        LinkType.ETHERNET -> EthernetFrame(buffer, offset, length)
        LinkType.RAW_IP, LinkType.UNKNOWN -> ip(offset)
        LinkType.NULL, LinkType.LOOP -> ip(offset + 4)
        LinkType.LINUX_SLL -> ip(offset + 16)
        LinkType.LINUX_SLL2 -> ip(offset + 20)
    }
}
