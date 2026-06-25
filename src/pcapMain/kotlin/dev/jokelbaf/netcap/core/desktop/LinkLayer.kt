package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.readUShort

/**
 * Maps a libpcap data-link type (`pcap_datalink`) to the byte offset of the IPv4
 * header inside a captured frame, or -1 when the frame doesn't carry IPv4 and
 * should be skipped. Covers the link types seen on desktop interfaces; the
 * downstream [dev.jokelbaf.netcap.core.protocol.Ipv4Packet] parser revalidates,
 * so an unexpected layout degrades to a skipped packet rather than a bad parse.
 */
internal object LinkLayer {

    private const val DLT_NULL = 0
    private const val DLT_EN10MB = 1
    private const val DLT_RAW = 12
    private const val DLT_RAW_LINKTYPE = 101
    private const val DLT_LOOP = 108
    private const val DLT_LINUX_SLL = 113
    private const val DLT_LINUX_SLL2 = 276

    private const val ETHERTYPE_IPV4 = 0x0800
    private const val ETHERTYPE_IPV6 = 0x86DD
    private const val ETHERTYPE_VLAN = 0x8100
    private const val ETHERTYPE_QINQ = 0x88A8

    fun ipOffset(datalink: Int, frame: ByteArray): Int = when (datalink) {
        DLT_RAW, DLT_RAW_LINKTYPE -> 0
        DLT_NULL, DLT_LOOP -> if (frame.size >= 4) 4 else -1
        DLT_EN10MB -> ethernetOffset(frame)
        DLT_LINUX_SLL -> if (frame.size >= 16 && isIp(frame.readUShort(14))) 16 else -1
        DLT_LINUX_SLL2 -> if (frame.size >= 20 && isIp(frame.readUShort(0))) 20 else -1
        else -> -1
    }

    private fun ethernetOffset(frame: ByteArray): Int {
        if (frame.size < 14) return -1
        return when (frame.readUShort(12)) {
            ETHERTYPE_IPV4, ETHERTYPE_IPV6 -> 14
            ETHERTYPE_VLAN, ETHERTYPE_QINQ ->
                if (frame.size >= 18 && isIp(frame.readUShort(16))) 18 else -1
            else -> -1
        }
    }

    private fun isIp(etherType: Int): Boolean = etherType == ETHERTYPE_IPV4 || etherType == ETHERTYPE_IPV6
}
