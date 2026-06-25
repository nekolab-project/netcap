package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.readUShort

/**
 * A read-only Ethernet ([dev.jokelbaf.netcap.core.protocol.Payload]) view at [frameOffset]
 * in [buffer]. [payload] decodes the upper layer lazily — IPv4/IPv6 (skipping any 802.1Q/ad
 * VLAN tags), or a [RawPayload] for protocols we don't decode yet (e.g. ARP).
 */
class EthernetFrame internal constructor(
    private val buffer: ByteArray,
    private val frameOffset: Int,
    private val frameLength: Int,
) : Payload, Sliceable {

    val destinationMac: MacAddress get() = MacAddress(buffer, frameOffset)
    val sourceMac: MacAddress get() = MacAddress(buffer, frameOffset + 6)

    /** The EtherType field (may be a VLAN TPID — see [payload] which skips tags). */
    val etherType: Int get() = buffer.readUShort(frameOffset + 12)

    val payload: Payload by lazy { decodeUpper() }

    override fun slice(): ByteArray = buffer.copyOfRange(frameOffset, frameOffset + frameLength)

    private fun decodeUpper(): Payload {
        val end = frameOffset + frameLength
        var typeOffset = frameOffset + 12
        while (typeOffset + 4 <= end) {
            val tpid = buffer.readUShort(typeOffset)
            if (tpid != VLAN && tpid != QINQ) break
            typeOffset += 4
        }
        if (typeOffset + 2 > end) return RawPayload(buffer, frameOffset, frameLength)
        val type = buffer.readUShort(typeOffset)
        val ipStart = typeOffset + 2
        return when (type) {
            IPV4, IPV6 -> IpPacket.parse(buffer, ipStart, end - ipStart) ?: RawPayload(buffer, ipStart, end - ipStart)
            else -> RawPayload(buffer, ipStart, end - ipStart) // ARP, etc. — not decoded yet
        }
    }

    companion object {
        const val HEADER_LENGTH = 14
        private const val IPV4 = 0x0800
        private const val IPV6 = 0x86DD
        private const val VLAN = 0x8100
        private const val QINQ = 0x88A8
    }
}
