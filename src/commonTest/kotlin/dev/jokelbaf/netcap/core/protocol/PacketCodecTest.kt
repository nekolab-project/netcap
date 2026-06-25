package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.IpVersion
import dev.jokelbaf.netcap.core.parseIpv4Address
import dev.jokelbaf.netcap.core.parseIpv6Address
import dev.jokelbaf.netcap.core.readIpv6Address
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PacketCodecTest {

    private val src = parseIpv4Address("10.0.0.2")
    private val dst = parseIpv4Address("93.184.216.34")
    private val src6 = assertNotNull(parseIpv6Address("2001:db8::2"))
    private val dst6 = assertNotNull(parseIpv6Address("2606:4700:4700::1111"))

    @Test
    fun ipv4HeaderChecksumIsValid() {
        val packet = Ipv4Packet.build(src, dst, TransportProtocolNumber.TCP, ByteArray(0))
        // The checksum over a header that already contains its checksum is zero.
        assertEquals(0, Checksum.compute(packet, 0, Ipv4Packet.MIN_HEADER_LENGTH))
    }

    @Test
    fun tcpBuildParseRoundTrip() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        val packet = TcpSegment.build(
            sourceBytes = src,
            destinationBytes = dst,
            sourcePort = 44000,
            destinationPort = 443,
            sequenceNumber = 0x11223344L,
            acknowledgementNumber = 0x55667788L,
            flags = TcpFlags.ACK or TcpFlags.PSH,
            windowSize = 65535,
            payload = payload,
        )

        val ip = assertNotNull(Ipv4Packet.parse(packet, packet.size))
        assertEquals("10.0.0.2", ip.sourceAddress)
        assertEquals("93.184.216.34", ip.destinationAddress)
        assertEquals(TransportProtocolNumber.TCP, ip.protocolNumber)

        val tcp = assertNotNull(TcpSegment.parse(packet, ip.transportOffset, ip.transportLength))
        assertEquals(44000, tcp.sourcePort)
        assertEquals(443, tcp.destinationPort)
        assertEquals(0x11223344L, tcp.sequenceNumber)
        assertEquals(0x55667788L, tcp.acknowledgementNumber)
        assertTrue(tcp.isAck)
        assertEquals(payload.size, tcp.payloadLength)
        assertEquals(payload.toList(), packet.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength).toList())

        // The transport checksum over the segment + pseudo-header must fold to zero.
        val pseudo = Checksum.pseudoHeaderSum(src, dst, TransportProtocolNumber.TCP, ip.transportLength)
        assertEquals(0, Checksum.compute(packet, ip.transportOffset, ip.transportLength, pseudo))
    }

    @Test
    fun udpBuildParseRoundTrip() {
        val payload = byteArrayOf(9, 8, 7)
        val packet = UdpDatagram.build(
            sourceBytes = src,
            destinationBytes = dst,
            sourcePort = 5353,
            destinationPort = 53,
            payload = payload,
        )

        val ip = assertNotNull(Ipv4Packet.parse(packet, packet.size))
        assertEquals(TransportProtocolNumber.UDP, ip.protocolNumber)

        val udp = assertNotNull(UdpDatagram.parse(packet, ip.transportOffset, ip.transportLength))
        assertEquals(5353, udp.sourcePort)
        assertEquals(53, udp.destinationPort)
        assertEquals(payload.size, udp.payloadLength)

        val pseudo = Checksum.pseudoHeaderSum(src, dst, TransportProtocolNumber.UDP, ip.transportLength)
        assertEquals(0, Checksum.compute(packet, ip.transportOffset, ip.transportLength, pseudo))
    }

    @Test
    fun parseRejectsNonIpv4() {
        val notIpv4 = ByteArray(40).also { it[0] = 0x60.toByte() } // version 6
        assertEquals(null, Ipv4Packet.parse(notIpv4, notIpv4.size))
    }

    @Test
    fun ipv6AddressRoundTrip() {
        for (address in listOf("::1", "::", "fe80::1", "2001:db8::2", "2606:4700:4700::1111")) {
            val bytes = assertNotNull(parseIpv6Address(address))
            assertEquals(16, bytes.size)
            assertEquals(address, bytes.readIpv6Address(0))
            assertEquals(bytes.toList(), assertNotNull(parseIpv6Address(bytes.readIpv6Address(0))).toList())
        }
        // Leading zeros and full zero groups are canonicalised.
        assertEquals("2001:db8::1", assertNotNull(parseIpv6Address("2001:0db8:0000:0000:0000:0000:0000:0001")).readIpv6Address(0))
    }

    @Test
    fun ipv6TcpBuildParseRoundTrip() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        val packet = TcpSegment.build(
            sourceBytes = src6,
            destinationBytes = dst6,
            sourcePort = 44000,
            destinationPort = 443,
            sequenceNumber = 0x11223344L,
            acknowledgementNumber = 0x55667788L,
            flags = TcpFlags.ACK or TcpFlags.PSH,
            windowSize = 65535,
            payload = payload,
        )

        val ip = assertNotNull(IpPacket.parse(packet, packet.size))
        assertEquals(IpVersion.IPV6, ip.version)
        assertEquals("2001:db8::2", ip.sourceAddress)
        assertEquals("2606:4700:4700::1111", ip.destinationAddress)
        assertEquals(TransportProtocolNumber.TCP, ip.protocolNumber)

        val tcp = assertNotNull(TcpSegment.parse(packet, ip.transportOffset, ip.transportLength))
        assertEquals(44000, tcp.sourcePort)
        assertEquals(443, tcp.destinationPort)
        assertEquals(payload.toList(), packet.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength).toList())

        val pseudo = Checksum.pseudoHeaderSumV6(src6, dst6, TransportProtocolNumber.TCP, ip.transportLength)
        assertEquals(0, Checksum.compute(packet, ip.transportOffset, ip.transportLength, pseudo))
    }

    @Test
    fun ipv6UdpBuildParseRoundTrip() {
        val payload = byteArrayOf(9, 8, 7)
        val packet = UdpDatagram.build(src6, dst6, 5353, 53, payload)

        val ip = assertNotNull(IpPacket.parse(packet, packet.size))
        assertEquals(IpVersion.IPV6, ip.version)
        assertEquals(TransportProtocolNumber.UDP, ip.protocolNumber)

        val udp = assertNotNull(UdpDatagram.parse(packet, ip.transportOffset, ip.transportLength))
        assertEquals(5353, udp.sourcePort)
        assertEquals(53, udp.destinationPort)

        val pseudo = Checksum.pseudoHeaderSumV6(src6, dst6, TransportProtocolNumber.UDP, ip.transportLength)
        assertEquals(0, Checksum.compute(packet, ip.transportOffset, ip.transportLength, pseudo))
    }

    @Test
    fun ipv6SkipsExtensionHeaderToTransport() {
        // 40-byte IPv6 header with next-header = Hop-by-Hop (0), then an 8-byte
        // Hop-by-Hop option whose own next-header is UDP.
        val udp = UdpDatagram.build(src6, dst6, 1000, 2000, byteArrayOf(1))
        val transport = udp.copyOfRange(Ipv6Packet.HEADER_LENGTH, udp.size)
        val withExt = ByteArray(Ipv6Packet.HEADER_LENGTH + 8 + transport.size)
        udp.copyInto(withExt, 0, 0, Ipv6Packet.HEADER_LENGTH)
        withExt[6] = 0 // next header: Hop-by-Hop
        // payload length now covers the extension header + transport
        withExt[4] = ((8 + transport.size) ushr 8).toByte()
        withExt[5] = ((8 + transport.size) and 0xFF).toByte()
        withExt[Ipv6Packet.HEADER_LENGTH] = TransportProtocolNumber.UDP.toByte() // ext next-header
        withExt[Ipv6Packet.HEADER_LENGTH + 1] = 0 // ext length: 0 → 8 bytes
        transport.copyInto(withExt, Ipv6Packet.HEADER_LENGTH + 8)

        val ip = assertNotNull(IpPacket.parse(withExt, withExt.size))
        assertEquals(TransportProtocolNumber.UDP, ip.protocolNumber)
        assertEquals(Ipv6Packet.HEADER_LENGTH + 8, ip.transportOffset)
    }

    private object TransportProtocolNumber {
        const val TCP = 6
        const val UDP = 17
    }
}
