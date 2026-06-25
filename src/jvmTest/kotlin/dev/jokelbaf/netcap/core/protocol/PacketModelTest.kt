package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.parseIpv6Address
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Instant

/** Exercises the lazy layered [Packet] model end-to-end over synthetic frames. */
class PacketModelTest {

    private val sourceIp = byteArrayOf(10, 0, 0, 5)
    private val destIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)
    private val payload = "GET / HTTP/1.1".encodeToByteArray()

    private fun tcp(source: ByteArray = sourceIp, dest: ByteArray = destIp): ByteArray = TcpSegment.build(
        sourceBytes = source,
        destinationBytes = dest,
        sourcePort = 51000,
        destinationPort = 443,
        sequenceNumber = 1000L,
        acknowledgementNumber = 0L,
        flags = TcpFlags.PSH or TcpFlags.ACK,
        windowSize = 65535,
        payload = payload,
    )

    private fun ethernet(etherType: Int): ByteArray = ByteArray(14).also {
        it[12] = (etherType ushr 8).toByte()
        it[13] = etherType.toByte()
    }

    private fun packet(bytes: ByteArray, link: LinkType = LinkType.ETHERNET): Packet =
        decodedPacket(bytes, Instant.fromEpochSeconds(0), PacketDirection.OUTBOUND, "test0", link)

    @Test
    fun decodesEthernetIpv4Tcp() {
        val p = packet(ethernet(ETHERTYPE_IPV4) + tcp())
        assertNotNull(p.ethernet)
        assertEquals("test0", p.interfaceName)
        val ip = assertNotNull(p.ipv4)
        assertEquals("10.0.0.5", ip.sourceAddress)
        assertEquals("93.184.216.34", ip.destinationAddress)
        val t = assertNotNull(p.tcp)
        assertEquals(51000, t.sourcePort)
        assertEquals(443, t.destinationPort)
        assertNull(p.udp)
        assertContentEquals(payload, t.payload.toByteArray())
    }

    @Test
    fun rawIpStartsAtIpNotEthernet() {
        val p = packet(tcp(), LinkType.RAW_IP)
        assertNull(p.ethernet)
        assertNotNull(p.ipv4)
        assertNotNull(p.tcp)
    }

    @Test
    fun decodesUdp() {
        val udp = UdpDatagram.build(sourceIp, destIp, 5353, 53, payload)
        val p = packet(ethernet(ETHERTYPE_IPV4) + udp)
        val u = assertNotNull(p.udp)
        assertEquals(5353, u.sourcePort)
        assertEquals(53, u.destinationPort)
        assertNull(p.tcp)
    }

    @Test
    fun decodesEthernetIpv6() {
        val source6 = assertNotNull(parseIpv6Address("2001:db8::5"))
        val dest6 = assertNotNull(parseIpv6Address("2606:4700:4700::1111"))
        val p = packet(ethernet(ETHERTYPE_IPV6) + tcp(source6, dest6))
        val ip = assertNotNull(p.ipv6)
        assertEquals("2001:db8::5", ip.sourceAddress)
        assertNull(p.ipv4)
        assertEquals(443, assertNotNull(p.tcp).destinationPort)
    }

    @Test
    fun decodesVlanTagged() {
        val vlan = ByteArray(18).also {
            it[12] = 0x81.toByte(); it[13] = 0x00 // 802.1Q TPID
            it[16] = 0x08; it[17] = 0x00          // inner EtherType: IPv4
        }
        val p = packet(vlan + tcp())
        assertEquals(51000, assertNotNull(p.tcp).sourcePort)
    }

    @Test
    fun nonIpEthertypeHasEthernetButNoIp() {
        val p = packet(ethernet(ETHERTYPE_ARP) + tcp())
        assertNotNull(p.ethernet)
        assertNull(p.ip)
        assertNull(p.tcp)
    }

    @Test
    fun toByteArrayCopiesThisLayerOnly() {
        val ipPacket = tcp()
        val p = packet(ethernet(ETHERTYPE_IPV4) + ipPacket)
        assertContentEquals(ipPacket, assertNotNull(p.ip).toByteArray())
        assertEquals(ethernet(ETHERTYPE_IPV4).size + ipPacket.size, p.frame.bytes.size)
    }

    private companion object {
        const val ETHERTYPE_IPV4 = 0x0800
        const val ETHERTYPE_IPV6 = 0x86DD
        const val ETHERTYPE_ARP = 0x0806
    }
}
