package dev.jokelbaf.netcap.core.format

import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.TcpFlags
import dev.jokelbaf.netcap.core.protocol.TcpSegment
import dev.jokelbaf.netcap.core.protocol.UdpDatagram
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import dev.jokelbaf.netcap.core.protocol.tcp
import dev.jokelbaf.netcap.core.protocol.udp
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Instant

class PcapFileTest {

    private val sourceIp = byteArrayOf(10, 0, 0, 5)
    private val destIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)

    private fun ethernet(etherType: Int): ByteArray = ByteArray(14).also {
        it[12] = (etherType ushr 8).toByte()
        it[13] = etherType.toByte()
    }

    private fun tcpFrame(): ByteArray = ethernet(0x0800) + TcpSegment.build(
        sourceIp, destIp, 51000, 443, 1000L, 0L, TcpFlags.PSH or TcpFlags.ACK, 65535,
        "GET / HTTP/1.1".encodeToByteArray(),
    )

    private fun udpFrame(): ByteArray = UdpDatagram.build(sourceIp, destIp, 5353, 53, byteArrayOf(1, 2, 3))

    private fun packet(bytes: ByteArray, ts: Instant, link: LinkType): Packet =
        decodedPacket(bytes, ts, PacketDirection.OUTBOUND, "eth0", link)

    @Test
    fun roundTripsEthernetMicroseconds() {
        val ts = Instant.fromEpochSeconds(1_700_000_000, 123_456_000)
        val original = packet(tcpFrame(), ts, LinkType.ETHERNET)

        val bytes = PcapWriter(LinkType.ETHERNET).write(listOf(original))
        val decoded = PcapReader.read(bytes, "file")

        assertEquals(1, decoded.size)
        val p = decoded.single()
        assertContentEquals(original.frame.bytes, p.frame.bytes)
        assertEquals(1_700_000_000, p.timestamp.epochSeconds)
        assertEquals(123_456_000, p.timestamp.nanosecondsOfSecond) // microsecond precision preserved
        assertEquals(PacketDirection.UNKNOWN, p.direction)
        assertEquals("file", p.interfaceName)
        assertEquals(443, assertNotNull(p.tcp).destinationPort)
    }

    @Test
    fun roundTripsRawIpNanoseconds() {
        val ts = Instant.fromEpochSeconds(1_700_000_001, 123_456_789)
        val original = packet(udpFrame(), ts, LinkType.RAW_IP)

        val writer = PcapWriter(LinkType.RAW_IP, resolution = PcapTimestampResolution.NANOSECONDS)
        val decoded = PcapReader.read(writer.write(listOf(original)))

        val p = decoded.single()
        assertEquals(123_456_789, p.timestamp.nanosecondsOfSecond) // full nanosecond precision
        assertEquals(53, assertNotNull(p.udp).destinationPort)
    }

    @Test
    fun parsesHeaderFields() {
        val bytes = PcapWriter(LinkType.ETHERNET, snapLength = 4096).write(emptyList())
        val reader = PcapReader()
        reader.decode(bytes)
        val header = assertNotNull(reader.header)
        assertEquals(LinkType.ETHERNET, header.linkType)
        assertEquals(4096, header.snapLength)
        assertEquals(PcapTimestampResolution.MICROSECONDS, header.resolution)
        assertEquals(2, header.versionMajor)
        assertEquals(4, header.versionMinor)
    }

    @Test
    fun globalHeaderMatchesFormat() {
        val header = PcapWriter(LinkType.ETHERNET, snapLength = 65_536).fileHeader()
        // magic a1b2c3d4, version 2.4, zone 0, sigfigs 0, snaplen 65536, network 1 (LINKTYPE_ETHERNET)
        val expected = byteArrayOf(
            0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte(),
            0x00, 0x02, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        )
        assertContentEquals(expected, header)
    }

    @Test
    fun decodesStreamingInOddChunks() {
        val ts = Instant.fromEpochSeconds(1_700_000_000, 500_000_000)
        val packets = List(5) { packet(tcpFrame(), ts, LinkType.ETHERNET) }
        val bytes = PcapWriter(LinkType.ETHERNET).write(packets)

        val reader = PcapReader()
        val decoded = mutableListOf<Packet>()
        var i = 0
        while (i < bytes.size) {
            val end = minOf(i + 7, bytes.size) // deliberately awkward chunk boundaries
            decoded += reader.decode(bytes.copyOfRange(i, end))
            i = end
        }
        assertEquals(5, decoded.size)
        assertContentEquals(packets.first().frame.bytes, decoded.first().frame.bytes)
    }

    @Test
    fun readsLittleEndianFile() {
        // A hand-built little-endian micro file: header + one 1-byte record at t=1.000002s.
        val le = byteArrayOf(
            0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte(), // swapped magic
            0x02, 0x00, 0x04, 0x00,                                     // version 2.4
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00,                                     // snaplen 262144
            0x65, 0x00, 0x00, 0x00,                                     // network 101 (RAW)
            0x01, 0x00, 0x00, 0x00,                                     // ts_sec = 1
            0x02, 0x00, 0x00, 0x00,                                     // ts_usec = 2
            0x01, 0x00, 0x00, 0x00,                                     // incl_len = 1
            0x01, 0x00, 0x00, 0x00,                                     // orig_len = 1
            0x45,                                                       // 1 payload byte
        )
        val reader = PcapReader()
        val decoded = reader.decode(le)
        assertEquals(LinkType.RAW_IP, assertNotNull(reader.header).linkType)
        val p = decoded.single()
        assertEquals(1, p.timestamp.epochSeconds)
        assertEquals(2_000, p.timestamp.nanosecondsOfSecond) // 2 microseconds
        assertContentEquals(byteArrayOf(0x45), p.frame.bytes)
    }

    @Test
    fun rejectsBadMagic() {
        assertFailsWith<PcapFormatException> {
            PcapReader().decode(ByteArray(GLOBAL_HEADER_SIZE) { 0x00 })
        }
    }

    @Test
    fun writerRejectsUnknownLinkType() {
        assertFailsWith<IllegalArgumentException> { PcapWriter(LinkType.UNKNOWN) }
    }
}
