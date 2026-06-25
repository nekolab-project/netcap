package dev.jokelbaf.netcap.core

import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.TcpFlags
import dev.jokelbaf.netcap.core.protocol.TcpSegment
import dev.jokelbaf.netcap.core.protocol.UdpDatagram
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Instant

/** Verifies the software [CaptureFilter] matcher used by the mobile backends. */
class CaptureFilterTest {

    private val sourceIp = byteArrayOf(10, 0, 0, 5)
    private val destIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)

    private fun tcp443(): Packet = packet(
        TcpSegment.build(sourceIp, destIp, 51000, 443, 1000L, 0L, TcpFlags.ACK, 65535, ByteArray(0)),
    )

    private fun udp53(): Packet = packet(
        UdpDatagram.build(sourceIp, destIp, 5353, 53, ByteArray(0)),
    )

    private fun packet(bytes: ByteArray): Packet =
        decodedPacket(bytes, Instant.fromEpochSeconds(0), PacketDirection.OUTBOUND, null, LinkType.RAW_IP)

    @Test
    fun nullFilterPassesEverything() {
        assertTrue(tcp443().matches(null))
        assertTrue(udp53().matches(null))
    }

    @Test
    fun bpfIsNotMatchedInSoftware() {
        assertTrue(tcp443().matches(CaptureFilter.Bpf("udp port 53")))
    }

    @Test
    fun protocolRuleFilters() {
        val tcpOnly = CaptureFilter.Rules(protocols = setOf(TransportProtocol.TCP))
        assertTrue(tcp443().matches(tcpOnly))
        assertFalse(udp53().matches(tcpOnly))
    }

    @Test
    fun portRuleMatchesEitherEnd() {
        val port443 = CaptureFilter.Rules(ports = setOf(443))
        assertTrue(tcp443().matches(port443))
        assertFalse(udp53().matches(port443))
    }

    @Test
    fun hostRuleMatchesEitherEnd() {
        val byDest = CaptureFilter.Rules(hosts = setOf("93.184.216.34"))
        assertTrue(tcp443().matches(byDest))
        assertFalse(tcp443().matches(CaptureFilter.Rules(hosts = setOf("1.2.3.4"))))
    }

    @Test
    fun rulesAreConjunctive() {
        val tcpAnd53 = CaptureFilter.Rules(protocols = setOf(TransportProtocol.TCP), ports = setOf(53))
        assertFalse(tcp443().matches(tcpAnd53))
        assertFalse(udp53().matches(tcpAnd53))
    }
}
