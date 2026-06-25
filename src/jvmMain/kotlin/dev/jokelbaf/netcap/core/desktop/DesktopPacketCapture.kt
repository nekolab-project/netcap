package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.CaptureStats
import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.net.NetworkInterface
import kotlin.concurrent.thread
import kotlin.time.Instant

/**
 * Passive packet capture for one interface, backed by libpcap/npcap. Unlike the mobile
 * capture there is no TUN or NAT: the OS routes traffic normally and we observe copies.
 * Each frame is copied into an owned buffer and handed to [onPacket] as a lazily-decoded
 * [Packet] (decoding happens only when a layer is accessed); direction is inferred by
 * matching the IP source against the host's own addresses.
 *
 * Capture runs on a dedicated daemon thread; [start] returns once the handle is open.
 */
internal class DesktopPacketCapture(
    private val deviceName: String,
    private val options: CaptureOptions,
    private val onPacket: (Packet) -> Unit,
    private val log: (String) -> Unit,
) {

    @Volatile private var running = false
    @Volatile private var statsSnapshot = CaptureStats()
    private var thread: Thread? = null
    private var arena: Arena? = null
    private var handle: MemorySegment = MemorySegment.NULL

    /** Latest received/dropped counters, refreshed on the capture thread. */
    fun readStats(): CaptureStats = statsSnapshot

    /** Opens the capture handle. Throws [PcapException] if the device can't be opened. */
    fun start() {
        val session = Arena.ofShared()
        arena = session
        val errbuf = session.allocate(Pcap.ERRBUF_SIZE)
        val device = session.allocateFrom(deviceName)
        val promisc = if (options.promiscuous) 1 else 0
        val opened = Pcap.openLive(device, options.snapLength, promisc, TIMEOUT_MS, errbuf)
        if (opened.address() == 0L) {
            val reason = errbuf.getString(0).ifBlank { "Could not open '$deviceName'" }
            session.close()
            arena = null
            throw PcapException(reason)
        }
        handle = opened
        applyFilter(session, opened)
        val datalink = Pcap.dataLink(opened)
        val localAddresses = localAddresses()
        log("Capturing on $deviceName (datalink $datalink, ${localAddresses.size} local IPs)")

        running = true
        thread = thread(name = "pcap-$deviceName", isDaemon = true) {
            captureLoop(session, opened, datalink, localAddresses)
        }
    }

    fun stop() {
        running = false
        val open = handle
        if (open.address() != 0L) Pcap.breakLoop(open)
        thread?.join(STOP_TIMEOUT_MS)
        thread = null
        if (open.address() != 0L) {
            Pcap.close(open)
            handle = MemorySegment.NULL
        }
        arena?.close()
        arena = null
    }

    private fun applyFilter(arena: Arena, handle: MemorySegment) {
        val program = arena.allocate(BPF_PROGRAM_SIZE)
        val expression = arena.allocateFrom(options.filter.toBpf())
        if (Pcap.compile(handle, program, expression, 1, Pcap.NETMASK_UNKNOWN) != 0) {
            log("Filter compile failed (${Pcap.error(handle)}); capturing unfiltered")
            return
        }
        if (Pcap.setFilter(handle, program) != 0) {
            log("setfilter failed (${Pcap.error(handle)}); capturing unfiltered")
        }
        Pcap.freeCode(program)
    }

    private fun captureLoop(arena: Arena, handle: MemorySegment, datalink: Int, localAddresses: Set<List<Byte>>) {
        val headerOut = arena.allocate(ValueLayout.ADDRESS)
        val dataOut = arena.allocate(ValueLayout.ADDRESS)
        val statBuf = arena.allocate(Pcap.STAT_SIZE)
        val linkType = LinkType.fromPcapDatalink(datalink)
        var sinceStats = 0
        while (running) {
            when (Pcap.nextEx(handle, headerOut, dataOut)) {
                1 -> {
                    val header = headerOut.get(ValueLayout.ADDRESS, 0).reinterpret(PKTHDR_SIZE)
                    val caplen = header.get(ValueLayout.JAVA_INT, Pcap.CAPLEN_OFFSET)
                    if (caplen <= 0) continue
                    val frame = dataOut.get(ValueLayout.ADDRESS, 0)
                        .reinterpret(caplen.toLong())
                        .toArray(ValueLayout.JAVA_BYTE)
                    val direction = inferDirection(frame, datalink, localAddresses)
                    onPacket(decodedPacket(frame, readTimestamp(header), direction, deviceName, linkType))
                    if (++sinceStats >= STATS_EVERY) {
                        sinceStats = 0
                        updateStats(handle, statBuf)
                    }
                }
                0 -> updateStats(handle, statBuf) // idle: keep counters fresh, re-check `running`
                -1 -> {
                    log("Capture error: ${Pcap.error(handle)}")
                    return
                }
                else -> return
            }
        }
    }

    /** Reads `pcap_stats` on the capture thread (so no pcap handle is touched concurrently). */
    private fun updateStats(handle: MemorySegment, statBuf: MemorySegment) {
        if (Pcap.stats(handle, statBuf) != 0) return
        statsSnapshot = CaptureStats(
            received = statBuf.get(ValueLayout.JAVA_INT, Pcap.STAT_RECV_OFFSET).toLong() and 0xFFFF_FFFFL,
            dropped = statBuf.get(ValueLayout.JAVA_INT, Pcap.STAT_DROP_OFFSET).toLong() and 0xFFFF_FFFFL,
        )
    }

    /** Reads the per-packet timestamp from a `pcap_pkthdr` (`timeval` widths differ on Windows). */
    private fun readTimestamp(header: MemorySegment): Instant {
        val seconds: Long
        val micros: Long
        if (isWindows) {
            seconds = header.get(ValueLayout.JAVA_INT, 0).toLong()
            micros = header.get(ValueLayout.JAVA_INT, 4).toLong()
        } else {
            seconds = header.get(ValueLayout.JAVA_LONG, 0)
            micros = header.get(ValueLayout.JAVA_LONG, 8)
        }
        return Instant.fromEpochSeconds(seconds, micros * 1_000)
    }

    /** Direction from the IP source address only (cheap — avoids decoding the whole packet). */
    private fun inferDirection(frame: ByteArray, datalink: Int, localAddresses: Set<List<Byte>>): PacketDirection {
        val offset = LinkLayer.ipOffset(datalink, frame)
        if (offset < 0 || offset >= frame.size) return PacketDirection.UNKNOWN
        val source = when (frame[offset].toInt() ushr 4) {
            4 -> if (offset + 16 <= frame.size) frame.copyOfRange(offset + 12, offset + 16) else null
            6 -> if (offset + 24 <= frame.size) frame.copyOfRange(offset + 8, offset + 24) else null
            else -> null
        } ?: return PacketDirection.UNKNOWN
        return if (source.toList() in localAddresses) PacketDirection.OUTBOUND else PacketDirection.INBOUND
    }

    private companion object {
        const val TIMEOUT_MS = 10
        const val STOP_TIMEOUT_MS = 1_000L
        const val PKTHDR_SIZE = 24L
        const val BPF_PROGRAM_SIZE = 16L
        const val STATS_EVERY = 256
    }
}

private fun localAddresses(): Set<List<Byte>> = buildSet {
    runCatching {
        for (nic in NetworkInterface.getNetworkInterfaces()) {
            for (address in nic.inetAddresses) {
                add(address.address.toList())
            }
        }
    }
}
