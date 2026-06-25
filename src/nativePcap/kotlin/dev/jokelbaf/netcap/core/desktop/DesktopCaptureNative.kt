@file:OptIn(ExperimentalForeignApi::class, DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)

package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.CaptureStats
import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.PacketSniffer
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocPointerTo
import kotlinx.cinterop.convert
import kotlinx.cinterop.cstr
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlin.concurrent.Volatile
import kotlin.time.Instant
import pcap.PCAP_NETMASK_UNKNOWN
import pcap.bpf_program
import pcap.pcap_close
import pcap.pcap_compile
import pcap.pcap_datalink
import pcap.pcap_findalldevs
import pcap.pcap_freealldevs
import pcap.pcap_freecode
import pcap.pcap_geterr
import pcap.pcap_if
import pcap.pcap_next_ex
import pcap.pcap_open_live
import pcap.pcap_pkthdr
import pcap.pcap_setfilter
import pcap.pcap_stat
import pcap.pcap_stats
import pcap.pcap_t

private const val ERRBUF_SIZE = 256
private const val SNAP_TIMEOUT_MS = 10

internal actual fun pcapDevicesImpl(): List<PcapDevice> = memScoped {
    val errbuf = allocArray<ByteVar>(ERRBUF_SIZE)
    val alldevs = allocPointerTo<pcap_if>()
    if (pcap_findalldevs(alldevs.ptr, errbuf) != 0) {
        throw PcapException("pcap_findalldevs failed: ${errbuf.toKString()}")
    }
    val devices = buildList {
        var node = alldevs.value
        while (node != null) {
            val dev = node.pointed
            val name = dev.name?.toKString()
            if (!name.isNullOrEmpty()) add(PcapDevice(name, dev.description?.toKString()))
            node = dev.next
        }
    }
    pcap_freealldevs(alldevs.value)
    devices
}

internal actual fun openPcapSnifferImpl(
    device: String,
    options: CaptureOptions,
    log: (String) -> Unit,
): PacketSniffer = NativePcapSniffer(device, options, log)

private class NativePcapSniffer(
    private val device: String,
    private val options: CaptureOptions,
    private val log: (String) -> Unit,
) : PacketSniffer {

    private val _packets = MutableSharedFlow<Packet>(extraBufferCapacity = 2048)
    override val packets = _packets.asSharedFlow()
    private val _state = MutableStateFlow(CaptureState.IDLE)
    override val state = _state.asStateFlow()
    private val _stats = MutableStateFlow(CaptureStats())
    override val stats = _stats.asStateFlow()

    private var handle: CPointer<pcap_t>? = null
    private var loopContext: kotlinx.coroutines.CloseableCoroutineDispatcher? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile private var running = false

    override fun start() {
        if (_state.value != CaptureState.IDLE) return
        _state.value = CaptureState.STARTING
        val opened = memScoped {
            val errbuf = allocArray<ByteVar>(ERRBUF_SIZE)
            pcap_open_live(device, options.snapLength, if (options.promiscuous) 1 else 0, SNAP_TIMEOUT_MS, errbuf)
                ?: throw PcapException(errbuf.toKString().ifBlank { "Could not open '$device'" })
        }
        handle = opened
        applyFilter(opened, options.filter.toBpf())
        val linkType = LinkType.fromPcapDatalink(pcap_datalink(opened))
        running = true
        _state.value = CaptureState.RUNNING
        val ctx = newSingleThreadContext("pcap-$device")
        loopContext = ctx
        scope.launch(ctx) { captureLoop(opened, linkType) }
    }

    private fun applyFilter(handle: CPointer<pcap_t>, bpf: String) = memScoped {
        val program = alloc<bpf_program>()
        if (pcap_compile(handle, program.ptr, bpf, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            log("filter compile failed (${pcap_geterr(handle)?.toKString()}); capturing unfiltered")
            return@memScoped
        }
        if (pcap_setfilter(handle, program.ptr) != 0) log("setfilter failed")
        pcap_freecode(program.ptr)
    }

    private fun captureLoop(handle: CPointer<pcap_t>, linkType: LinkType) = memScoped {
        val header = allocPointerTo<pcap_pkthdr>()
        val data = allocPointerTo<UByteVar>()
        val stat = alloc<pcap_stat>()
        var sinceStats = 0
        while (running) {
            when (pcap_next_ex(handle, header.ptr, data.ptr)) {
                1 -> {
                    val pkthdr = header.value!!.pointed
                    val caplen = pkthdr.caplen.toInt()
                    if (caplen <= 0) continue
                    val bytes = data.value!!.reinterpret<ByteVar>().readBytes(caplen)
                    val timestamp = Instant.fromEpochSeconds(
                        pkthdr.ts.tv_sec.convert(),
                        pkthdr.ts.tv_usec.convert<Long>() * 1_000,
                    )
                    _packets.tryEmit(decodedPacket(bytes, timestamp, PacketDirection.UNKNOWN, device, linkType))
                    if (++sinceStats >= STATS_EVERY) {
                        sinceStats = 0
                        updateStats(handle, stat)
                    }
                }
                0 -> updateStats(handle, stat)
                else -> running = false
            }
        }
    }

    private fun updateStats(handle: CPointer<pcap_t>, stat: pcap_stat) {
        if (pcap_stats(handle, stat.ptr) == 0) {
            _stats.value = CaptureStats(received = stat.ps_recv.toLong(), dropped = stat.ps_drop.toLong())
        }
    }

    override fun stop() {
        if (_state.value == CaptureState.IDLE) return
        _state.value = CaptureState.STOPPING
        running = false
        handle?.let { pcap_close(it) }
        handle = null
        scope.cancel()
        loopContext?.close()
        loopContext = null
        _state.value = CaptureState.IDLE
    }

    private companion object {
        const val STATS_EVERY = 256
    }
}
