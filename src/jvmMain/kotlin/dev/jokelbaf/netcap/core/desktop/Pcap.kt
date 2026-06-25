package dev.jokelbaf.netcap.core.desktop

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

private val osName: String = System.getProperty("os.name").lowercase()
internal val isWindows: Boolean = osName.contains("win")
internal val isMac: Boolean = osName.contains("mac") || osName.contains("darwin")

/**
 * Hand-written Foreign Function & Memory bindings to libpcap (Linux/macOS) and
 * npcap's `wpcap` (Windows). Only the handful of functions the sniffer needs are
 * bound; the surface is small and stable, so no code generation is involved.
 *
 * The native library is resolved at runtime — there is nothing to vendor or link
 * at build time. All entry points are thin: callers pass [MemorySegment]s they own
 * and receive Kotlin types back.
 */
internal object Pcap {

    const val ERRBUF_SIZE = 256L
    const val SNAPLEN = 262_144
    const val NETMASK_UNKNOWN = -1 // PCAP_NETMASK_UNKNOWN (0xffffffff)

    // struct pcap_stat { u_int ps_recv; u_int ps_drop; u_int ps_ifdrop; … }
    const val STAT_SIZE = 16L
    const val STAT_RECV_OFFSET = 0L
    const val STAT_DROP_OFFSET = 4L

    /** `pcap_pkthdr.caplen` byte offset: 8 on Windows (32-bit `long` in `timeval`), 16 elsewhere. */
    val CAPLEN_OFFSET: Long = if (isWindows) 8L else 16L

    private val linker = Linker.nativeLinker()
    private val lookup: SymbolLookup = run {
        val base = if (isWindows) "wpcap" else "pcap"
        // The OS loader wants the real file name, e.g. libpcap.so / libpcap.dylib / wpcap.dll.
        // Fall back to the versioned soname for systems without the -dev symlink.
        val candidates = buildList {
            add(System.mapLibraryName(base))
            if (!isWindows && !isMac) add(System.mapLibraryName(base) + ".1")
        }
        val arena = Arena.global()
        candidates.firstNotNullOfOrNull { name ->
            runCatching { SymbolLookup.libraryLookup(name, arena) }.getOrNull()
        } ?: throw PcapException(
            "Could not load native capture library '$base'. " +
                if (isWindows) "Install Npcap (https://npcap.com)." else "Install libpcap.",
        )
    }

    private fun bind(symbol: String, descriptor: FunctionDescriptor): MethodHandle {
        val address = lookup.find(symbol)
            .orElseThrow { PcapException("Native symbol not found: $symbol") }
        return linker.downcallHandle(address, descriptor)
    }

    private val A = ValueLayout.ADDRESS
    private val I = ValueLayout.JAVA_INT

    private val findAllDevsHandle = bind("pcap_findalldevs", FunctionDescriptor.of(I, A, A))
    private val freeAllDevsHandle = bind("pcap_freealldevs", FunctionDescriptor.ofVoid(A))
    private val openLiveHandle = bind("pcap_open_live", FunctionDescriptor.of(A, A, I, I, I, A))
    private val dataLinkHandle = bind("pcap_datalink", FunctionDescriptor.of(I, A))
    private val compileHandle = bind("pcap_compile", FunctionDescriptor.of(I, A, A, A, I, I))
    private val setFilterHandle = bind("pcap_setfilter", FunctionDescriptor.of(I, A, A))
    private val freeCodeHandle = bind("pcap_freecode", FunctionDescriptor.ofVoid(A))
    private val nextExHandle = bind("pcap_next_ex", FunctionDescriptor.of(I, A, A, A))
    private val statsHandle = bind("pcap_stats", FunctionDescriptor.of(I, A, A))
    private val getErrHandle = bind("pcap_geterr", FunctionDescriptor.of(A, A))
    private val breakLoopHandle = bind("pcap_breakloop", FunctionDescriptor.ofVoid(A))
    private val closeHandle = bind("pcap_close", FunctionDescriptor.ofVoid(A))

    fun findAllDevs(alldevsp: MemorySegment, errbuf: MemorySegment): Int =
        findAllDevsHandle.invokeExact(alldevsp, errbuf) as Int

    fun freeAllDevs(devices: MemorySegment) {
        freeAllDevsHandle.invokeExact(devices)
    }

    fun openLive(device: MemorySegment, snaplen: Int, promisc: Int, toMs: Int, errbuf: MemorySegment): MemorySegment =
        openLiveHandle.invokeExact(device, snaplen, promisc, toMs, errbuf) as MemorySegment

    fun dataLink(handle: MemorySegment): Int = dataLinkHandle.invokeExact(handle) as Int

    fun compile(handle: MemorySegment, program: MemorySegment, filter: MemorySegment, optimize: Int, netmask: Int): Int =
        compileHandle.invokeExact(handle, program, filter, optimize, netmask) as Int

    fun setFilter(handle: MemorySegment, program: MemorySegment): Int =
        setFilterHandle.invokeExact(handle, program) as Int

    fun freeCode(program: MemorySegment) {
        freeCodeHandle.invokeExact(program)
    }

    fun nextEx(handle: MemorySegment, header: MemorySegment, data: MemorySegment): Int =
        nextExHandle.invokeExact(handle, header, data) as Int

    /** Fills [stat] (a `struct pcap_stat`, [STAT_SIZE] bytes) with received/dropped counters. */
    fun stats(handle: MemorySegment, stat: MemorySegment): Int =
        statsHandle.invokeExact(handle, stat) as Int

    fun error(handle: MemorySegment): String =
        (getErrHandle.invokeExact(handle) as MemorySegment).reinterpret(ERRBUF_SIZE).getString(0)

    fun breakLoop(handle: MemorySegment) {
        breakLoopHandle.invokeExact(handle)
    }

    fun close(handle: MemorySegment) {
        closeHandle.invokeExact(handle)
    }
}
