package dev.jokelbaf.netcap.core

import dev.jokelbaf.netcap.core.protocol.Packet
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * The library's unified capture surface. Construction is platform-specific (a desktop
 * interface, an Android `Context`, an iOS app group), but observation is identical
 * everywhere: collect [packets] (lazily decoded), watch [state] and [stats].
 */
interface PacketSniffer {
    /** The captured packets, as a hot stream. Each [Packet] decodes its layers lazily on access. */
    val packets: Flow<Packet>

    val state: StateFlow<CaptureState>

    /** Running counters (received / dropped). Backends without drop accounting report received only. */
    val stats: StateFlow<CaptureStats>

    fun start()

    fun stop()
}

/** Capture counters. [dropped] is what the backend couldn't keep up with (desktop `pcap_stats`). */
data class CaptureStats(
    val received: Long = 0,
    val dropped: Long = 0,
)
