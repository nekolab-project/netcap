package dev.jokelbaf.netcap.core.android

import dev.jokelbaf.netcap.core.CaptureFilter
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.LogBuffer
import dev.jokelbaf.netcap.core.PacketSink
import dev.jokelbaf.netcap.core.PacketStore
import dev.jokelbaf.netcap.core.matches
import dev.jokelbaf.netcap.core.protocol.Packet
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Process-wide capture state shared between the [SnifferVpnService] (which runs the engine) and
 * [AndroidSniffer], both living in the same process. In-process capture makes a singleton the
 * simplest correct option.
 */
internal object AndroidCapture {
    val store = PacketStore()
    val state = MutableStateFlow(CaptureState.IDLE)
    val logs = LogBuffer()

    /** Hot per-packet stream backing [AndroidSniffer]'s unified [Packet] flow. */
    val packets = MutableSharedFlow<Packet>(
        extraBufferCapacity = PACKET_BUFFER,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /** The active software filter, applied at the single capture entry point. */
    @Volatile
    var filter: CaptureFilter? = null

    /** The engine's sink: filters once, then fans out to the UI store and the hot flow. */
    val sink = PacketSink { packet ->
        if (packet.matches(filter)) {
            store.onPacketCaptured(packet)
            packets.tryEmit(packet)
        }
    }

    private const val PACKET_BUFFER = 2048
}
