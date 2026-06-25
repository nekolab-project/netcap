package dev.jokelbaf.netcap.core.ios

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.CaptureStats
import dev.jokelbaf.netcap.core.PacketSniffer
import dev.jokelbaf.netcap.core.matches
import dev.jokelbaf.netcap.core.protocol.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * iOS [PacketSniffer]. Capture runs in the `NEPacketTunnelProvider` extension (a separate
 * process); the app process can only see it through the shared App Group snapshot, which this
 * polls to surface a hot [packets] flow plus [state] and [stats].
 *
 * The VPN profile lifecycle (`NETunnelProviderManager` save/load/start/stop) lives in Swift and
 * is triggered through [onStart]/[onStop].
 *
 * @param appGroup the App Group id shared by the app and the extension.
 * @param options [CaptureOptions.filter] is matched in software against the polled packets; the
 *   other options apply only to desktop capture.
 */
class IosSniffer(
    appGroup: String,
    private val options: CaptureOptions = CaptureOptions(),
    private val onStart: () -> Unit = {},
    private val onStop: () -> Unit = {},
) : PacketSniffer {

    private val sharedStore = IosSharedStore(appGroup)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val _packets = MutableSharedFlow<Packet>(
        extraBufferCapacity = PACKET_BUFFER,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    override val packets: Flow<Packet> = _packets.asSharedFlow()

    private val _state = MutableStateFlow(CaptureState.IDLE)
    override val state = _state.asStateFlow()

    private val _stats = MutableStateFlow(CaptureStats())
    override val stats = _stats.asStateFlow()

    private var pollJob: Job? = null
    private var lastTotal = 0L

    override fun start() {
        _state.value = CaptureState.STARTING
        lastTotal = 0
        onStart()
        pollJob = scope.launch {
            while (isActive) {
                poll()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    override fun stop() {
        _state.value = CaptureState.STOPPING
        onStop()
        pollJob?.cancel()
        pollJob = null
        _state.value = CaptureState.IDLE
    }

    private fun poll() {
        val snapshot = sharedStore.read()

        // The extension publishes RUNNING while alive; hold STARTING until it does.
        if (snapshot.state == CaptureState.RUNNING || _state.value != CaptureState.STARTING) {
            _state.value = snapshot.state
        }
        _stats.value = CaptureStats(received = snapshot.totalCount)

        val newCount = (snapshot.totalCount - lastTotal)
            .coerceIn(0, snapshot.packets.size.toLong())
            .toInt()
        if (newCount > 0) {
            snapshot.packets.takeLast(newCount)
                .filter { it.matches(options.filter) }
                .forEach { _packets.tryEmit(it) }
        }
        lastTotal = snapshot.totalCount
    }

    private companion object {
        const val POLL_INTERVAL_MS = 300L
        const val PACKET_BUFFER = 2048
    }
}
