package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.CaptureStats
import dev.jokelbaf.netcap.core.PacketSniffer
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
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The desktop [PacketSniffer], backed by libpcap/npcap on one interface. Packets flow from a
 * dedicated capture thread into a hot [packets] stream; [stats] is polled from `pcap_stats`.
 *
 * @throws PcapException from [start] if the device can't be opened (e.g. missing permissions).
 */
class DesktopSniffer(
    private val deviceName: String,
    private val options: CaptureOptions = CaptureOptions(),
    private val log: (String) -> Unit = {},
) : PacketSniffer {

    private val _packets = MutableSharedFlow<Packet>(extraBufferCapacity = PACKET_BUFFER, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    override val packets: Flow<Packet> = _packets.asSharedFlow()

    private val _state = MutableStateFlow(CaptureState.IDLE)
    override val state: StateFlow<CaptureState> = _state.asStateFlow()

    private val _stats = MutableStateFlow(CaptureStats())
    override val stats: StateFlow<CaptureStats> = _stats.asStateFlow()

    private var capture: DesktopPacketCapture? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var statsJob: Job? = null

    override fun start() {
        if (_state.value != CaptureState.IDLE) return
        _state.value = CaptureState.STARTING
        try {
            capture = DesktopPacketCapture(deviceName, options, { _packets.tryEmit(it) }, log).also { it.start() }
            _state.value = CaptureState.RUNNING
            statsJob = scope.launch {
                while (isActive) {
                    delay(STATS_POLL_MS)
                    _stats.value = capture?.readStats() ?: CaptureStats()
                }
            }
        } catch (e: Throwable) {
            capture = null
            _state.value = CaptureState.IDLE
            throw e
        }
    }

    override fun stop() {
        if (_state.value == CaptureState.IDLE) return
        _state.value = CaptureState.STOPPING
        statsJob?.cancel()
        statsJob = null
        capture?.stop()
        capture = null
        _stats.value = capture?.readStats() ?: _stats.value
        _state.value = CaptureState.IDLE
    }

    private companion object {
        const val PACKET_BUFFER = 2048
        const val STATS_POLL_MS = 1_000L
    }
}
