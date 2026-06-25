package dev.jokelbaf.netcap.core.ios

import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.PacketStore
import dev.jokelbaf.netcap.core.LogBuffer
import dev.jokelbaf.netcap.core.stack.SnifferEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import platform.Foundation.NSData

/**
 * The engine driver that runs inside the `NEPacketTunnelProvider` extension.
 *
 * Swift wires the packet flow to it: each IP packet read from the TUN is handed
 * to [receivePacket]; the engine's synthesized responses come back through the
 * [writeToTun] closure (which Swift forwards to `packetFlow.writePackets`).
 * Captured packets and diagnostic logs are pumped into the shared App Group store
 * on a timer so the app process can display them.
 *
 * @param appGroup the App Group id shared by the app and the extension.
 * @param boundInterfaceIndex index of the physical interface upstream sockets
 *   must bind to (so they don't loop back into the tunnel); 0 disables binding.
 * @param writeToTun hands an outbound IP packet back to the system tunnel.
 */
class IosPacketTunnel(
    appGroup: String,
    private val boundInterfaceIndex: Int,
    private val writeToTun: (NSData) -> Unit,
) {
    private val store = PacketStore()
    private val logBuffer = LogBuffer()
    private val sharedStore = IosSharedStore(appGroup)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pumpJob: Job? = null

    private val engine = SnifferEngine(
        // Socket-layer logs flush immediately so the last action before any teardown is captured.
        channelFactory = IosNetworkChannelFactory(boundInterfaceIndex.toUInt()) { line -> diagnostic(line) },
        tunWriter = { packet -> writeToTun(packet.toNSData()) },
        packetSink = store,
        logger = { line -> logBuffer.log(line) },
    )

    fun start() {
        logBuffer.log("engine starting; boundInterfaceIndex=$boundInterfaceIndex")
        engine.start()
        publish(CaptureState.RUNNING)
        pumpJob = scope.launch {
            while (isActive) {
                delay(SNAPSHOT_INTERVAL_MS)
                publish(CaptureState.RUNNING)
            }
        }
    }

    private var firstPacketLogged = false

    /** Feeds one raw IP packet read from the TUN by the Swift provider. */
    fun receivePacket(packet: NSData) {
        val bytes = packet.toByteArray()
        if (!firstPacketLogged) {
            firstPacketLogged = true
            val version = if (bytes.isNotEmpty()) (bytes[0].toInt() ushr 4) and 0xF else 0
            diagnostic("first TUN packet: ${bytes.size} bytes, v$version")
        }
        engine.onTunPacket(bytes, bytes.size)
    }

    /** Logs a line and immediately flushes a snapshot, so it survives an imminent teardown. */
    fun diagnostic(message: String) {
        logBuffer.log(message)
        publish(CaptureState.RUNNING)
    }

    fun stop() {
        pumpJob?.cancel()
        pumpJob = null
        engine.stop()
        publish(CaptureState.IDLE)
        scope.cancel()
    }

    private fun publish(state: CaptureState) {
        sharedStore.write(state, store.totalCount.value, store.packets.value, logBuffer.snapshot())
    }

    private companion object {
        const val SNAPSHOT_INTERVAL_MS = 300L
    }
}
