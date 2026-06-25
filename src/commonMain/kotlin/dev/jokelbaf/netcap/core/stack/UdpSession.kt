package dev.jokelbaf.netcap.core.stack

import dev.jokelbaf.netcap.core.currentTimeMillis
import dev.jokelbaf.netcap.core.net.UdpChannel
import dev.jokelbaf.netcap.core.net.UdpChannelListener
import dev.jokelbaf.netcap.core.protocol.UdpDatagram

/**
 * One UDP NAT flow. Datagrams from the device are relayed to a connected socket
 * on the real destination; replies are wrapped back into IP/UDP packets and
 * written into the TUN. Idle flows are reaped by the engine ticker.
 *
 * Methods run on the engine worker; the [UdpChannelListener] hops replies back
 * onto it via [SnifferEngine.submit].
 */
internal class UdpSession(
    private val engine: SnifferEngine,
    private val key: FlowKey,
    private val clientBytes: ByteArray,
    private val serverBytes: ByteArray,
) {
    private var lastActivityMillis = currentTimeMillis()

    private val channel: UdpChannel = engine.channelFactory.openUdp(
        key.destinationAddress,
        key.destinationPort,
        object : UdpChannelListener {
            override fun onData(data: ByteArray) {
                engine.submit { onRemoteData(data) }
            }

            override fun onError(error: Throwable) {
                engine.submit {
                    close()
                    engine.removeUdp(key)
                }
            }
        },
    )

    fun onClientDatagram(payload: ByteArray) {
        lastActivityMillis = currentTimeMillis()
        channel.send(payload)
    }

    private fun onRemoteData(payload: ByteArray) {
        lastActivityMillis = currentTimeMillis()
        val packet = UdpDatagram.build(
            sourceBytes = serverBytes,
            destinationBytes = clientBytes,
            sourcePort = key.destinationPort,
            destinationPort = key.sourcePort,
            payload = payload,
        )
        engine.deliverInbound(packet)
    }

    fun isIdle(now: Long): Boolean = now - lastActivityMillis > IDLE_TIMEOUT_MS

    fun close() {
        channel.close()
    }

    private companion object {
        const val IDLE_TIMEOUT_MS = 30_000L
    }
}
