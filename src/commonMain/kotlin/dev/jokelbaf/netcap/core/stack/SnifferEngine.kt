package dev.jokelbaf.netcap.core.stack

import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.PacketSink
import dev.jokelbaf.netcap.core.TransportProtocol
import dev.jokelbaf.netcap.core.currentTimeMillis
import dev.jokelbaf.netcap.core.net.NetworkChannelFactory
import dev.jokelbaf.netcap.core.protocol.IpPacket
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.TcpSegment
import dev.jokelbaf.netcap.core.protocol.UdpDatagram
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import kotlin.time.Instant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The platform-agnostic heart of the sniffer.
 *
 * It owns a userspace IPv4 NAT: outbound packets read from the TUN are parsed,
 * captured, and forwarded to the real destination through protected sockets
 * ([NetworkChannelFactory]); the responses are turned back into IP packets,
 * captured, and written into the TUN ([TunWriter]). The device therefore keeps
 * full connectivity while every packet in both directions is observed.
 *
 * All NAT state lives behind a single-consumer mailbox: every mutation runs on
 * one coroutine, so connection state needs no locks even though socket callbacks
 * arrive on many IO threads.
 */
class SnifferEngine(
    internal val channelFactory: NetworkChannelFactory,
    private val tunWriter: TunWriter,
    private val packetSink: PacketSink,
    private val maxSegmentSize: Int = DEFAULT_MSS,
    private val logger: (String) -> Unit = {},
) {
    /** Diagnostic trace hook; routed to the platform log when provided. */
    internal fun trace(message: String) = logger(message)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Closures submitted from any thread, executed serially on the worker.
    private val mailbox = Channel<() -> Unit>(Channel.UNLIMITED)

    // Inbound packets are written off the worker so a blocking TUN write never
    // stalls NAT processing; a single consumer keeps them in order.
    private val tunOutbox = Channel<ByteArray>(Channel.UNLIMITED)

    private val tcpConnections = HashMap<FlowKey, TcpConnection>()
    private val udpSessions = HashMap<FlowKey, UdpSession>()

    internal val mss: Int get() = maxSegmentSize

    fun start() {
        scope.launch { runMailbox() }
        scope.launch { runTunWriter() }
        scope.launch { runTicker() }
    }

    fun stop() {
        submit {
            tcpConnections.values.toList().forEach { it.abort() }
            tcpConnections.clear()
            udpSessions.values.toList().forEach { it.close() }
            udpSessions.clear()
        }
        mailbox.close()
        tunOutbox.close()
        scope.cancel()
    }

    /**
     * Feeds one raw IP packet read from the TUN (device → internet). The bytes
     * are copied because the caller reuses its read buffer.
     */
    fun onTunPacket(buffer: ByteArray, length: Int) {
        val copy = buffer.copyOf(length)
        submit { handleOutbound(copy) }
    }

    // region worker plumbing

    internal fun submit(task: () -> Unit) {
        mailbox.trySend(task)
    }

    private suspend fun runMailbox() {
        for (task in mailbox) {
            runCatching { task() }
        }
    }

    private suspend fun runTunWriter() {
        for (packet in tunOutbox) {
            runCatching { tunWriter.writePacket(packet) }
        }
    }

    private suspend fun runTicker() {
        while (scope.isActive) {
            delay(TICK_INTERVAL_MS)
            submit { onTick() }
        }
    }

    private fun onTick() {
        val now = currentTimeMillis()
        tcpConnections.values.toList().forEach { it.onTick(now) }
        udpSessions.entries.toList().forEach { (key, session) ->
            if (session.isIdle(now)) {
                session.close()
                udpSessions.remove(key)
            }
        }
    }

    // endregion

    // region engine context used by connections (always called on the worker)

    /** Captures a synthesized inbound packet and queues it for the TUN. */
    internal fun deliverInbound(packet: ByteArray) {
        capture(packet, packet.size, PacketDirection.INBOUND)
        tunOutbox.trySend(packet)
    }

    internal fun removeTcp(key: FlowKey) {
        tcpConnections.remove(key)
    }

    internal fun removeUdp(key: FlowKey) {
        udpSessions.remove(key)
    }

    // endregion

    private fun handleOutbound(packet: ByteArray) {
        val ip = IpPacket.parse(packet, packet.size) ?: return
        when (TransportProtocol.fromNumber(ip.protocolNumber)) {
            TransportProtocol.TCP -> {
                val tcp = TcpSegment.parse(packet, ip.transportOffset, ip.transportLength) ?: return
                capture(packet, packet.size, PacketDirection.OUTBOUND)
                dispatchTcp(ip, tcp, packet)
            }
            TransportProtocol.UDP -> {
                val udp = UdpDatagram.parse(packet, ip.transportOffset, ip.transportLength) ?: return
                capture(packet, packet.size, PacketDirection.OUTBOUND)
                dispatchUdp(ip, udp, packet)
            }
            else -> Unit // Non-TCP/UDP (e.g. ICMP) is not forwarded.
        }
    }

    private fun dispatchTcp(ip: IpPacket, tcp: TcpSegment, packet: ByteArray) {
        val key = FlowKey(
            TransportProtocol.TCP,
            ip.sourceAddress, tcp.sourcePort,
            ip.destinationAddress, tcp.destinationPort,
        )
        val connection = tcpConnections[key]
        if (connection == null) {
            // A new connection only begins with a lone SYN; ignore strays.
            if (!tcp.isSyn || tcp.isAck) return
            trace("TCP new ${key.destinationAddress}:${key.destinationPort} (active=${tcpConnections.size})")
            val created = TcpConnection(this, key, ip.sourceBytes, ip.destinationBytes)
            tcpConnections[key] = created
            created.onClientSegment(tcp, packet)
        } else {
            connection.onClientSegment(tcp, packet)
        }
    }

    private fun dispatchUdp(ip: IpPacket, udp: UdpDatagram, packet: ByteArray) {
        val key = FlowKey(
            TransportProtocol.UDP,
            ip.sourceAddress, udp.sourcePort,
            ip.destinationAddress, udp.destinationPort,
        )
        val session = udpSessions.getOrPut(key) {
            UdpSession(this, key, ip.sourceBytes, ip.destinationBytes)
        }
        val payload = packet.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
        session.onClientDatagram(payload)
    }

    /**
     * Captures one raw IP packet. The bytes are copied into an owned frame and wrapped in a
     * lazily-decoded [dev.jokelbaf.netcap.core.protocol.Packet]; no parsing happens here — the
     * NAT already parsed for forwarding, and the public packet decodes on demand when observed.
     */
    private fun capture(buffer: ByteArray, length: Int, direction: PacketDirection) {
        packetSink.onPacketCaptured(
            decodedPacket(
                bytes = buffer.copyOf(length),
                timestamp = Instant.fromEpochMilliseconds(currentTimeMillis()),
                direction = direction,
                interfaceName = null,
                linkType = LinkType.RAW_IP,
            ),
        )
    }

    companion object {
        /** IP MTU minus 20-byte IPv4 and 20-byte TCP headers. */
        private const val DEFAULT_MSS = 1460
        private const val TICK_INTERVAL_MS = 250L
    }
}
