package dev.jokelbaf.netcap.core.stack

import dev.jokelbaf.netcap.core.currentTimeMillis
import dev.jokelbaf.netcap.core.net.TcpChannel
import dev.jokelbaf.netcap.core.net.TcpChannelListener
import dev.jokelbaf.netcap.core.protocol.TcpFlags
import dev.jokelbaf.netcap.core.protocol.TcpSegment
import kotlin.random.Random

/**
 * A userspace TCP endpoint for one connection. To the device app we impersonate
 * the real server (completing the handshake, ACKing data, sending the server's
 * bytes back); to the internet we open a real socket and relay bytes both ways.
 *
 * The link between the app and this endpoint runs over the TUN, which is
 * effectively lossless, and the real internet leg has its own kernel TCP doing
 * congestion control and retransmission. That lets this implementation stay
 * compact: it tracks sequence/ack state and the peer window, retransmits its own
 * unacked segments on a coarse timer, and otherwise leans on those two reliable
 * legs. All methods run on the engine worker.
 */
internal class TcpConnection(
    private val engine: SnifferEngine,
    private val key: FlowKey,
    private val clientBytes: ByteArray,
    private val serverBytes: ByteArray,
) {
    private class OutSegment(val seq: Long, val data: ByteArray)

    // Our send side (server → app), in our sequence space.
    private var sendIsn = 0L
    private var sendNext = 0L
    private var sendUnacked = 0L

    // Our receive side (app → server): the next byte we expect; doubles as our ACK.
    private var recvNext = 0L

    private var peerWindow = INITIAL_WINDOW
    private var established = false
    private var synAckSent = false
    private var remoteConnected = false

    private var appFinReceived = false
    private var remoteEof = false
    private var finSent = false
    private var finAcked = false
    private var finSeq = 0L

    private var closed = false
    private var channelOpened = false

    private var lastSendMillis = 0L
    private var retransmits = 0

    // IPv6's header is 20 bytes larger than IPv4's, so our segments must be smaller to fit the MTU.
    private val maxSegment = engine.mss - if (clientBytes.size == IPV6_ADDRESS_SIZE) IPV6_HEADER_OVERHEAD else 0

    private val unsentToApp = ArrayDeque<ByteArray>()
    private val unackedSegments = ArrayDeque<OutSegment>()
    private val pendingToRemote = ArrayDeque<ByteArray>()

    private lateinit var channel: TcpChannel

    fun onClientSegment(tcp: TcpSegment, packet: ByteArray) {
        if (closed) return
        peerWindow = tcp.windowSize

        if (tcp.isRst) {
            finish()
            return
        }

        // Initial SYN (or a retransmit of it before the handshake completes).
        if (tcp.isSyn && !tcp.isAck) {
            handleSyn(tcp)
            return
        }

        if (tcp.isAck) processAck(tcp.acknowledgementNumber)

        if (tcp.payloadLength > 0) processIncomingData(tcp, packet)

        if (tcp.isFin) processFin(tcp)

        checkTeardown()
    }

    private fun handleSyn(tcp: TcpSegment) {
        if (synAckSent) {
            // Retransmitted SYN: re-send our SYN-ACK.
            sendSegment(sendIsn, recvNext, TcpFlags.SYN or TcpFlags.ACK)
            return
        }
        recvNext = Seq.add(tcp.sequenceNumber, 1)
        sendIsn = Random.nextLong(0, 0x1_0000_0000L)
        sendNext = sendIsn
        sendUnacked = sendIsn
        synAckSent = true

        sendSegment(sendNext, recvNext, TcpFlags.SYN or TcpFlags.ACK)
        sendNext = Seq.add(sendNext, 1) // SYN consumes one sequence number

        openRemote()
    }

    private fun openRemote() {
        if (channelOpened) return
        channelOpened = true
        channel = engine.channelFactory.openTcp(
            key.destinationAddress,
            key.destinationPort,
            object : TcpChannelListener {
                override fun onConnected() = engine.submit { onRemoteConnected() }
                override fun onData(data: ByteArray) = engine.submit { onRemoteData(data) }
                override fun onClosed() = engine.submit { onRemoteClosed() }
                override fun onError(error: Throwable) = engine.submit { reset() }
            },
        )
    }

    private fun processAck(ackNumber: Long) {
        // Mark the handshake complete once our SYN-ACK is acknowledged.
        if (!established && Seq.leq(Seq.add(sendIsn, 1), ackNumber)) {
            established = true
            engine.trace("TCP ${key.destinationAddress}:${key.destinationPort} established")
        }

        if (seqGt(ackNumber, sendUnacked) && Seq.leq(ackNumber, sendNext)) {
            trimAcked(ackNumber)
            sendUnacked = ackNumber
            retransmits = 0
            if (finSent && ackNumber == Seq.add(finSeq, 1)) finAcked = true
        }
        flushToApp()
    }

    private fun trimAcked(ackNumber: Long) {
        while (unackedSegments.isNotEmpty()) {
            val seg = unackedSegments.first()
            val segEnd = Seq.add(seg.seq, seg.data.size)
            if (Seq.leq(segEnd, ackNumber)) {
                unackedSegments.removeFirst()
            } else if (seqGt(ackNumber, seg.seq)) {
                // Partially acked: trim the acknowledged prefix.
                val consumed = ((ackNumber - seg.seq) and Seq.MASK).toInt()
                unackedSegments.removeFirst()
                unackedSegments.addFirst(OutSegment(ackNumber, seg.data.copyOfRange(consumed, seg.data.size)))
                break
            } else {
                break
            }
        }
    }

    private fun processIncomingData(tcp: TcpSegment, packet: ByteArray) {
        if (tcp.sequenceNumber == recvNext) {
            val payload = packet.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength)
            deliverToRemote(payload)
            recvNext = Seq.add(recvNext, tcp.payloadLength)
        }
        // Duplicate/old or out-of-order: just (re-)acknowledge what we have.
        sendPureAck()
    }

    private fun deliverToRemote(payload: ByteArray) {
        if (remoteConnected) {
            channel.send(payload)
        } else {
            pendingToRemote.addLast(payload)
        }
    }

    private fun onRemoteConnected() {
        if (closed) return
        remoteConnected = true
        engine.trace("TCP ${key.destinationAddress}:${key.destinationPort} remote connected, flushing ${pendingToRemote.size}")
        while (pendingToRemote.isNotEmpty()) {
            channel.send(pendingToRemote.removeFirst())
        }
    }

    private fun onRemoteData(data: ByteArray) {
        if (closed) return
        unsentToApp.addLast(data)
        flushToApp()
    }

    private fun onRemoteClosed() {
        if (closed) return
        engine.trace("TCP ${key.destinationAddress}:${key.destinationPort} remote EOF")
        remoteEof = true
        flushToApp()
    }

    private fun processFin(tcp: TcpSegment) {
        // The FIN occupies the sequence number right after any payload it carried.
        val finSeqNumber = Seq.add(tcp.sequenceNumber, tcp.payloadLength)
        if (!appFinReceived && finSeqNumber == recvNext) {
            appFinReceived = true
            recvNext = Seq.add(recvNext, 1)
            sendPureAck()
            if (remoteConnected) channel.closeOutbound()
        } else {
            sendPureAck()
        }
    }

    private fun flushToApp() {
        if (!established) return

        var allowance = peerWindow - inFlightBytes()
        while (unsentToApp.isNotEmpty() && allowance > 0) {
            val chunk = unsentToApp.first()
            val take = minOf(maxSegment, allowance, chunk.size)
            val segment = if (take == chunk.size) {
                unsentToApp.removeFirst()
            } else {
                unsentToApp.removeFirst()
                unsentToApp.addFirst(chunk.copyOfRange(take, chunk.size))
                chunk.copyOfRange(0, take)
            }
            sendData(sendNext, segment)
            unackedSegments.addLast(OutSegment(sendNext, segment))
            sendNext = Seq.add(sendNext, take)
            allowance -= take
        }

        // Once everything the remote sent is on its way, mirror its close with a FIN.
        if (unsentToApp.isEmpty() && remoteEof && !finSent) {
            finSeq = sendNext
            sendSegment(sendNext, recvNext, TcpFlags.FIN or TcpFlags.ACK, tracked = true)
            sendNext = Seq.add(sendNext, 1)
            finSent = true
        }
    }

    fun onTick(now: Long) {
        if (closed) return
        val elapsed = now - lastSendMillis
        if (elapsed < RTO_MS) return

        if (unackedSegments.isNotEmpty()) {
            if (++retransmits > MAX_RETRANSMITS) {
                reset()
                return
            }
            // Resend everything still in flight.
            unackedSegments.forEach { sendData(it.seq, it.data) }
        }
        if (finSent && !finAcked) {
            sendSegment(finSeq, recvNext, TcpFlags.FIN or TcpFlags.ACK, tracked = true)
        }
    }

    private fun checkTeardown() {
        if (appFinReceived && finAcked) finish()
    }

    private fun reset() {
        if (closed) return
        engine.trace("TCP ${key.destinationAddress}:${key.destinationPort} reset")
        sendSegment(sendNext, recvNext, TcpFlags.RST or TcpFlags.ACK)
        finish()
    }

    fun abort() {
        if (closed) return
        closed = true
        if (channelOpened) channel.close()
    }

    private fun finish() {
        if (closed) return
        closed = true
        if (channelOpened) channel.close()
        engine.removeTcp(key)
    }

    // region segment emission

    private fun sendData(seq: Long, payload: ByteArray) {
        emit(seq, recvNext, TcpFlags.ACK or TcpFlags.PSH, payload, tracked = true)
    }

    private fun sendSegment(seq: Long, ack: Long, flags: Int, tracked: Boolean = false) {
        emit(seq, ack, flags, EMPTY, tracked)
    }

    private fun sendPureAck() {
        emit(sendNext, recvNext, TcpFlags.ACK, EMPTY, tracked = false)
    }

    /**
     * @param tracked whether this send arms the retransmission timer. Only data
     * and FIN segments are retransmittable; pure ACKs, the SYN-ACK and RST are
     * not, so they must not reset the timer for outstanding data.
     */
    private fun emit(seq: Long, ack: Long, flags: Int, payload: ByteArray, tracked: Boolean) {
        val packet = TcpSegment.build(
            sourceBytes = serverBytes,
            destinationBytes = clientBytes,
            sourcePort = key.destinationPort,
            destinationPort = key.sourcePort,
            sequenceNumber = seq,
            acknowledgementNumber = ack,
            flags = flags,
            windowSize = INITIAL_WINDOW,
            payload = payload,
        )
        if (tracked) lastSendMillis = currentTimeMillis()
        engine.deliverInbound(packet)
    }

    // endregion

    private fun inFlightBytes(): Int = ((sendNext - sendUnacked) and Seq.MASK).toInt()

    private fun seqGt(a: Long, b: Long): Boolean = Seq.lt(b, a)

    private companion object {
        const val INITIAL_WINDOW = 65535
        const val RTO_MS = 500L
        const val MAX_RETRANSMITS = 10
        const val IPV6_ADDRESS_SIZE = 16
        const val IPV6_HEADER_OVERHEAD = 20
        val EMPTY = ByteArray(0)
    }
}
