package dev.jokelbaf.netcap.core.android

import android.net.VpnService
import android.util.Log
import dev.jokelbaf.netcap.core.net.NetworkChannelFactory
import dev.jokelbaf.netcap.core.net.TcpChannel
import dev.jokelbaf.netcap.core.net.TcpChannelListener
import dev.jokelbaf.netcap.core.net.UdpChannel
import dev.jokelbaf.netcap.core.net.UdpChannelListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

/**
 * Opens real sockets to the internet for the userspace NAT. Every socket is
 * handed to [VpnService.protect] so its traffic egresses on the physical
 * interface instead of looping back into our own TUN.
 *
 * Blocking socket I/O runs on [scope] (IO dispatcher); reads and the connect
 * deliver results through the channel listeners, which the engine re-serializes.
 */
internal class AndroidNetworkChannelFactory(
    private val vpnService: VpnService,
    private val scope: CoroutineScope,
) : NetworkChannelFactory {

    override fun openTcp(remoteAddress: String, remotePort: Int, listener: TcpChannelListener): TcpChannel =
        AndroidTcpChannel(vpnService, scope, remoteAddress, remotePort, listener)

    override fun openUdp(remoteAddress: String, remotePort: Int, listener: UdpChannelListener): UdpChannel =
        AndroidUdpChannel(vpnService, scope, remoteAddress, remotePort, listener)
}

private const val TAG = "Sniffer"
private const val CONNECT_TIMEOUT_MS = 10_000
private const val TCP_READ_BUFFER = 16 * 1024
private const val UDP_READ_BUFFER = 64 * 1024

private class AndroidTcpChannel(
    private val vpnService: VpnService,
    private val scope: CoroutineScope,
    private val host: String,
    private val port: Int,
    private val listener: TcpChannelListener,
) : TcpChannel {

    // SocketChannel.open() creates the underlying fd immediately, so protect()
    // actually takes effect. A plain `Socket()` defers fd creation until connect,
    // at which point protect() is a no-op and the socket's packets loop back into
    // our own TUN instead of egressing on the physical interface. We then do all
    // I/O via the channel's ByteBuffer read/write rather than the socket's stream
    // adaptors, which can silently fail to deliver on a channel-backed socket.
    private val channel = SocketChannel.open()
    private val sendQueue = Channel<ByteArray>(Channel.UNLIMITED)

    @Volatile
    private var closed = false
    private var writerJob: Job? = null

    init {
        scope.launch(Dispatchers.IO) { connectAndRead() }
    }

    private fun connectAndRead() {
        try {
            val socket = channel.socket()
            val protectedOk = vpnService.protect(socket)
            Log.d(TAG, "TCP $host:$port protect=$protectedOk")
            if (!protectedOk) {
                listener.onError(IllegalStateException("VpnService.protect failed for $host:$port"))
                return
            }
            socket.tcpNoDelay = true
            // Timed connect via the adaptor; it restores blocking mode afterwards.
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            if (closed) return
            Log.d(TAG, "TCP $host:$port connected")
            listener.onConnected()
            startWriter()

            val buffer = ByteBuffer.allocate(TCP_READ_BUFFER)
            while (!closed) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) {
                    Log.d(TAG, "TCP $host:$port EOF")
                    listener.onClosed()
                    break
                }
                if (read > 0) {
                    buffer.flip()
                    val data = ByteArray(read)
                    buffer.get(data)
                    listener.onData(data)
                }
            }
        } catch (t: Throwable) {
            if (!closed) {
                Log.w(TAG, "TCP $host:$port error: ${t.message}")
                listener.onError(t)
            }
        }
    }

    private fun startWriter() {
        writerJob = scope.launch(Dispatchers.IO) {
            try {
                for (data in sendQueue) {
                    val buffer = ByteBuffer.wrap(data)
                    while (buffer.hasRemaining()) channel.write(buffer)
                }
                // sendQueue closed by closeOutbound(): all queued data sent, half-close.
                runCatching { channel.shutdownOutput() }
            } catch (t: Throwable) {
                if (!closed) {
                    Log.w(TAG, "TCP $host:$port write error: ${t.message}")
                    listener.onError(t)
                }
            }
        }
    }

    override fun send(data: ByteArray) {
        sendQueue.trySend(data)
    }

    override fun closeOutbound() {
        sendQueue.close()
    }

    override fun close() {
        if (closed) return
        closed = true
        sendQueue.close()
        writerJob?.cancel()
        runCatching { channel.close() }
    }
}

private class AndroidUdpChannel(
    vpnService: VpnService,
    private val scope: CoroutineScope,
    host: String,
    port: Int,
    private val listener: UdpChannelListener,
) : UdpChannel {

    private val socket = DatagramSocket()
    private val sendQueue = Channel<ByteArray>(Channel.UNLIMITED)

    @Volatile
    private var closed = false

    init {
        val protectedOk = vpnService.protect(socket)
        Log.d(TAG, "UDP $host:$port protect=$protectedOk")
        socket.connect(InetSocketAddress(host, port))
        scope.launch(Dispatchers.IO) { readLoop() }
        scope.launch(Dispatchers.IO) { writeLoop() }
    }

    private fun readLoop() {
        try {
            val buffer = ByteArray(UDP_READ_BUFFER)
            val packet = DatagramPacket(buffer, buffer.size)
            while (!closed) {
                socket.receive(packet)
                listener.onData(buffer.copyOf(packet.length))
                packet.length = buffer.size
            }
        } catch (t: Throwable) {
            if (!closed) listener.onError(t)
        }
    }

    private suspend fun writeLoop() {
        try {
            for (data in sendQueue) {
                socket.send(DatagramPacket(data, data.size))
            }
        } catch (t: Throwable) {
            if (!closed) listener.onError(t)
        }
    }

    override fun send(data: ByteArray) {
        sendQueue.trySend(data)
    }

    override fun close() {
        if (closed) return
        closed = true
        sendQueue.close()
        runCatching { socket.close() }
    }
}
