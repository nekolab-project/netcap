@file:OptIn(ExperimentalForeignApi::class, DelicateCoroutinesApi::class)

package dev.jokelbaf.netcap.core.ios

import dev.jokelbaf.netcap.core.net.NetworkChannelFactory
import dev.jokelbaf.netcap.core.net.TcpChannel
import dev.jokelbaf.netcap.core.net.TcpChannelListener
import dev.jokelbaf.netcap.core.net.UdpChannel
import dev.jokelbaf.netcap.core.net.UdpChannelListener
import dev.jokelbaf.netcap.core.parseIpv6Address
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.newFixedThreadPoolContext
import kotlin.concurrent.Volatile
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.IPPROTO_IP
import platform.posix.IPPROTO_IPV6
import platform.posix.SOCK_DGRAM
import platform.posix.SOCK_STREAM
import platform.posix.close
import platform.posix.connect
import platform.posix.memcpy
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.shutdown
import platform.posix.sockaddr
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6
import platform.posix.socket

/**
 * iOS network side of the userspace NAT, built on POSIX sockets.
 *
 * Inside a `NEPacketTunnelProvider`, with a default route claimed by the tunnel,
 * the provider's own sockets would route back into the tunnel and loop. There is
 * no `VpnService.protect()` equivalent, so each upstream socket is bound to the
 * physical interface via `IP_BOUND_IF`/`IPV6_BOUND_IF` ([boundInterfaceIndex],
 * resolved in Swift) to force its traffic onto Wi-Fi/cellular instead.
 *
 * Destination addresses always arrive as numeric IPv4 or IPv6 (from parsed
 * headers), so no DNS resolution is required here.
 */
internal class IosNetworkChannelFactory(
    private val boundInterfaceIndex: UInt,
    private val log: (String) -> Unit,
) : NetworkChannelFactory {

    // Reads and writes get SEPARATE pools. Each connection's blocking recv() holds
    // a read thread for the connection's lifetime; if reads and writes shared a
    // pool, enough concurrent reads would leave no thread for the (brief, otherwise
    // suspended) writers to send() — so requests never reach the server and it
    // idle-closes. Keeping writes on their own pool makes them immune to that.
    // Blocked threads are cheap (lazily-paged stacks), so this fits the NE budget.
    private val readScope = CoroutineScope(newFixedThreadPoolContext(READ_THREADS, "sniffer-ios-read"))
    private val writeScope = CoroutineScope(newFixedThreadPoolContext(WRITE_THREADS, "sniffer-ios-write"))

    override fun openTcp(remoteAddress: String, remotePort: Int, listener: TcpChannelListener): TcpChannel {
        log("open TCP ${family(remoteAddress)} $remoteAddress:$remotePort")
        return IosTcpChannel(readScope, writeScope, remoteAddress, remotePort, listener, boundInterfaceIndex, log)
    }

    override fun openUdp(remoteAddress: String, remotePort: Int, listener: UdpChannelListener): UdpChannel {
        log("open UDP ${family(remoteAddress)} $remoteAddress:$remotePort")
        return IosUdpChannel(readScope, writeScope, remoteAddress, remotePort, listener, boundInterfaceIndex, log)
    }

    private fun family(host: String): String = if (host.contains(':')) "v6" else "v4"

    private companion object {
        const val READ_THREADS = 64
        const val WRITE_THREADS = 16
    }
}

/** `IP_BOUND_IF` / `IPV6_BOUND_IF` from Darwin's headers (bind a socket to an interface). */
private const val IP_BOUND_IF = 25
private const val IPV6_BOUND_IF = 125
private const val SHUT_WR = 1
private const val READ_BUFFER = 64 * 1024

/** Network byte order for a 16-bit port (host is little-endian on arm64). */
private fun htonsPort(port: Int): UShort =
    (((port and 0xFF) shl 8) or ((port ushr 8) and 0xFF)).toUShort()

/**
 * Converts a dotted-quad IPv4 string to a network-byte-order `in_addr_t`,
 * replacing `inet_addr` (not exposed in Darwin's posix interop).
 */
private fun ipv4ToNetworkOrder(host: String): UInt {
    val parts = host.split('.')
    if (parts.size != 4) return 0u
    val b0 = (parts[0].toIntOrNull() ?: 0).toUInt() and 0xFFu
    val b1 = (parts[1].toIntOrNull() ?: 0).toUInt() and 0xFFu
    val b2 = (parts[2].toIntOrNull() ?: 0).toUInt() and 0xFFu
    val b3 = (parts[3].toIntOrNull() ?: 0).toUInt() and 0xFFu
    return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
}

@OptIn(ExperimentalForeignApi::class)
private fun connectSocket(type: Int, host: String, port: Int, boundInterfaceIndex: UInt): Int =
    if (host.contains(':')) {
        connectSocket6(type, host, port, boundInterfaceIndex)
    } else {
        connectSocket4(type, host, port, boundInterfaceIndex)
    }

/** Binds a socket to the physical interface so its traffic doesn't loop back into our tunnel. */
@OptIn(ExperimentalForeignApi::class)
private fun bindToInterface(fd: Int, level: Int, option: Int, boundInterfaceIndex: UInt) {
    if (boundInterfaceIndex == 0u) return
    memScoped {
        val index = alloc<UIntVar>()
        index.value = boundInterfaceIndex
        setsockopt(fd, level, option, index.ptr, sizeOf<UIntVar>().convert())
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun connectSocket4(type: Int, host: String, port: Int, boundInterfaceIndex: UInt): Int {
    val fd = socket(AF_INET, type, 0)
    if (fd < 0) return -1
    bindToInterface(fd, IPPROTO_IP, IP_BOUND_IF, boundInterfaceIndex)
    memScoped {
        val addr = alloc<sockaddr_in>()
        addr.sin_family = AF_INET.convert()
        addr.sin_port = htonsPort(port)
        addr.sin_addr.s_addr = ipv4ToNetworkOrder(host)
        if (connect(fd, addr.ptr.reinterpret<sockaddr>(), sizeOf<sockaddr_in>().convert()) != 0) {
            close(fd)
            return -1
        }
    }
    return fd
}

@OptIn(ExperimentalForeignApi::class)
private fun connectSocket6(type: Int, host: String, port: Int, boundInterfaceIndex: UInt): Int {
    val addressBytes = parseIpv6Address(host) ?: return -1
    val fd = socket(AF_INET6, type, 0)
    if (fd < 0) return -1
    bindToInterface(fd, IPPROTO_IPV6, IPV6_BOUND_IF, boundInterfaceIndex)
    memScoped {
        val addr = alloc<sockaddr_in6>()
        addr.sin6_family = AF_INET6.convert()
        addr.sin6_port = htonsPort(port)
        addressBytes.usePinned { memcpy(addr.sin6_addr.ptr, it.addressOf(0), 16.convert()) }
        if (connect(fd, addr.ptr.reinterpret<sockaddr>(), sizeOf<sockaddr_in6>().convert()) != 0) {
            close(fd)
            return -1
        }
    }
    return fd
}

private class IosTcpChannel(
    private val readScope: CoroutineScope,
    private val writeScope: CoroutineScope,
    private val host: String,
    private val port: Int,
    private val listener: TcpChannelListener,
    private val boundInterfaceIndex: UInt,
    private val log: (String) -> Unit,
) : TcpChannel {

    private val sendQueue = Channel<ByteArray>(Channel.UNLIMITED)
    private var fd = -1

    @Volatile
    private var closed = false

    init {
        readScope.launch { run() }
    }

    private fun run() {
        fd = connectSocket(SOCK_STREAM, host, port, boundInterfaceIndex)
        if (fd < 0) {
            log("TCP connect failed $host:$port")
            if (!closed) listener.onError(IllegalStateException("TCP connect failed to $host:$port"))
            return
        }
        log("TCP connected $host:$port")
        listener.onConnected()
        // fd is valid now, so the writer never races ahead of connect.
        writeScope.launch { writeLoop() }

        val buffer = ByteArray(READ_BUFFER)
        while (!closed) {
            val n = buffer.usePinned { recv(fd, it.addressOf(0), READ_BUFFER.convert(), 0) }
            when {
                n > 0 -> listener.onData(buffer.copyOf(n.toInt()))
                n == 0L -> {
                    listener.onClosed()
                    break
                }
                else -> {
                    if (!closed) listener.onError(IllegalStateException("TCP recv error $host:$port"))
                    break
                }
            }
        }
    }

    private suspend fun writeLoop() {
        for (data in sendQueue) {
            if (closed) break
            sendAll(fd, data)
        }
        if (fd >= 0 && !closed) shutdown(fd, SHUT_WR)
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
        if (fd >= 0) close(fd)
    }
}

private class IosUdpChannel(
    private val readScope: CoroutineScope,
    private val writeScope: CoroutineScope,
    private val host: String,
    private val port: Int,
    private val listener: UdpChannelListener,
    private val boundInterfaceIndex: UInt,
    private val log: (String) -> Unit,
) : UdpChannel {

    private val sendQueue = Channel<ByteArray>(Channel.UNLIMITED)
    private var fd = -1

    @Volatile
    private var closed = false

    init {
        readScope.launch { run() }
    }

    private fun run() {
        fd = connectSocket(SOCK_DGRAM, host, port, boundInterfaceIndex)
        if (fd < 0) {
            log("UDP connect failed $host:$port")
            if (!closed) listener.onError(IllegalStateException("UDP connect failed to $host:$port"))
            return
        }
        writeScope.launch { writeLoop() }

        val buffer = ByteArray(READ_BUFFER)
        while (!closed) {
            val n = buffer.usePinned { recv(fd, it.addressOf(0), READ_BUFFER.convert(), 0) }
            if (n > 0) {
                listener.onData(buffer.copyOf(n.toInt()))
            } else {
                if (n < 0 && !closed) listener.onError(IllegalStateException("UDP recv error $host:$port"))
                break
            }
        }
    }

    private suspend fun writeLoop() {
        for (data in sendQueue) {
            if (closed) break
            sendAll(fd, data)
        }
    }

    override fun send(data: ByteArray) {
        sendQueue.trySend(data)
    }

    override fun close() {
        if (closed) return
        closed = true
        sendQueue.close()
        if (fd >= 0) close(fd)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun sendAll(fd: Int, data: ByteArray) {
    if (data.isEmpty()) return
    data.usePinned { pinned ->
        var sent = 0
        while (sent < data.size) {
            val n = send(fd, pinned.addressOf(sent), (data.size - sent).convert(), 0)
            if (n <= 0) break
            sent += n.toInt()
        }
    }
}
