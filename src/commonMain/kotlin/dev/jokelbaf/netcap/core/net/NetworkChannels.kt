package dev.jokelbaf.netcap.core.net

/**
 * The network-facing side of the userspace stack. Each platform provides an
 * implementation that opens real sockets to the internet - on Android these are
 * routed around the VPN via `VpnService.protect()`; on iOS the extension's own
 * sockets already egress on the physical interface.
 *
 * All callbacks are invoked on arbitrary IO threads; the engine re-serializes
 * them onto its single worker, so implementations need no locking of engine state.
 */
interface NetworkChannelFactory {
    fun openTcp(remoteAddress: String, remotePort: Int, listener: TcpChannelListener): TcpChannel
    fun openUdp(remoteAddress: String, remotePort: Int, listener: UdpChannelListener): UdpChannel
}

/** A live TCP connection to a real destination, driven by the userspace NAT. */
interface TcpChannel {
    /** Forwards application bytes to the remote peer. */
    fun send(data: ByteArray)

    /** Half-closes our writing side after the app sent a FIN. */
    fun closeOutbound()

    /** Tears the connection down completely. */
    fun close()
}

interface TcpChannelListener {
    /** The TCP connection to the remote peer is established. */
    fun onConnected()

    /** Bytes received from the remote peer, to be relayed to the app. */
    fun onData(data: ByteArray)

    /** The remote peer closed its writing side (EOF). */
    fun onClosed()

    fun onError(error: Throwable)
}

/** A connected UDP socket to a real destination, driven by the userspace NAT. */
interface UdpChannel {
    fun send(data: ByteArray)
    fun close()
}

interface UdpChannelListener {
    /** A datagram received from the remote peer, to be relayed to the app. */
    fun onData(data: ByteArray)

    fun onError(error: Throwable)
}
