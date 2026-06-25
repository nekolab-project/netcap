package dev.jokelbaf.netcap.core.stack

/** Sink the engine uses to push synthesized inbound IP packets back into the TUN. */
fun interface TunWriter {
    fun writePacket(packet: ByteArray)
}
