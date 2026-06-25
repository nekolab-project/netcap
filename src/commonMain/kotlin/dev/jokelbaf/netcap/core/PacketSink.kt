package dev.jokelbaf.netcap.core

import dev.jokelbaf.netcap.core.protocol.Packet

/** Receives every packet a capture backend produces, in both directions. */
fun interface PacketSink {
    fun onPacketCaptured(packet: Packet)
}
