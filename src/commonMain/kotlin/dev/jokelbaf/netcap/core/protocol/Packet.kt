package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.PacketDirection
import kotlin.time.Instant

/** The single owned byte buffer of a captured packet - the only place bytes are stored. */
interface Frame {
    val bytes: ByteArray
}

/**
 * One captured packet: source/timing metadata plus a lazily-decoded [Payload] layer chain
 * over the owned [frame]. Desktop captures start at [dev.jokelbaf.netcap.core.protocol.EthernetFrame];
 * mobile captures start at IP. Nothing is decoded until a layer is accessed (e.g. via [tcp], [ip]).
 */
interface Packet {
    /** The raw captured frame; the only byte storage. Layers are views over it. */
    val frame: Frame

    /** Capture time, at the precision the backend provides (micro/nanosecond). */
    val timestamp: Instant

    val direction: PacketDirection

    /** The capture source (pcap device name, TUN, replay file, …), when known. */
    val interfaceName: String?

    /** The top decoded layer; the rest of the stack hangs off it lazily. */
    val payload: Payload
}
