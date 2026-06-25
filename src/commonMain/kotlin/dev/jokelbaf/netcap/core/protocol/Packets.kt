package dev.jokelbaf.netcap.core.protocol

import dev.jokelbaf.netcap.core.PacketDirection
import kotlin.time.Instant

private class CapturedFrame(override val bytes: ByteArray) : Frame

/**
 * Wraps captured [bytes] into a lazily-decoded [Packet]; the bytes become the owned frame.
 * Nothing is decoded until a layer is accessed. Backends call this; users never construct packets.
 */
internal fun decodedPacket(
    bytes: ByteArray,
    timestamp: Instant,
    direction: PacketDirection,
    interfaceName: String?,
    linkType: LinkType,
): Packet = DecodedPacket(CapturedFrame(bytes), timestamp, direction, interfaceName, linkType)

private class DecodedPacket(
    override val frame: Frame,
    override val timestamp: Instant,
    override val direction: PacketDirection,
    override val interfaceName: String?,
    private val linkType: LinkType,
) : Packet {
    override val payload: Payload by lazy { decodeLink(frame.bytes, 0, frame.bytes.size, linkType) }
}
