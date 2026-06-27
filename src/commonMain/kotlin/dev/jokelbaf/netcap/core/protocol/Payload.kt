package dev.jokelbaf.netcap.core.protocol

/**
 * One decoded protocol layer of a captured packet (Ethernet, IPv4/IPv6, TCP/UDP, …),
 * forming a lazily-decoded chain - each layer exposes the next via its own `payload`.
 *
 * Layers are **purely structural views**: a layer carries no bytes of its own, only a
 * position over the packet's single owned [Frame] buffer, and computes header fields on
 * access. Use [toByteArray] for an explicit, opt-in copy of a layer's slice when raw
 * bytes are genuinely needed; the whole frame is available via [Packet.frame].
 */
sealed interface Payload

/** Internal capability letting [toByteArray] copy a layer's slice without exposing the shared buffer. */
internal interface Sliceable {
    fun slice(): ByteArray
}

/** Copies this layer's bytes out of the shared frame buffer. An explicit, allocating operation. */
fun Payload.toByteArray(): ByteArray = (this as? Sliceable)?.slice() ?: EMPTY

private val EMPTY = ByteArray(0)

/** An undecoded or terminal layer (e.g. application data, or a protocol we don't decode yet). */
class RawPayload internal constructor(
    private val buffer: ByteArray,
    private val offset: Int,
    val size: Int,
) : Payload, Sliceable {
    override fun slice(): ByteArray = buffer.copyOfRange(offset, offset + size)
}
