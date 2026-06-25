package dev.jokelbaf.netcap.core.protocol

/** A 48-bit Ethernet MAC address, read on demand from a shared buffer. */
class MacAddress internal constructor(private val buffer: ByteArray, private val offset: Int) {

    val octets: ByteArray get() = buffer.copyOfRange(offset, offset + LENGTH)

    override fun toString(): String = buildString {
        for (i in 0 until LENGTH) {
            if (i != 0) append(':')
            val byte = buffer[offset + i].toInt() and 0xFF
            append(HEX[byte ushr 4])
            append(HEX[byte and 0x0F])
        }
    }

    override fun equals(other: Any?): Boolean =
        other is MacAddress && octets.contentEquals(other.octets)

    override fun hashCode(): Int = octets.contentHashCode()

    companion object {
        const val LENGTH = 6
        private const val HEX = "0123456789abcdef"
    }
}
