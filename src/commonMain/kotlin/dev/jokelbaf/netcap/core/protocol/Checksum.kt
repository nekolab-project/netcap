package dev.jokelbaf.netcap.core.protocol

/**
 * The standard 16-bit one's-complement Internet checksum (RFC 1071) used by the
 * IPv4, TCP and UDP headers. We must recompute these whenever we synthesize the
 * inbound packets written back into the TUN.
 */
internal object Checksum {

    /**
     * Computes the checksum over [length] bytes of [data] starting at [offset].
     * [initial] seeds the running sum and is used to fold in a pseudo-header.
     */
    fun compute(data: ByteArray, offset: Int, length: Int, initial: Long = 0L): Int {
        var sum = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            // Odd trailing byte is padded with a zero low byte.
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    /**
     * Builds the partial sum of a TCP/UDP IPv4 pseudo-header
     * (source address, destination address, protocol, transport length). The
     * result is fed back into [compute] as its [initial] seed.
     */
    fun pseudoHeaderSum(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        protocol: Int,
        transportLength: Int,
    ): Long {
        var sum = 0L
        sum += ((sourceAddress[0].toInt() and 0xFF) shl 8) or (sourceAddress[1].toInt() and 0xFF)
        sum += ((sourceAddress[2].toInt() and 0xFF) shl 8) or (sourceAddress[3].toInt() and 0xFF)
        sum += ((destinationAddress[0].toInt() and 0xFF) shl 8) or (destinationAddress[1].toInt() and 0xFF)
        sum += ((destinationAddress[2].toInt() and 0xFF) shl 8) or (destinationAddress[3].toInt() and 0xFF)
        sum += protocol and 0xFFFF
        sum += transportLength and 0xFFFF
        return sum
    }

    /**
     * Builds the partial sum of a TCP/UDP IPv6 pseudo-header (RFC 8200 §8.1):
     * 16-byte source and destination addresses, a 32-bit upper-layer length, and
     * the next-header value. Fed back into [compute] as its [initial] seed.
     */
    fun pseudoHeaderSumV6(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        nextHeader: Int,
        transportLength: Int,
    ): Long {
        var sum = 0L
        var i = 0
        while (i < 16) {
            sum += ((sourceAddress[i].toInt() and 0xFF) shl 8) or (sourceAddress[i + 1].toInt() and 0xFF)
            sum += ((destinationAddress[i].toInt() and 0xFF) shl 8) or (destinationAddress[i + 1].toInt() and 0xFF)
            i += 2
        }
        sum += (transportLength ushr 16) and 0xFFFF
        sum += transportLength and 0xFFFF
        sum += nextHeader and 0xFFFF
        return sum
    }
}
