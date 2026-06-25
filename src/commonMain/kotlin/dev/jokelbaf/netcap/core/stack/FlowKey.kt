package dev.jokelbaf.netcap.core.stack

import dev.jokelbaf.netcap.core.TransportProtocol

/** Identifies a transport flow by its 4-tuple and protocol. */
data class FlowKey(
    val protocol: TransportProtocol,
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int,
)

/**
 * 32-bit serial-number comparisons (RFC 1982) used for TCP sequence and
 * acknowledgement arithmetic, correct across the 2^32 wraparound.
 */
internal object Seq {
    const val MASK = 0xFFFFFFFFL

    fun add(value: Long, delta: Int): Long = (value + delta) and MASK

    /** True when [a] is strictly before [b] in sequence space. */
    fun lt(a: Long, b: Long): Boolean = ((a - b) and MASK).toInt() < 0

    /** True when [a] is at or before [b] in sequence space. */
    fun leq(a: Long, b: Long): Boolean = a == b || lt(a, b)
}
