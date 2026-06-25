package dev.jokelbaf.netcap.core

/**
 * Minimal big-endian (network byte order) helpers for reading and writing
 * integers in raw packet buffers. Kept dependency-free so the whole parsing
 * layer stays in [commonMain] and compiles for every Kotlin target.
 */

internal fun ByteArray.readUByte(offset: Int): Int = this[offset].toInt() and 0xFF

internal fun ByteArray.readUShort(offset: Int): Int =
    ((this[offset].toInt() and 0xFF) shl 8) or (this[offset + 1].toInt() and 0xFF)

internal fun ByteArray.readUInt(offset: Int): Long =
    ((this[offset].toLong() and 0xFF) shl 24) or
        ((this[offset + 1].toLong() and 0xFF) shl 16) or
        ((this[offset + 2].toLong() and 0xFF) shl 8) or
        (this[offset + 3].toLong() and 0xFF)

internal fun ByteArray.writeUByte(offset: Int, value: Int) {
    this[offset] = (value and 0xFF).toByte()
}

internal fun ByteArray.writeUShort(offset: Int, value: Int) {
    this[offset] = ((value ushr 8) and 0xFF).toByte()
    this[offset + 1] = (value and 0xFF).toByte()
}

internal fun ByteArray.writeUInt(offset: Int, value: Long) {
    this[offset] = ((value ushr 24) and 0xFF).toByte()
    this[offset + 1] = ((value ushr 16) and 0xFF).toByte()
    this[offset + 2] = ((value ushr 8) and 0xFF).toByte()
    this[offset + 3] = (value and 0xFF).toByte()
}

/** Formats four bytes starting at [offset] as a dotted-quad IPv4 address. */
internal fun ByteArray.readIpv4Address(offset: Int): String =
    "${readUByte(offset)}.${readUByte(offset + 1)}.${readUByte(offset + 2)}.${readUByte(offset + 3)}"

/** Parses a dotted-quad IPv4 address into its four bytes. */
internal fun parseIpv4Address(address: String): ByteArray {
    val parts = address.split('.')
    require(parts.size == 4) { "Invalid IPv4 address: $address" }
    return ByteArray(4) { (parts[it].toInt() and 0xFF).toByte() }
}

/**
 * Formats the sixteen bytes starting at [offset] as a canonical (RFC 5952) IPv6
 * address: lowercase hex, no leading zeros, the longest run of zero groups
 * collapsed to `::`.
 */
internal fun ByteArray.readIpv6Address(offset: Int): String {
    val groups = IntArray(8) { readUShort(offset + it * 2) }
    var runStart = -1
    var runLength = 0
    var i = 0
    while (i < 8) {
        if (groups[i] != 0) {
            i++
            continue
        }
        var j = i
        while (j < 8 && groups[j] == 0) j++
        if (j - i > runLength) {
            runLength = j - i
            runStart = i
        }
        i = j
    }
    if (runLength < 2) {
        return (0 until 8).joinToString(":") { groups[it].toString(16) }
    }
    val head = (0 until runStart).joinToString(":") { groups[it].toString(16) }
    val tail = (runStart + runLength until 8).joinToString(":") { groups[it].toString(16) }
    return "$head::$tail"
}

/** Parses an IPv6 address (with optional `::` compression) into its sixteen bytes, or null if malformed. */
internal fun parseIpv6Address(address: String): ByteArray? {
    val literal = address.substringBefore('%') // drop any zone id
    val bytes = ByteArray(16)

    fun writeGroup(index: Int, group: String): Boolean {
        val value = group.toIntOrNull(16) ?: return false
        if (value !in 0..0xFFFF) return false
        bytes[index * 2] = (value ushr 8).toByte()
        bytes[index * 2 + 1] = value.toByte()
        return true
    }

    val split = literal.indexOf("::")
    if (split >= 0) {
        val head = literal.substring(0, split).split(':').filter { it.isNotEmpty() }
        val tail = literal.substring(split + 2).split(':').filter { it.isNotEmpty() }
        if (head.size + tail.size > 7) return null
        head.forEachIndexed { i, g -> if (!writeGroup(i, g)) return null }
        tail.forEachIndexed { i, g -> if (!writeGroup(8 - tail.size + i, g)) return null }
        return bytes
    }
    val groups = literal.split(':')
    if (groups.size != 8) return null
    groups.forEachIndexed { i, g -> if (!writeGroup(i, g)) return null }
    return bytes
}
