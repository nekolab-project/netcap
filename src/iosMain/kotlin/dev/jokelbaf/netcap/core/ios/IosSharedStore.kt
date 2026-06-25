@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package dev.jokelbaf.netcap.core.ios

import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.PacketDirection
import dev.jokelbaf.netcap.core.protocol.LinkType
import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.decodedPacket
import kotlin.time.Instant
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSJSONSerialization
import platform.Foundation.NSURL
import platform.Foundation.NSNumber
import platform.Foundation.dataWithContentsOfURL
import platform.Foundation.writeToURL

/**
 * Cross-process bridge between the Network Extension (which runs the engine and captures
 * packets) and the app UI. Both processes share the App Group container; the extension
 * overwrites a single JSON snapshot file and the app polls it.
 *
 * Each packet is serialized as its (header-capped) raw frame bytes plus timestamp and
 * direction; the app reconstructs a lazily-decoded [Packet] from them. The frame is capped
 * to keep the snapshot small — enough for header inspection, not full payloads.
 *
 * The shared App Group identifier must match the one configured on both targets in Xcode.
 */
internal class IosSharedStore(private val appGroup: String) {

    private val snapshotUrl: NSURL?
        get() {
            val container = NSFileManager.defaultManager
                .containerURLForSecurityApplicationGroupIdentifier(appGroup) ?: return null
            return container.URLByAppendingPathComponent(SNAPSHOT_FILE)
        }

    data class Snapshot(
        val state: CaptureState,
        val totalCount: Long,
        val packets: List<Packet>,
        val logs: List<String>,
    )

    @Suppress("UNCHECKED_CAST")
    fun write(state: CaptureState, totalCount: Long, packets: List<Packet>, logs: List<String>) {
        val url = snapshotUrl ?: return
        val packetDicts = packets.takeLast(MAX_PACKETS).map { packet ->
            val bytes = packet.frame.bytes
            val capped = if (bytes.size > FRAME_CAP) bytes.copyOf(FRAME_CAP) else bytes
            mapOf(
                "ts" to packet.timestamp.toEpochMilliseconds(),
                "dir" to packet.direction.name,
                "bytes" to capped.map { it.toInt() and 0xFF }, // List<Int> bridges to NSArray<NSNumber>
            )
        }
        val root: Map<String, Any> = mapOf(
            "state" to state.name,
            "total" to totalCount,
            "packets" to packetDicts,
            "logs" to logs.takeLast(MAX_LOGS),
        )
        val data = NSJSONSerialization.dataWithJSONObject(root, 0u, null) ?: return
        data.writeToURL(url, atomically = true)
    }

    @Suppress("UNCHECKED_CAST")
    fun read(): Snapshot {
        val url = snapshotUrl ?: return EMPTY
        val data: NSData = NSData.dataWithContentsOfURL(url) ?: return EMPTY
        val root = NSJSONSerialization.JSONObjectWithData(data, 0u, null) as? Map<Any?, *> ?: return EMPTY

        val state = (root["state"] as? String)?.let { runCatching { CaptureState.valueOf(it) }.getOrNull() }
            ?: CaptureState.IDLE
        val total = (root["total"] as? NSNumber)?.longValue ?: 0L
        val packetList = (root["packets"] as? List<*>).orEmpty()

        val packets = packetList.mapNotNull { entry ->
            val dict = entry as? Map<*, *> ?: return@mapNotNull null
            val byteList = (dict["bytes"] as? List<*>).orEmpty()
            if (byteList.isEmpty()) return@mapNotNull null
            val bytes = ByteArray(byteList.size) { i -> ((byteList[i] as? NSNumber)?.intValue ?: 0).toByte() }
            val timestamp = Instant.fromEpochMilliseconds((dict["ts"] as? NSNumber)?.longValue ?: 0L)
            val direction = (dict["dir"] as? String)?.let { runCatching { PacketDirection.valueOf(it) }.getOrNull() }
                ?: PacketDirection.UNKNOWN
            // The extension always captures raw IP packets off the TUN.
            decodedPacket(bytes, timestamp, direction, interfaceName = null, linkType = LinkType.RAW_IP)
        }

        val logs = (root["logs"] as? List<*>).orEmpty().mapNotNull { it as? String }

        return Snapshot(state, total, packets, logs)
    }

    private companion object {
        const val SNAPSHOT_FILE = "capture-snapshot.json"
        const val MAX_PACKETS = 500
        const val MAX_LOGS = 200
        const val FRAME_CAP = 96 // bytes — enough for IPv4/IPv6 + TCP/UDP headers
        val EMPTY = Snapshot(CaptureState.IDLE, 0L, emptyList(), emptyList())
    }
}
