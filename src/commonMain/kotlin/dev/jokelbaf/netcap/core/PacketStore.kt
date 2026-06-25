package dev.jokelbaf.netcap.core

import dev.jokelbaf.netcap.core.protocol.Packet
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * An in-memory, observable ring buffer of captured packets for the UI. The most recent
 * [capacity] packets are retained in order; [totalCount] keeps counting beyond that.
 *
 * It is a [PacketSink], so a backend writes straight into it. StateFlow conflation means a
 * fast capture rate never blocks the producer.
 */
class PacketStore(private val capacity: Int = DEFAULT_CAPACITY) : PacketSink {

    private val _packets = MutableStateFlow<List<Packet>>(emptyList())
    val packets: StateFlow<List<Packet>> = _packets.asStateFlow()

    private val _totalCount = MutableStateFlow(0L)
    val totalCount: StateFlow<Long> = _totalCount.asStateFlow()

    override fun onPacketCaptured(packet: Packet) {
        _packets.update { current ->
            if (current.size < capacity) {
                current + packet
            } else {
                current.subList(current.size - capacity + 1, current.size) + packet
            }
        }
        _totalCount.update { it + 1 }
    }

    fun clear() {
        _packets.value = emptyList()
        _totalCount.value = 0
    }

    private companion object {
        const val DEFAULT_CAPACITY = 1000
    }
}
