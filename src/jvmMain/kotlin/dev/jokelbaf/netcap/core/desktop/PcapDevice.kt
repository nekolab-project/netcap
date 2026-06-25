package dev.jokelbaf.netcap.core.desktop

import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Enumerates the interfaces libpcap/npcap can capture on by walking the
 * `pcap_if_t` linked list. Only `next`, `name` and `description` are read; the
 * address list is skipped (direction inference uses the host's own addresses).
 */
internal fun findAllDevices(): List<PcapDevice> = Arena.ofConfined().use { arena ->
    val errbuf = arena.allocate(Pcap.ERRBUF_SIZE)
    val listHead = arena.allocate(ValueLayout.ADDRESS)
    if (Pcap.findAllDevs(listHead, errbuf) != 0) {
        throw PcapException("pcap_findalldevs failed: ${errbuf.getString(0)}")
    }
    val first = listHead.get(ValueLayout.ADDRESS, 0)
    if (first.address() == 0L) return emptyList()

    val devices = buildList {
        var node = first
        while (node.address() != 0L) {
            val struct = node.reinterpret(IF_STRUCT_SIZE)
            val name = struct.readCString(NAME_OFFSET) ?: ""
            if (name.isNotEmpty()) add(PcapDevice(name, struct.readCString(DESCRIPTION_OFFSET)))
            node = struct.get(ValueLayout.ADDRESS, NEXT_OFFSET)
        }
    }
    Pcap.freeAllDevs(first)
    devices
}

private fun MemorySegment.readCString(offset: Long): String? {
    val pointer = get(ValueLayout.ADDRESS, offset)
    if (pointer.address() == 0L) return null
    return pointer.reinterpret(MAX_CSTRING).getString(0)
}

// struct pcap_if { pcap_if *next; char *name; char *description; pcap_addr *addresses; bpf_u_int32 flags; }
private const val NEXT_OFFSET = 0L
private const val NAME_OFFSET = 8L
private const val DESCRIPTION_OFFSET = 16L
private const val IF_STRUCT_SIZE = 40L
private const val MAX_CSTRING = 4096L
