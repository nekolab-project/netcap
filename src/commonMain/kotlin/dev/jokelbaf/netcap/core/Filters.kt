package dev.jokelbaf.netcap.core

import dev.jokelbaf.netcap.core.protocol.Packet
import dev.jokelbaf.netcap.core.protocol.TcpSegment
import dev.jokelbaf.netcap.core.protocol.UdpDatagram
import dev.jokelbaf.netcap.core.protocol.ip
import dev.jokelbaf.netcap.core.protocol.transport

/**
 * Evaluates a [CaptureFilter] against an already-decoded [Packet] in software. This is how the
 * mobile backends honour a filter — they can't push it into the kernel like desktop's BPF. A raw
 * [CaptureFilter.Bpf] can't be matched this way (it's desktop-only), so it always passes here.
 */
internal fun Packet.matches(filter: CaptureFilter?): Boolean = when (filter) {
    null, is CaptureFilter.Bpf -> true
    is CaptureFilter.Rules -> matchesRules(filter)
}

private fun Packet.matchesRules(rules: CaptureFilter.Rules): Boolean {
    if (rules.protocols.isNotEmpty()) {
        val protocol = when (transport) {
            is TcpSegment -> TransportProtocol.TCP
            is UdpDatagram -> TransportProtocol.UDP
            else -> null
        }
        if (protocol == null || protocol !in rules.protocols) return false
    }
    if (rules.ports.isNotEmpty()) {
        val transport = transport ?: return false
        if (transport.sourcePort !in rules.ports && transport.destinationPort !in rules.ports) return false
    }
    if (rules.hosts.isNotEmpty()) {
        val ip = ip ?: return false
        if (ip.sourceAddress !in rules.hosts && ip.destinationAddress !in rules.hosts) return false
    }
    return true
}
