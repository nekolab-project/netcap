package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureFilter

/** The default desktop filter: only IPv4/IPv6 TCP or UDP, so we never see ARP/ICMP/etc. */
internal const val DEFAULT_BPF = "(ip or ip6) and (tcp or udp)"

/** Translates a [CaptureFilter] into a libpcap BPF expression. Null means the [DEFAULT_BPF]. */
internal fun CaptureFilter?.toBpf(): String = when (this) {
    null -> DEFAULT_BPF
    is CaptureFilter.Bpf -> expression
    is CaptureFilter.Rules -> {
        val clauses = buildList {
            if (protocols.isNotEmpty()) add(protocols.joinToString(" or ", "(", ")") { it.name.lowercase() })
            if (ports.isNotEmpty()) add(ports.joinToString(" or ", "(", ")") { "port $it" })
            if (hosts.isNotEmpty()) add(hosts.joinToString(" or ", "(", ")") { "host $it" })
        }
        if (clauses.isEmpty()) "ip or ip6" else clauses.joinToString(" and ")
    }
}
