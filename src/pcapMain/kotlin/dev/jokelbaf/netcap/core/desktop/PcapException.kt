package dev.jokelbaf.netcap.core.desktop

/** Raised when libpcap/npcap cannot be loaded, opened, or a call fails. */
class PcapException(message: String) : RuntimeException(message)
