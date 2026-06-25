package dev.jokelbaf.netcap.core.desktop

/**
 * A capture-capable network interface as reported by `pcap_findalldevs`.
 *
 * @property name the system device name to open (e.g. `eth0`, or `\Device\NPF_{…}` on Windows).
 * @property description a human-readable label, when the platform provides one.
 */
data class PcapDevice(val name: String, val description: String?)
