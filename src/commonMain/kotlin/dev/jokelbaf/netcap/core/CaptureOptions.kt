package dev.jokelbaf.netcap.core

/**
 * How a capture should behave. Backends apply what they can: desktop honours all of it
 * (the [filter] becomes a kernel BPF program), while the mobile TUN ignores [snapLength]
 * and [promiscuous] and evaluates [filter] in software on the parsed packet.
 *
 * @property snapLength max bytes captured per packet (desktop); larger keeps full payloads.
 * @property promiscuous capture all visible traffic, not just this host's (desktop).
 */
class CaptureOptions(
    val filter: CaptureFilter? = null,
    val snapLength: Int = 65_536,
    val promiscuous: Boolean = false,
)

/**
 * Restricts which packets are reported. On desktop this is pushed into the kernel via BPF
 * (the most effective way to cut load); on mobile it filters what's surfaced (the engine
 * still forwards everything). A raw [Bpf] expression is desktop-only.
 */
sealed interface CaptureFilter {
    /** A literal libpcap/BPF filter expression, e.g. `"tcp port 443"`. Desktop only. */
    class Bpf(val expression: String) : CaptureFilter

    /** A structured filter that works on both desktop (compiled to BPF) and mobile (matched in code). */
    class Rules(
        val protocols: Set<TransportProtocol> = emptySet(),
        val ports: Set<Int> = emptySet(),
        val hosts: Set<String> = emptySet(),
    ) : CaptureFilter
}
