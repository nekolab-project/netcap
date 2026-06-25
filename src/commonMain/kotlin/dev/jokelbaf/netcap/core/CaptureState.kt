package dev.jokelbaf.netcap.core

/** High-level lifecycle of a capture session, surfaced to the UI. */
enum class CaptureState {
    /** No capture running. */
    IDLE,

    /** Permissions granted, TUN being established. */
    STARTING,

    /** Actively capturing and forwarding traffic. */
    RUNNING,

    /** Tearing down the TUN and engine. */
    STOPPING,
}
