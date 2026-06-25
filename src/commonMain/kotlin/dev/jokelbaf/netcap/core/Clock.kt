package dev.jokelbaf.netcap.core

import kotlin.time.Clock

/** Wall-clock milliseconds, multiplatform (no expect/actual needed). */
internal fun currentTimeMillis(): Long = Clock.System.now().toEpochMilliseconds()
