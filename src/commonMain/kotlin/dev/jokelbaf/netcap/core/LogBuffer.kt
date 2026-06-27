package dev.jokelbaf.netcap.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * A small, observable ring buffer of diagnostic log lines for display in the UI.
 * Useful where there's no console - notably the iOS Network Extension, whose
 * lines are relayed to the app via the shared snapshot.
 */
class LogBuffer(private val capacity: Int = DEFAULT_CAPACITY) {

    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines.asStateFlow()

    fun log(line: String) {
        _lines.update { current ->
            if (current.size < capacity) current + line
            else current.subList(current.size - capacity + 1, current.size) + line
        }
    }

    fun snapshot(): List<String> = _lines.value

    fun replaceWith(lines: List<String>) {
        _lines.value = lines
    }

    fun clear() {
        _lines.value = emptyList()
    }

    private companion object {
        const val DEFAULT_CAPACITY = 200
    }
}
