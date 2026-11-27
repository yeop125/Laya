package com.music.laya.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/** The few lines a resolve has to say about itself. */
internal object DesktopTrackLog {

    private val clock = DateTimeFormatter.ofPattern("HH:mm:ss")

    /** `$XDG_STATE_HOME/laya/desktop.log`, or the usual default under $HOME. */
    private val file: Path? by lazy {
        runCatching {
            val state = System.getenv("XDG_STATE_HOME")?.takeIf { it.isNotBlank() }
                ?: "${System.getProperty("user.home")}/.local/state"
            val directory = Path.of(state, "laya")
            Files.createDirectories(directory)
            directory.resolve("desktop.log")
        }.getOrNull()
    }

    /**
     * Written on a thread of its own: the audio thread logs too (a transition, a converter), and an
     * open-append-close per line on Windows could hold it up long enough to be heard.
     */
    private val writer = java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "laya-log").apply { isDaemon = true }
    }

    fun log(line: String) {
        val stamped = "${LocalTime.now().format(clock)}  $line"
        runCatching {
            writer.execute {
                println("Laya: $stamped")
                val target = file ?: return@execute
                runCatching {
                    Files.writeString(
                        target,
                        stamped + System.lineSeparator(),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND,
                    )
                }
            }
        }
    }
}
