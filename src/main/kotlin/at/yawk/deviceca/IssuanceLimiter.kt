package at.yawk.deviceca

import io.micronaut.context.annotation.Value
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.time.Instant
import java.time.InstantSource
import kotlin.io.path.createDirectories
import kotlin.io.path.readLines
import kotlin.io.path.writeLines

private val LOG = LoggerFactory.getLogger(IssuanceLimiter::class.java)

/**
 * Limits public certificate requests per name, so that a compromised host can't use up the account's or the
 * registered domain's Let's Encrypt limits for the others: at most one attempt (an ACME order) per [MIN_INTERVAL], and
 * at most [MAX_ISSUED] issued certificates per [PERIOD], below Let's Encrypt's 5 duplicate certificates per week. A
 * shortlived certificate renewed at a third of its lifetime needs fewer than two per week. Failed attempts only count
 * towards the interval, so a host can retry an outage hourly without locking itself out.
 */
@Singleton
class IssuanceLimiter(
    @Value("\${storage}/acme/attempts")
    private val storage: Path,
    private val clock: InstantSource,
) {
    companion object {
        // a bit less than the clients' hourly timer
        val MIN_INTERVAL: Duration = Duration.ofMinutes(50)
        const val MAX_ISSUED = 3
        val PERIOD: Duration = Duration.ofDays(7)

        private const val ATTEMPT = "attempt"
        private const val ISSUED = "issued"
    }

    private data class Event(val kind: String, val time: Instant)

    private fun read(name: String): List<Event> {
        val lines = try {
            storage.resolve(name).readLines()
        } catch (_: NoSuchFileException) {
            return emptyList()
        }
        return lines.mapNotNull { line ->
            val parts = line.split(' ')
            try {
                Event(parts[0], Instant.parse(parts[1]))
            } catch (_: Exception) {
                // e.g. a partial line from a crash, don't lock the name out over it
                LOG.warn("Ignoring bad line in the attempts of {}: {}", name, line)
                null
            }
        }
    }

    private fun write(name: String, events: List<Event>) {
        storage.createDirectories()
        val tmp = Files.createTempFile(storage, name, ".tmp")
        tmp.writeLines(events.map { "${it.kind} ${it.time}" })
        Files.move(tmp, storage.resolve(name), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    private fun recent(name: String, now: Instant) = read(name).filter { it.time > now - PERIOD }

    /**
     * Record an attempt for [name], unless the limits forbid one.
     */
    @Synchronized
    fun tryAcquire(name: String): Boolean {
        val now = clock.instant()
        val recent = recent(name, now)
        if (recent.any { it.kind == ATTEMPT && it.time > now - MIN_INTERVAL } ||
            recent.count { it.kind == ISSUED } >= MAX_ISSUED) {
            return false
        }
        write(name, recent + Event(ATTEMPT, now))
        return true
    }

    @Synchronized
    fun recordIssued(name: String) {
        val now = clock.instant()
        write(name, recent(name, now) + Event(ISSUED, now))
    }
}
