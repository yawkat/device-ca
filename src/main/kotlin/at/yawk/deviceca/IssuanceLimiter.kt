package at.yawk.deviceca

import jakarta.inject.Singleton
import java.time.Duration
import java.time.Instant
import java.time.InstantSource

/**
 * Limits public certificate requests per name, so that a compromised host can't use up the account's or the
 * registered domain's Let's Encrypt limits for the others: at most one attempt (an ACME order) per [MIN_INTERVAL], and
 * at most [MAX_ISSUED] issued certificates per [PERIOD], below Let's Encrypt's 5 duplicate certificates per week. A
 * shortlived certificate renewed at a third of its lifetime needs fewer than two per week. Failed attempts only count
 * towards the interval, so a host can retry an outage hourly without locking itself out.
 *
 * Only in memory: the CA is rarely restarted.
 */
@Singleton
class IssuanceLimiter(private val clock: InstantSource) {
    companion object {
        // a bit less than the clients' hourly timer
        val MIN_INTERVAL: Duration = Duration.ofMinutes(50)
        const val MAX_ISSUED = 3
        val PERIOD: Duration = Duration.ofDays(7)
    }

    private val lastAttempt = HashMap<String, Instant>()
    private val issued = HashMap<String, MutableList<Instant>>()

    /**
     * Record an attempt for [name], unless the limits forbid one.
     */
    @Synchronized
    fun tryAcquire(name: String): Boolean {
        val now = clock.instant()
        val recentIssued = issued[name]?.count { it > now - PERIOD } ?: 0
        if (lastAttempt[name]?.let { it > now - MIN_INTERVAL } == true || recentIssued >= MAX_ISSUED) {
            return false
        }
        lastAttempt[name] = now
        return true
    }

    @Synchronized
    fun recordIssued(name: String) {
        val now = clock.instant()
        val list = issued.getOrPut(name) { ArrayList() }
        list.removeIf { it <= now - PERIOD }
        list.add(now)
    }
}
