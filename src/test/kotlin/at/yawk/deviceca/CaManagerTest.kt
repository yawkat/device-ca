package at.yawk.deviceca

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.time.Instant
import java.time.InstantSource
import java.time.temporal.ChronoUnit
import java.util.Date

class CaManagerTest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun test() {
        val scheduler = object : TimeScheduler, InstantSource {
            var time = Instant.now()
                set(value) {
                    field = value
                    val scheduled = scheduled
                    if (scheduled != null && scheduled.first <= value) {
                        this.scheduled = null
                        scheduled.second.invoke()
                    }
                }

            private var scheduled: Pair<Instant, () -> Unit>? = null

            override fun schedule(time: Instant, task: () -> Unit) {
                assert(time > this.time)
                assert(scheduled == null)
                this.scheduled = Pair(time, task)
            }

            override fun instant() = time
        }
        val caManager = CaManager(
            tmp,
            tmp.resolve("traefik.crt"),
            tmp.resolve("traefik.key"),
            scheduler,
            scheduler
        )

        val certificates1 = caManager.getValidCertificates()
        assertEquals(2, certificates1.size)
        val key1 = caManager.getSigningKey()
        assertEquals(certificates1.first(), key1.cert)
        certificates1.first().checkValidity(Date.from(scheduler.time))
        assertEquals(
            scheduler.time.plus(INTERMEDIATE_ROLLOVER_PERIOD * 2).truncatedTo(ChronoUnit.SECONDS),
            certificates1.first().notAfter.toInstant()
        )

        scheduler.time += INTERMEDIATE_ROLLOVER_PERIOD * 4 / 3

        val certificates2 = caManager.getValidCertificates()
        assertEquals(3, certificates2.size)
        assertEquals(certificates1, certificates2.subList(0, 2))
        val key2 = caManager.getSigningKey()
        assertEquals(certificates2[1], key2.cert)
        certificates2.forEach { if (it.notBefore.toInstant() <= scheduler.time) it.checkValidity(Date.from(scheduler.time)) }

        scheduler.time += INTERMEDIATE_ROLLOVER_PERIOD * 4 / 3

        val key3 = caManager.getSigningKey()
        val certificates3 = caManager.getValidCertificates()
        assertEquals(3, certificates3.size)
        assertEquals(certificates2.subList(1, 3), certificates3.subList(0, 2))
        certificates3.forEach { if (it.notBefore.toInstant() <= scheduler.time) it.checkValidity(Date.from(scheduler.time)) }
        assertEquals(certificates3[1], key3.cert)
    }
}