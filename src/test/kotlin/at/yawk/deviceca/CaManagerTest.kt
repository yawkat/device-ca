package at.yawk.deviceca

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.time.InstantSource
import java.time.temporal.ChronoUnit
import java.util.Date

class CaManagerTest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun test() {
        var time = Instant.now()

        val clock = InstantSource { time }
        val certificateLifeTime = Duration.ofDays(30)
        val caManager = CaManager(
            tmp.resolve("ca-certs"),
            tmp.resolve("ca.key"),
            tmp.resolve("local.key"),
            tmp.resolve("local.pem"),
            clock,
            certificateLifeTime
        )

        val certificates1 = caManager.getValidCertificates()
        assertEquals(1, certificates1.size)
        val certificates2 = caManager.getValidCertificates()
        assertEquals(certificates1, certificates2)
        val key1 = caManager.getSigningKey()
        assertEquals(certificates1.single(), key1.cert)
        certificates1.single().checkValidity(Date.from(time))
        assertEquals(
            time.plus(certificateLifeTime).truncatedTo(ChronoUnit.SECONDS),
            certificates1.single().notAfter.toInstant()
        )

        time += Duration.ofDays(20)

        val certificates3 = caManager.getValidCertificates()
        assertEquals(2, certificates3.size)
        assertEquals(certificates1.single(), certificates3.first())
        val key2 = caManager.getSigningKey()
        assertEquals(certificates3.last(), key2.cert)
        certificates3.forEach { it.checkValidity(Date.from(time)) }

        time += Duration.ofDays(20)

        val key3 = caManager.getSigningKey()
        val certificates4 = caManager.getValidCertificates()
        assertEquals(2, certificates4.size)
        assertEquals(certificates3.last(), certificates4.first())
        certificates4.forEach { it.checkValidity(Date.from(time)) }
        assertEquals(certificates4.last(), key3.cert)
    }
}