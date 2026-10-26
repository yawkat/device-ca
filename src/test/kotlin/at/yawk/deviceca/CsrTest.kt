package at.yawk.deviceca

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.http.HttpStatus
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.runtime.server.EmbeddedServer
import jakarta.inject.Singleton
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.slf4j.LoggerFactory
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.readText

private val log = LoggerFactory.getLogger(CsrTest::class.java)

class CsrTest {
    @TempDir
    lateinit var storage: Path
    @TempDir
    lateinit var tmp: Path

    private fun createContext() = ApplicationContext.run(mapOf(
        "storage" to storage.toString(),
        "local-key-path" to storage.resolve("local.key").toString(),
        "local-cert-path" to storage.resolve("local.pem").toString(),
    ))

    @Test
    fun `normal flow`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        ctx.getBean(MockResolver::class.java).expectedDnsName = "test.local.yawk.at"
        ctx.getBean(MockResolver::class.java).expectedIp = "1.2.3.4"

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        run("curl -fsSO ${server.uri}/ca.tar")
        run("tar xf ca.tar")
        run("openssl verify -CAfile 0.pem chain.pem")

        run("mv private.key old.key")
        createCsr("/CN=test.local.yawk.at")
        renew(ctx, "1.2.3.4")

        run("openssl verify -CAfile 0.pem chain.pem")
    }

    @Test
    fun `upn flow`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        ctx.getBean(MockResolver::class.java).expectedDnsName = "test.local.yawk.at"
        ctx.getBean(MockResolver::class.java).expectedIp = "1.2.3.4"

        createCsr("/CN=foo@test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        run("curl -fsSO ${server.uri}/ca.tar")
        run("tar xf ca.tar")
        run("openssl verify -CAfile 0.pem chain.pem")
        run("openssl x509 -in chain.pem -text | grep -E 'UPN::?foo@test.local.yawk.at'")
    }

    @Test
    fun `enrollment failure cn out of scope`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=test.yawk.at")
        enroll(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Bad CN"))
    }

    @Test
    fun `enrollment failure cn weird`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=x_.local.yawk.at")
        enroll(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Bad CN"))
    }

    @Test
    fun `enrollment failure cn does not resolve to request ip`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        ctx.getBean(MockResolver::class.java).expectedDnsName = "test.local.yawk.at"
        ctx.getBean(MockResolver::class.java).expectedIp = "1.2.3.4"
        ctx.getBean(MockResolver::class.java).result = false

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Requesting IP does not match"))
    }

    @Test
    fun `enrollment failure duplicate enrollment`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        ctx.getBean(MockResolver::class.java).expectedDnsName = "test.local.yawk.at"
        ctx.getBean(MockResolver::class.java).expectedIp = "1.2.3.4"

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")
        enroll(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Already enrolled"))
    }

    @Test
    fun `public flow`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        ctx.getBean(MockResolver::class.java).expectedDnsName = "test.local.yawk.at"
        ctx.getBean(MockResolver::class.java).expectedIp = "1.2.3.4"

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")
        public(ctx, "1.2.3.4")
        Assertions.assertEquals("public chain", tmp.resolve("public.pem").readText())
        Assertions.assertEquals(listOf("test.local.yawk.at"), ctx.getBean(MockIssuer::class.java).issued)
    }

    @Test
    fun `public failure without client cert`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")
        run("curl --fail-with-body -H 'X-Forwarded-For: 1.2.3.4' -H 'content-type: application/x-pem-file' --data-binary @public.csr ${server.uri}/csr/public > public.pem", 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Missing client certificate"))
        Assertions.assertEquals(emptyList<String>(), ctx.getBean(MockIssuer::class.java).issued)
    }

    @Test
    fun `public failure expired client cert`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        ctx.getBean(MockClock::class.java).time += Duration.ofDays(2)
        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Client certificate not valid"))
    }

    @Test
    fun `public failure cert for other name`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")
        createCsr("/CN=other.local.yawk.at")
        run("mv chain.pem test.pem")
        enroll(ctx, "1.2.3.4")
        run("mv test.pem chain.pem")

        createPublicCsr("/CN=other.local.yawk.at", "DNS:other.local.yawk.at")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Original cert unknown"))
    }

    @Test
    fun `public failure upn`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=foo@test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        createPublicCsr("/CN=foo@test.local.yawk.at", "DNS:foo@test.local.yawk.at")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Not a host name"))
    }

    @Test
    fun `public failure bad csr`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at,DNS:yawk.at")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("SAN must be exactly the CN"))

        createPublicCsr("/CN=test.local.yawk.at", "IP:1.2.3.4")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("SAN must be exactly the CN"))

        createPublicCsr("/CN=test.local.yawk.at", null)
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("CSR must only request the SAN extension"))

        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at", "-addext keyUsage=digitalSignature")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("CSR must only request the SAN extension"))

        createPublicCsr("/CN=test.local.yawk.at/O=yawkat", "DNS:test.local.yawk.at")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Subject must only contain the CN"))

        Assertions.assertEquals(emptyList<String>(), ctx.getBean(MockIssuer::class.java).issued)
    }

    @Test
    fun `public rate limit`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()
        val clock = ctx.getBean(MockClock::class.java)

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")
        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")

        // one attempt per interval
        public(ctx, "1.2.3.4")
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Too many requests"))

        // and a few issued certificates per week
        repeat(IssuanceLimiter.MAX_ISSUED - 1) {
            clock.time += IssuanceLimiter.MIN_INTERVAL
            public(ctx, "1.2.3.4")
        }
        clock.time += IssuanceLimiter.MIN_INTERVAL
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("Too many requests"))
        Assertions.assertEquals(IssuanceLimiter.MAX_ISSUED, ctx.getBean(MockIssuer::class.java).issued.size)
    }

    @Test
    fun `public failures only count towards the interval`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()
        val clock = ctx.getBean(MockClock::class.java)
        val issuer = ctx.getBean(MockIssuer::class.java)

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")
        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")

        issuer.failure = IllegalStateException("challenge failed")
        repeat(IssuanceLimiter.MAX_ISSUED + 2) {
            public(ctx, "1.2.3.4", exit = 22)
            Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("challenge failed"))
            clock.time += IssuanceLimiter.MIN_INTERVAL
        }
        issuer.failure = null
        public(ctx, "1.2.3.4")
    }

    @Test
    fun `public unavailable does not count`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()
        val issuer = ctx.getBean(MockIssuer::class.java)

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")
        createPublicCsr("/CN=test.local.yawk.at", "DNS:test.local.yawk.at")

        issuer.available = false
        public(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("public.pem").readText().contains("No DNS credentials configured"))
        issuer.available = true
        public(ctx, "1.2.3.4")
    }

    @Test
    fun `renewal grace`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()
        val clock = ctx.getBean(MockClock::class.java)

        createCsr("/CN=test.local.yawk.at")
        enroll(ctx, "1.2.3.4")

        // a host that was offline for a while can still renew
        clock.time += Duration.ofDays(10)
        createCsr("/CN=test.local.yawk.at")
        renew(ctx, "1.2.3.4")

        // but not forever
        clock.time += RENEW_GRACE + Duration.ofDays(2)
        createCsr("/CN=test.local.yawk.at")
        renew(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Client certificate not valid"))
    }

    @Test
    fun `bad csr body`(): Unit = createContext().use { ctx ->
        val server = ctx.getBean(EmbeddedServer::class.java)
        server.start()

        run("echo garbage > csr.pem")
        enroll(ctx, "1.2.3.4", exit = 22)
        Assertions.assertTrue(tmp.resolve("chain.pem").readText().contains("Bad CSR"))
    }

    private fun createPublicCsr(subj: String, san: String?, @Language("bash") extra: String = "") {
        val addext = if (san == null) "" else "-addext 'subjectAltName=$san'"
        run("openssl req -subj '$subj' $addext $extra -newkey rsa:2048 -keyout public.key -passout 'pass:' -out public.csr")
    }

    private fun public(ctx: ApplicationContext, ip: String, exit: Int = 0) {
        run("curl --fail-with-body -H 'X-Forwarded-For: $ip' -H 'x-forwarded-tls-client-cert: ${toTraefikFormat(tmp.resolve("chain.pem").readText())}' -H 'content-type: application/x-pem-file' --data-binary @public.csr ${ctx.getBean(EmbeddedServer::class.java).uri}/csr/public > public.pem", exit)
    }

    private fun createCsr(subj: String) {
        run("openssl req -subj '$subj' -newkey rsa:2048 -keyout private.key -passout 'pass:' -out csr.pem")
    }

    private fun enroll(ctx: ApplicationContext, ip: String, exit: Int = 0) {
        run("curl --fail-with-body -H 'X-Forwarded-For: $ip' -H 'content-type: application/x-pem-file' --data-binary @csr.pem ${ctx.getBean(EmbeddedServer::class.java).uri}/csr/enroll > chain.pem", exit)
    }

    private fun renew(ctx: ApplicationContext, ip: String, exit: Int = 0) {
        run("curl --fail-with-body -H 'X-Forwarded-For: $ip' -H 'x-forwarded-tls-client-cert: ${toTraefikFormat(tmp.resolve("chain.pem").readText())}' -H 'content-type: application/x-pem-file' --data-binary @csr.pem ${ctx.getBean(EmbeddedServer::class.java).uri}/csr/renew > chain.pem", exit)
    }

    private fun run(@Language("bash") cmd: String, exit: Int = 0) {
        log.info("$ $cmd")
        val proc = ProcessBuilder("sh", "-c", cmd)
            .directory(tmp.toFile())
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.PIPE)
            .start()
        Thread.ofVirtual().start {
            BufferedReader(InputStreamReader(proc.inputStream)).useLines {
                for (string in it) {
                    log.info(string)
                }
            }
        }
        val ret = proc.waitFor()
        Assertions.assertEquals(exit, ret)
    }

    @Singleton
    @Replaces(LetsEncryptIssuer::class)
    class MockIssuer : AcmeIssuer {
        val issued = mutableListOf<String>()
        var available = true
        var failure: Exception? = null

        override fun prepare() {
            if (!available) {
                throw HttpStatusException(HttpStatus.SERVICE_UNAVAILABLE, "No DNS credentials configured")
            }
        }

        override fun issue(name: String, csr: PKCS10CertificationRequest): String {
            failure?.let { throw it }
            issued.add(name)
            return "public chain"
        }
    }

    @Singleton
    @Replaces(Resolver::class)
    class MockResolver : Resolver() {
        var expectedDnsName: String? = null
        var expectedIp: String? = null
        var result = true

        override fun matches(dnsName: String, ip: InetAddress): Boolean {
            if (expectedDnsName != null) {
                Assertions.assertEquals(expectedDnsName, dnsName)
            }
            if (expectedIp != null) {
                Assertions.assertEquals(expectedIp, ip.hostAddress)
            }
            return result
        }
    }
}