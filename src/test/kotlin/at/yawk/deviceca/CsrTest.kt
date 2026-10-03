package at.yawk.deviceca

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.runtime.server.EmbeddedServer
import jakarta.inject.Singleton
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.slf4j.LoggerFactory
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.nio.file.Path
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