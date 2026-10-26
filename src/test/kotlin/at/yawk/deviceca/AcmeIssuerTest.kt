package at.yawk.deviceca

import io.micronaut.http.HttpStatus
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.context.ApplicationContext
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.Signature
import kotlin.io.path.exists
import kotlin.io.path.getPosixFilePermissions
import kotlin.io.path.listDirectoryEntries

class AcmeIssuerTest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun `account key survives a restart`() {
        val path = tmp.resolve("acme/account.key")
        val created = loadOrCreateKeyPair(path)
        val loaded = loadOrCreateKeyPair(path)
        Assertions.assertEquals(created.public, loaded.public)
        val signature = Signature.getInstance("SHA384withECDSA")
        signature.initSign(loaded.private)
        signature.update(byteArrayOf(1))
        val sig = signature.sign()
        signature.initVerify(created.public)
        signature.update(byteArrayOf(1))
        Assertions.assertTrue(signature.verify(sig))
        Assertions.assertEquals("rw-------", PosixFilePermissions.toString(path.getPosixFilePermissions()))
        Assertions.assertEquals(listOf(path), path.parent.listDirectoryEntries())
    }

    @Test
    fun `unavailable without token`() {
        for (tokenFile in listOf("", tmp.resolve("missing").toString())) {
            val storage = tmp.resolve("storage-${tokenFile.length}")
            ApplicationContext.run(mapOf(
                "storage" to storage.toString(),
                "local-key-path" to storage.resolve("local.key").toString(),
                "local-cert-path" to storage.resolve("local.pem").toString(),
                "cloudflare.token-file" to tokenFile,
            )).use { ctx ->
                val e = Assertions.assertThrows(HttpStatusException::class.java) {
                    ctx.getBean(LetsEncryptIssuer::class.java).prepare()
                }
                Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE, e.status)
            }
            // nothing was created on the way
            Assertions.assertFalse(storage.resolve("acme").exists())
        }
    }
}
