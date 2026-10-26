package at.yawk.deviceca

import io.micronaut.http.HttpStatus
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.json.JsonMapper
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.Signature
import java.time.InstantSource
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

    private fun issuer(tokenFile: String) = LetsEncryptIssuer(
        tmp, "acme://letsencrypt.org/staging", "http://127.0.0.1:1", tokenFile, JsonMapper.createDefault(),
        InstantSource.system()
    )

    @Test
    fun `unavailable without token`() {
        for (tokenFile in listOf("", tmp.resolve("missing").toString())) {
            val e = Assertions.assertThrows(HttpStatusException::class.java) { issuer(tokenFile).prepare() }
            Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE, e.status)
        }
        // nothing was created on the way
        Assertions.assertEquals(emptyList<Path>(), tmp.listDirectoryEntries())
    }
}
