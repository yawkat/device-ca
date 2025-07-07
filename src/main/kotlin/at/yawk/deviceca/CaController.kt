package at.yawk.deviceca

import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter

@Controller("/ca.tar")
class CaController(private val caManager: CaManager) {
    @Get
    @Produces("application/x-tar")
    fun getCertificates(): ByteArray {
        val baos = ByteArrayOutputStream()
        TarArchiveOutputStream(baos).use {
            for ((i, certificate) in caManager.getValidCertificates().withIndex()) {
                val baos = ByteArrayOutputStream()
                JcaPEMWriter(OutputStreamWriter(baos)).use { pem ->
                    pem.writeObject(certificate)
                }
                val entry = TarArchiveEntry("$i.pem")
                entry.size = baos.size().toLong()
                it.putArchiveEntry(entry)
                it.write(baos.toByteArray())
                it.closeArchiveEntry()
            }
        }
        return baos.toByteArray()
    }
}