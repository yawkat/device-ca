package at.yawk.deviceca

import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Header
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.exceptions.HttpStatusException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.io.pem.PemReader
import org.slf4j.LoggerFactory
import java.io.StringReader
import java.io.StringWriter
import java.net.InetAddress
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Duration
import java.time.InstantSource
import java.time.temporal.ChronoUnit
import java.util.UUID
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.deleteExisting
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeText

private val log = LoggerFactory.getLogger(CsrController::class.java)

fun toTraefikFormat(pem: String): String {
    val out = StringBuilder()
    PemReader(StringReader(pem)).use {
        while (true) {
            val obj = it.readPemObject() ?: break
            if (out.isNotEmpty()) out.append(',')
            out.append(Base64.encode(obj.content).toString(Charsets.UTF_8))
        }
    }
    return out.toString()
}

private fun traefikStartsWith(chain: String, clientCert: String) =
    chain == clientCert || chain.startsWith("$clientCert,")

private val CN_PATTERN = "(?:[a-z0-9]+@)?([a-z0-9.\\-]+\\.local\\.yawk\\.at)".toRegex()
private val OID_UPN_NAME = ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

@Controller("/csr")
class CsrController(
    private val caManager: CaManager,
    private val clock: InstantSource,
    private val resolver: Resolver,
    @Value("\${storage}/leafCerts")
    private val leafStorage: Path
) {
    init {
        try {
            leafStorage.createDirectories()
        } catch (_: FileAlreadyExistsException) {
        }
    }

    private fun fail(msg: String): Nothing {
        log.warn("Failed to process CSR: $msg")
        throw HttpStatusException(HttpStatus.BAD_REQUEST, msg)
    }

    /**
     * Enroll in the certificate service. Only allowed if the CN has not been enrolled before. Authentication via user
     * IP.
     */
    @Post("/enroll")
    @Produces("application/x-pem-file")
    @Consumes("application/x-pem-file")
    fun enroll(@Header("x-forwarded-for") userIp: String?, @Body body: String): String {
        return run(null, userIp, body, false)
    }

    /**
     * Renew a certificate. Authentication via a previous cert.
     */
    @Post("/renew")
    @Produces("application/x-pem-file")
    @Consumes("application/x-pem-file")
    fun renew(
        @Header("x-forwarded-for") userIp: String?,
        @Header("x-forwarded-tls-client-cert") clientCert: String?,
        @Body body: String
    ): String {
        return run(clientCert, userIp, body, true)
    }

    /**
     * Remove all certs for a client except the one it's connecting with, preventing those certs from being used in
     * future renewals.
     */
    @Post("/pin")
    fun pin(@Header("x-forwarded-for") userIp: String?, @Header("x-forwarded-tls-client-cert") clientCert: String) {
        val begin = "-----BEGIN CERTIFICATE-----"
        val end = "-----END CERTIFICATE-----"
        val pem = begin + "\n" + clientCert.replace(",", "\n$end\n$begin\n") + "\n" + end
        val holder = PEMParser(StringReader(pem)).use { it.readObject() as X509CertificateHolder }
        val cert = toCertificate(holder)
        val cn = getAndCheckCn(userIp, X500Name.getInstance(cert.subjectX500Principal.encoded))
        log.info("Pinned cert for {}", cn)
        val dir = leafStorage.resolve(cn)
        val item = dir.listDirectoryEntries().single { traefikStartsWith(toTraefikFormat(it.readText()), clientCert) }
        for (f in dir.listDirectoryEntries()) {
            if (f != item) {
                f.deleteExisting()
            }
        }
    }

    private fun run(
        @Header("x-forwarded-tls-client-cert") clientCert: String?,
        @Header("x-forwarded-for") userIp: String?,
        @Body body: String,
        renew: Boolean
    ): String {
        val csr = PEMParser(StringReader(body)).use { it.readObject() as PKCS10CertificationRequest }
        val signingKey = caManager.getSigningKey()
        val cn = getAndCheckCn(userIp, csr.subject)
        val dir = leafStorage.resolve(cn)

        if (renew) {
            if (clientCert == null) {
                fail("Missing client certificate")
            }
            if (dir.listDirectoryEntries().none { traefikStartsWith(toTraefikFormat(it.readText()), clientCert) }) {
                fail("Original cert unknown")
            }
            // above check implies that the CN matches.
        }

        val certificate = signingKey.sign(
            clock.instant().minus(30, ChronoUnit.MINUTES),
            csr.subjectPublicKeyInfo,
            cn,
            if (cn.contains('@')) GeneralName(
                GeneralName.otherName, DERSequence(
                    OID_UPN_NAME,
                    DERTaggedObject(
                        0, DERUTF8String(cn)
                    )
                )
            )
            else GeneralName(GeneralName.dNSName, cn),
            lifetime = Duration.ofDays(1)
        )
        val sw = StringWriter()
        JcaPEMWriter(sw).use {
            it.writeObject(certificate)
            it.writeObject(signingKey.cert)
        }
        try {
            dir.createDirectory()
        } catch (_: FileAlreadyExistsException) {
            if (!renew) {
                fail("Already enrolled")
            }
        }
        dir.resolve(UUID.randomUUID().toString() + ".pem")
            .writeText(sw.toString(), Charsets.UTF_8, StandardOpenOption.CREATE_NEW)
        log.info("{} cert for {}", if (renew) "Renewed" else "Enrolled", cn)
        return sw.toString()
    }

    private fun getAndCheckCn(userIp: String?, subj: X500Name): String {
        val cn = IETFUtils.valueToString(subj.getRDNs(BCStyle.CN).first().first.value)
        val matcher = CN_PATTERN.matchEntire(cn)
        if (matcher == null) {
            fail("Bad CN")
        }
        if (userIp == null || !resolver.matches(matcher.groupValues[1], InetAddress.getByName(userIp))) {
            fail("Requesting IP does not match")
        }
        return cn
    }
}