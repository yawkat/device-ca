package at.yawk.deviceca

import io.micronaut.context.annotation.Context
import io.micronaut.context.annotation.Value
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralSubtree
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.NameConstraints
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.slf4j.LoggerFactory
import java.io.Serializable
import java.io.StringWriter
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.InstantSource
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import kotlin.io.path.createDirectories
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.setPosixFilePermissions

fun toCertificate(holder: X509CertificateHolder): X509Certificate =
    JcaX509CertificateConverter().getCertificate(holder)

val GRACE_TIME: Duration = Duration.ofMinutes(30)
val INTERMEDIATE_ROLLOVER_PERIOD: Duration = Duration.ofDays(6)

private val LOG = LoggerFactory.getLogger(CaManager::class.java)

operator fun Duration.times(v: Long): Duration = multipliedBy(v)
operator fun Duration.div(v: Long): Duration = dividedBy(v)

@Context
class CaManager(
    @Value("\${storage}")
    private val storage: Path,
    @Value("\${local-key-path}")
    private val localKeyFile: Path,
    @Value("\${local-cert-path}")
    private val localCertFile: Path,
    private val clock: InstantSource,
    private val scheduler: TimeScheduler
) {
    private val certCache = ConcurrentHashMap<Path, X509Certificate>()

    private val certDir = storage.resolve("ca-certs")

    private val currentKeyFile = storage.resolve("current.key")
    private val nextKeyFile = storage.resolve("next.key")

    init {
        try {
            certDir.createDirectories()
        } catch (_: FileAlreadyExistsException) {
        }
        certDir.setPosixFilePermissions(PERMISSIONS)

        updateIntermediates()
    }

    private companion object {
        fun readPem(path: Path): Any {
            return PEMParser(Files.newBufferedReader(path)).use { pemReader ->
                pemReader.readObject()
            }
        }

        val PERMISSIONS = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
    }

    private fun getCert(path: Path): X509Certificate =
        certCache.computeIfAbsent(path) { toCertificate(readPem(it) as X509CertificateHolder) }

    private fun updateIntermediates() {
        var current = try {
            loadSigningKey(currentKeyFile)
        } catch (_: NoSuchFileException) {
            null
        }
        var next = try {
            loadSigningKey(nextKeyFile)
        } catch (_: NoSuchFileException) {
            null
        }
        val now = clock.instant()
        if (current != null && current.cert.notAfter.toInstant() < now + INTERMEDIATE_ROLLOVER_PERIOD) {
            // the current cert will expire within INTERMEDIATE_ROLLOVER_PERIOD, so we need to start signing with a new one
            current = null
            LOG.info("Discarded intermediate certificate $current because it will expire soon")
        }
        if (current == null) {
            if (next != null) {
                Files.move(nextKeyFile, currentKeyFile, StandardCopyOption.REPLACE_EXISTING)
                current = next
                next = null
                LOG.info("Rolled over to existing certificate $next")
            } else {
                Files.deleteIfExists(currentKeyFile)
                current = makeCaCertificate(now, currentKeyFile)
                LOG.info("Created new certificate $current for immediate use")
            }
        }
        if (next == null) {
            next = makeCaCertificate(current.end - INTERMEDIATE_ROLLOVER_PERIOD, nextKeyFile)
            LOG.info("Created new certificate $next for future use")
        }
        scheduler.schedule(next.start, this::updateIntermediates)

        refreshLocalCert(now, current)
    }

    private fun refreshLocalCert(now: Instant, currentIntermediate: CertAndKey) {
        try {
            val signingIntermediate = PEMParser(Files.newBufferedReader(localCertFile)).use { reader ->
                reader.readObject() as X509CertificateHolder
                reader.readObject() as X509CertificateHolder
            }
            if (signingIntermediate.serialNumber == currentIntermediate.cert.serialNumber) {
                LOG.info("Traefik certificate still up-to-date")
                return
            }
        } catch (_: NoSuchFileException) {
        }

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val localKeyPair = kpg.genKeyPair()
        val localCert = currentIntermediate.sign(
            now,
            SubjectPublicKeyInfo.getInstance(localKeyPair.public.encoded),
            "ca.local.yawk.at",
            lifetime = INTERMEDIATE_ROLLOVER_PERIOD * 2
        )
        Files.write(localCertFile, toPem(localCert, currentIntermediate.cert))
        Files.write(localKeyFile, toPem(localKeyPair.private))
        LOG.info("Generated new traefik certificate")
    }

    fun getAllCertificates() = certDir.listDirectoryEntries()
        .map { getCert(it) }
        .sortedBy { it.notAfter.toInstant() }

    @Synchronized
    fun getValidCertificates(): List<X509Certificate> {
        val now = clock.instant()
        return getAllCertificates().filter { !now.isAfter(it.notAfter.toInstant()) }
    }

    @Throws(NoSuchFileException::class)
    private fun loadSigningKey(path: Path): CertAndKey {
        return PEMParser(Files.newBufferedReader(path)).use { reader ->
            val pair = reader.readObject() as PEMKeyPair
            val cert = reader.readObject() as X509CertificateHolder
            CertAndKey(toCertificate(cert), JcaPEMKeyConverter().getPrivateKey(pair.privateKeyInfo))
        }
    }

    @Synchronized
    fun getSigningKey(): CertAndKey {
        return loadSigningKey(currentKeyFile)
    }

    private fun makeCaCertificate(from: Instant, privateLocation: Path): CertAndKey {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.genKeyPair()
        val principal = X500Principal("CN=ca@ca.local.yawk.at")
        val builder = JcaX509v3CertificateBuilder(
            principal,
            BigInteger(64, SecureRandom.getInstanceStrong()),
            Date.from(from.minus(GRACE_TIME)),
            Date.from(from.plus(INTERMEDIATE_ROLLOVER_PERIOD * 2)),
            principal,
            keyPair.public
        )
        builder.addExtension(
            Extension.nameConstraints, true, NameConstraints(
                arrayOf(GeneralSubtree(GeneralName(GeneralName.dNSName, "local.yawk.at"))),
                null
            )
        )
        builder.addExtension(Extension.keyUsage, false, KeyUsage(KeyUsage.keyCertSign))
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(1))
        builder.addExtension(Extension.subjectKeyIdentifier, false,
            BcX509ExtensionUtils().createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)))
        val holder = builder.build(
            JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.private)
        )
        val certificate = toCertificate(holder)
        certificate.verify(keyPair.public)
        val certAndKey = CertAndKey(certificate, keyPair.private)
        Files.write(
            certDir.resolve(certAndKey.uniqueName + ".pem"),
            toPem(certificate)
        )
        Files.createFile(privateLocation, PosixFilePermissions.asFileAttribute(PERMISSIONS))
        Files.write(privateLocation, toPem(keyPair.private, certificate))
        return certAndKey
    }

    private fun toPem(vararg obj: Serializable): ByteArray {
        val sw = StringWriter()
        JcaPEMWriter(sw).use {
            for (item in obj) {
                it.writeObject(item)
            }
        }
        return sw.toString().toByteArray()
    }
}