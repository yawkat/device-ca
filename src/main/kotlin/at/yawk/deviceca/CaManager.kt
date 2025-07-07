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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringWriter
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.InstantSource
import java.time.ZoneOffset
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import kotlin.io.path.createDirectories
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.setPosixFilePermissions

fun toCertificate(holder: X509CertificateHolder) =
    JcaX509CertificateConverter().getCertificate(holder)

@Context
class CaManager(
    @Value("\${storage}/ca-certs")
    private val certDir: Path,
    @Value("\${storage}/ca.key")
    private val keyFile: Path,
    @Value("\${local-key-path}")
    private val localKeyFile: Path,
    @Value("\${local-cert-path}")
    private val localCertFile: Path,
    private val clock: InstantSource,
    @Value("\${ca-life-time}")
    private val certificateLifeTime: Duration
) {
    private val certCache = ConcurrentHashMap<Path, X509Certificate>()
    private var certificates: List<CertAndKey>

    init {
        try {
            certDir.createDirectories()
        } catch (_: FileAlreadyExistsException) {
        }
        certDir.setPosixFilePermissions(PERMISSIONS)

        val certificates = ArrayList<CertAndKey>()
        for (keyFile in certDir.listDirectoryEntries("*.key")) {
            val certFile = keyFile.parent.resolve(keyFile.nameWithoutExtension + ".pem")
            if (!Files.exists(certFile)) {
                throw IllegalArgumentException("Certificate file does not exist: $certFile")
            }
            certificates.add(
                CertAndKey(
                    readPem(certFile) as X509Certificate,
                    readPem(keyFile) as PrivateKey
                )
            )
        }
        certificates.sortBy { it.cert.notAfter.toInstant() }
        this.certificates = certificates
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

    fun getAllCertificates() = certDir.listDirectoryEntries()
        .map { getCert(it) }
        .sortedBy { it.notAfter.toInstant() }

    @Synchronized
    fun getValidCertificates(): List<X509Certificate> {
        val now = clock.instant()
        var certs = getAllCertificates()
        if (certs.isEmpty() || isObsolete(now, certs.last())) {
            generate(now)
            certs = getAllCertificates()
        }

        return certs.filter { !now.isAfter(it.notAfter.toInstant()) }
    }

    @Synchronized
    fun getSigningKey(): CertAndKey {
        val now = clock.instant()
        for (i in 0..1) {
            val current = try {
                PEMParser(Files.newBufferedReader(keyFile)).use { reader ->
                    val pair = reader.readObject() as PEMKeyPair
                    val cert = reader.readObject() as X509CertificateHolder
                    CertAndKey(toCertificate(cert), JcaPEMKeyConverter().getPrivateKey(pair.privateKeyInfo))
                }
            } catch (_: NoSuchFileException) {
                null
            }
            if (current == null || isObsolete(now, current.cert)) {
                generate(now)
            } else {
                return current
            }
        }
        throw IllegalStateException("New cert already obsolete?")
    }

    private fun isObsolete(now: Instant, cert: X509Certificate) =
        now.plus(certificateLifeTime.dividedBy(2)).isAfter(cert.notAfter.toInstant())

    private fun generate(now: Instant) {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.genKeyPair()
        val certificate = makeCaCertificate(now, keyPair)

        val certBytes = toPem(certificate)
        val keyBytes = toPem(keyPair.private, certificate)
        val pemFile = certDir.resolve(
            now.atOffset(ZoneOffset.UTC).toLocalDate().toString() + "_" + certificate.serialNumber + ".pem"
        )

        val localKeyPair = kpg.genKeyPair()
        val localCertificate = CertAndKey(certificate, keyPair.private)
            .sign(now, SubjectPublicKeyInfo.getInstance(localKeyPair.public.encoded), "ca.local.yawk.at", lifetime = certificateLifeTime)
        JcaPEMWriter(Files.newBufferedWriter(localCertFile)).use {
            it.writeObject(localCertificate)
            it.writeObject(certificate)
        }
        JcaPEMWriter(Files.newBufferedWriter(localKeyFile)).use {
            it.writeObject(localKeyPair.private)
        }

        Files.write(pemFile, certBytes)
        val tmp = Files.createTempFile(
            keyFile.parent,
            keyFile.fileName.toString(),
            null,
            PosixFilePermissions.asFileAttribute(PERMISSIONS)
        )
        Files.write(tmp, keyBytes)
        Files.move(tmp, keyFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    private fun makeCaCertificate(now: Instant, keyPair: KeyPair): X509Certificate {
        val principal = X500Principal("CN=root@ca.local.yawk.at")
        val builder = JcaX509v3CertificateBuilder(
            principal,
            BigInteger(64, SecureRandom.getInstanceStrong()),
            Date.from(now.minus(Duration.ofMinutes(30))),
            Date.from(now.plus(certificateLifeTime)),
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
        val holder = builder.build(
            JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.private)
        )
        val certificate = toCertificate(holder)
        certificate.verify(keyPair.public)
        return certificate
    }

    private fun toPem(vararg obj: Any): ByteArray {
        val sw = StringWriter()
        JcaPEMWriter(sw).use {
            for (item in obj) {
                it.writeObject(item)
            }
        }
        return sw.toString().toByteArray()
    }
}