package at.yawk.deviceca

import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpStatus
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.json.JsonMapper
import jakarta.inject.Singleton
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Login
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.challenge.Dns01Challenge
import org.slf4j.LoggerFactory
import java.io.IOException
import java.io.StringWriter
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.InstantSource
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

private val LOG = LoggerFactory.getLogger(AcmeIssuer::class.java)

/**
 * Zone that the `_acme-challenge` CNAMEs of the local names point into, e.g.
 * `_acme-challenge.paperless.local.yawk.at CNAME paperless._acme.cats.coffee`. The Cloudflare token can only write
 * here, so only names with such a CNAME can get a certificate.
 */
const val CHALLENGE_ZONE = "cats.coffee"

/**
 * Gets publicly trusted certificates for local names.
 */
interface AcmeIssuer {
    /**
     * Check that certificates can be issued at all, before the caller spends a rate limit attempt on it. Throws if
     * not.
     */
    fun prepare() {
    }

    /**
     * Get a certificate for [name] from the CSR, which the caller has checked. Returns the PEM chain.
     */
    fun issue(name: String, csr: PKCS10CertificationRequest): String
}

/**
 * Load a key pair stored by this function, or create and store a new EC one. Stored as PKCS#8 and SPKI: an EC key from
 * the JDK provider loses its curve in the `EC PRIVATE KEY` format that acme4j's KeyPairUtils writes.
 */
fun loadOrCreateKeyPair(path: Path): KeyPair {
    try {
        return PEMParser(Files.newBufferedReader(path)).use { reader ->
            val converter = JcaPEMKeyConverter()
            val private = converter.getPrivateKey(reader.readObject() as PrivateKeyInfo)
            val public = converter.getPublicKey(reader.readObject() as SubjectPublicKeyInfo)
            KeyPair(public, private)
        }
    } catch (_: NoSuchFileException) {
    }
    // not KeyPairUtils.createKeyPair, that needs the BouncyCastle provider registered
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp384r1"))
    val keyPair = kpg.genKeyPair()
    val sw = StringWriter()
    JcaPEMWriter(sw).use {
        it.writeObject(JcaPKCS8Generator(keyPair.private, null))
        it.writeObject(keyPair.public)
    }
    path.parent.createDirectories()
    // complete or not at all, a partial file would not be replaced
    val tmp = Files.createTempFile(
        path.parent, path.fileName.toString(), ".tmp",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
    )
    tmp.writeText(sw.toString())
    Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE)
    return keyPair
}

@Singleton
class LetsEncryptIssuer(
    @Value("\${storage}/acme")
    private val storage: Path,
    @Value("\${acme.directory}")
    private val directory: String,
    @Value("\${cloudflare.api-url}")
    private val cloudflareApiUrl: String,
    @Value("\${cloudflare.token-file:}")
    private val cloudflareTokenFile: String,
    private val json: JsonMapper,
    private val clock: InstantSource,
) : AcmeIssuer {
    private val cloudflare by lazy {
        val token = try {
            if (cloudflareTokenFile.isEmpty()) null else Path.of(cloudflareTokenFile).readText().trim()
        } catch (_: NoSuchFileException) {
            null
        }
        if (token.isNullOrEmpty()) null else Cloudflare(cloudflareApiUrl, token, CHALLENGE_ZONE, json)
    }

    private val login: Login by lazy {
        val keyPath = storage.resolve("account.key")
        val created = !keyPath.exists()
        val login = AccountBuilder()
            .agreeToTermsOfService()
            .useKeyPair(loadOrCreateKeyPair(keyPath))
            .createLogin(Session(directory))
        if (created) {
            LOG.info("Created ACME account key")
        }
        // needed for the CAA accounturi parameter
        LOG.info("Using ACME account {}", login.account.location)
        login
    }

    override fun prepare() {
        if (cloudflare == null) {
            throw HttpStatusException(HttpStatus.SERVICE_UNAVAILABLE, "No DNS credentials configured")
        }
        login
    }

    @Synchronized
    override fun issue(name: String, csr: PKCS10CertificationRequest): String {
        prepare()
        val cloudflare = cloudflare!!

        val order = login.newOrder().domain(name).profile("shortlived").create()
        for (auth in order.authorizations) {
            if (auth.status == Status.VALID) {
                continue
            }
            val challenge = auth.findChallenge(Dns01Challenge::class.java).orElseThrow {
                IllegalStateException("No dns-01 challenge for ${auth.identifier}")
            }
            val recordName = name.removeSuffix(".local.yawk.at") + "._acme." + CHALLENGE_ZONE
            cloudflare.withTxtRecord(recordName, challenge.digest) {
                challenge.trigger()
                val status = challenge.waitForCompletion(Duration.ofMinutes(2))
                if (status != Status.VALID) {
                    throw IllegalStateException("Challenge for $name failed: ${challenge.error.orElse(null)}")
                }
            }
        }

        order.waitUntilReady(Duration.ofMinutes(2))
        order.execute(csr)
        val status = order.waitForCompletion(Duration.ofMinutes(2))
        if (status != Status.VALID) {
            throw IllegalStateException("Order for $name failed: ${order.error.orElse(null)}")
        }

        val sw = StringWriter()
        order.certificate.writeCertificate(sw)
        val chain = sw.toString()
        LOG.info("Issued public certificate for {}", name)
        // only a record, the certificate is issued either way and must reach the client
        try {
            val issued = storage.resolve("issued").resolve(name)
            issued.createDirectories()
            issued.resolve("${clock.instant()}.pem").writeText(chain, Charsets.UTF_8, StandardOpenOption.CREATE_NEW)
        } catch (e: IOException) {
            LOG.error("Failed to store the public certificate for {}", name, e)
        }
        return chain
    }
}
