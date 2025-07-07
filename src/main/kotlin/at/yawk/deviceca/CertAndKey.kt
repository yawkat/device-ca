package at.yawk.deviceca

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

data class CertAndKey(
    val cert: X509Certificate,
    val key: PrivateKey,
) {
    fun sign(
        now: Instant,
        publicKeyInfo: SubjectPublicKeyInfo,
        cn: String,
        san: GeneralName = GeneralName(GeneralName.dNSName, cn),
        keyUsage: Int = -1,
        lifetime: Duration,
    ): X509CertificateHolder {
        val builder = JcaX509v3CertificateBuilder(
            X500Name.getInstance(cert.subjectX500Principal.encoded),
            BigInteger(64, SecureRandom.getInstanceStrong()),
            Date.from(now.minus(Duration.ofMinutes(30))),
            Date.from(now.plus(Duration.ofDays(7))),
            X500NameBuilder().addRDN(BCStyle.CN, cn).build(),
            publicKeyInfo
        )
        builder.addExtension(
            Extension.subjectAlternativeName,
            false,
            GeneralNames(san)
        )
        builder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            JcaX509ExtensionUtils().createAuthorityKeyIdentifier(cert)
        )
        builder.addExtension(
            Extension.keyUsage, true, KeyUsage(
                (KeyUsage.keyAgreement or KeyUsage.keyEncipherment or KeyUsage.digitalSignature or KeyUsage.dataEncipherment) and keyUsage
            )
        )
        return builder.build(
            JcaContentSignerBuilder(
                "SHA256WithRSAEncryption",
                cert.publicKey
            ).build(key)
        )
    }
}
