package at.yawk.deviceca

import jakarta.inject.Singleton
import java.net.InetAddress

@Singleton
open class Resolver {
    open fun matches(dnsName: String, ip: InetAddress) = InetAddress.getAllByName(dnsName)
        .any { it.address.contentEquals(ip.address) }
}