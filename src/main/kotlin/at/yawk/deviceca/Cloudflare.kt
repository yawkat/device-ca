package at.yawk.deviceca

import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.Hashtable
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.InitialDirContext

private val LOG = LoggerFactory.getLogger(Cloudflare::class.java)

/**
 * The few Cloudflare DNS API calls needed to publish DNS-01 challenge records in one zone. The token only has
 * Zone:Read and DNS:Edit on that zone.
 */
open class Cloudflare(
    private val apiUrl: String,
    private val token: String,
    private val zoneName: String,
    private val json: JsonMapper,
) {
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    private class Zone(val id: String, val nameServers: List<String>)

    private val zone by lazy {
        val result = call("GET", "/zones?name=${encode(zoneName)}").get("result")
        if (result == null || result.size() != 1) {
            throw IllegalStateException("Zone $zoneName not found")
        }
        val zone = result.get(0)!!
        Zone(
            zone.get("id")!!.stringValue,
            zone.get("name_servers")?.values()?.map { it.stringValue } ?: emptyList()
        )
    }

    /**
     * Publish a TXT record, run [action], and remove the record again. Any records of that name left over from an
     * earlier run are removed first.
     */
    fun <R> withTxtRecord(name: String, value: String, action: () -> R): R {
        deleteTxtRecords(name)
        val body = json.writeValueAsBytes(mapOf("type" to "TXT", "name" to name, "content" to value, "ttl" to 60))
        val id = call("POST", "/zones/${zone.id}/dns_records", body).get("result")!!.get("id")!!.stringValue
        LOG.info("Created TXT record {}", name)
        try {
            awaitVisible(name, value)
            return action()
        } finally {
            try {
                call("DELETE", "/zones/${zone.id}/dns_records/$id")
                LOG.info("Deleted TXT record {}", name)
            } catch (e: Exception) {
                LOG.warn("Failed to delete TXT record {}", name, e)
            }
        }
    }

    private fun deleteTxtRecords(name: String) {
        val existing = call("GET", "/zones/${zone.id}/dns_records?type=TXT&name=${encode(name)}").get("result")!!
        for (record in existing.values()) {
            call("DELETE", "/zones/${zone.id}/dns_records/${record.get("id")!!.stringValue}")
            LOG.info("Deleted stale TXT record {}", name)
        }
    }

    /**
     * Wait until all of the zone's name servers serve the record, so that the CA's lookup finds it.
     */
    protected open fun awaitVisible(name: String, value: String) {
        val deadline = Instant.now().plus(Duration.ofMinutes(2))
        for (server in zone.nameServers) {
            while (!txtVisible(server, name, value)) {
                if (Instant.now() > deadline) {
                    throw IllegalStateException("TXT record $name did not become visible on $server")
                }
                Thread.sleep(2000)
            }
        }
    }

    private fun txtVisible(server: String, name: String, value: String): Boolean {
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.dns.DnsContextFactory"
        env[Context.PROVIDER_URL] = "dns://$server"
        val ctx = InitialDirContext(env)
        try {
            val txt = ctx.getAttributes("$name.", arrayOf("TXT")).get("TXT") ?: return false
            return txt.all.asSequence().any { it.toString().trim('"') == value }
        } catch (_: NamingException) {
            return false
        } finally {
            ctx.close()
        }
    }

    private fun call(method: String, path: String, body: ByteArray? = null): JsonNode {
        val request = HttpRequest.newBuilder(URI.create(apiUrl + path))
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(30))
            .method(
                method,
                if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofByteArray(body)
            )
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        val node = try {
            json.readValue(response.body(), JsonNode::class.java)
        } catch (_: Exception) {
            null
        }
        if (response.statusCode() !in 200..299 || node?.get("success")?.booleanValue != true) {
            throw IllegalStateException("Cloudflare API $method $path failed with ${response.statusCode()}: ${node?.get("errors")}")
        }
        return node
    }

    private fun encode(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
}
