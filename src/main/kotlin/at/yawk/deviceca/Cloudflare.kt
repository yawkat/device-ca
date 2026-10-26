package at.yawk.deviceca

import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.uri.UriBuilder
import io.micronaut.json.tree.JsonNode
import org.slf4j.LoggerFactory
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
    private val client: HttpClient,
    private val apiUrl: String,
    private val token: String,
    private val zoneName: String,
) {
    private class Zone(val id: String, val nameServers: List<String>)

    private val zone by lazy {
        val result = call(HttpRequest.GET<Any>(api("zones").queryParam("name", zoneName).build())).get("result")
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
        val body = mapOf("type" to "TXT", "name" to name, "content" to value, "ttl" to 60)
        val id = call(HttpRequest.POST(api("zones/${zone.id}/dns_records").build(), body)).get("result")!!.get("id")!!.stringValue
        LOG.info("Created TXT record {}", name)
        try {
            awaitVisible(name, value)
            return action()
        } finally {
            try {
                call(HttpRequest.DELETE<Any>(api("zones/${zone.id}/dns_records/$id").build()))
                LOG.info("Deleted TXT record {}", name)
            } catch (e: Exception) {
                LOG.warn("Failed to delete TXT record {}", name, e)
            }
        }
    }

    private fun deleteTxtRecords(name: String) {
        val uri = api("zones/${zone.id}/dns_records").queryParam("type", "TXT").queryParam("name", name).build()
        val existing = call(HttpRequest.GET<Any>(uri)).get("result")!!
        for (record in existing.values()) {
            call(HttpRequest.DELETE<Any>(api("zones/${zone.id}/dns_records/${record.get("id")!!.stringValue}").build()))
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

    private fun api(path: String) = UriBuilder.of(apiUrl).path(path)

    private fun call(request: MutableHttpRequest<*>): JsonNode {
        request.bearerAuth(token)
        val node = try {
            client.toBlocking().retrieve(request, JsonNode::class.java)
        } catch (e: HttpClientResponseException) {
            val errors = e.response.getBody(JsonNode::class.java).map { it.get("errors") }.orElse(null)
            throw IllegalStateException("Cloudflare API ${request.method} ${request.path} failed with ${e.status}: $errors")
        }
        if (node?.get("success")?.booleanValue != true) {
            throw IllegalStateException("Cloudflare API ${request.method} ${request.path} failed: ${node?.get("errors")}")
        }
        return node
    }
}
