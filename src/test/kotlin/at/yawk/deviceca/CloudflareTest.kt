package at.yawk.deviceca

import com.sun.net.httpserver.HttpServer
import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress

class CloudflareTest {
    private val json = JsonMapper.createDefault()
    private lateinit var server: HttpServer

    /** id to name of the TXT records in the stub zone */
    private val records = linkedMapOf<String, String>()
    private val requests = mutableListOf<String>()
    private var nextId = 0

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            val path = exchange.requestURI.toString()
            requests.add("${exchange.requestMethod} $path")
            Assertions.assertEquals("Bearer secret", exchange.requestHeaders.getFirst("Authorization"))
            val result: Any = when {
                exchange.requestMethod == "GET" && path == "/zones?name=cats.coffee" ->
                    listOf(mapOf("id" to "zone1", "name_servers" to listOf("ns.example")))
                exchange.requestMethod == "GET" && path.startsWith("/zones/zone1/dns_records?type=TXT&name=") -> {
                    val name = path.substringAfter("name=")
                    records.filterValues { it == name }.keys.map { mapOf("id" to it) }
                }
                exchange.requestMethod == "POST" && path == "/zones/zone1/dns_records" -> {
                    val body = json.readValue(exchange.requestBody.readAllBytes(), JsonNode::class.java)!!
                    Assertions.assertEquals("TXT", body.get("type")!!.stringValue)
                    Assertions.assertEquals("digest", body.get("content")!!.stringValue)
                    val id = "record${nextId++}"
                    records[id] = body.get("name")!!.stringValue
                    mapOf("id" to id)
                }
                exchange.requestMethod == "DELETE" && path.startsWith("/zones/zone1/dns_records/") -> {
                    val id = path.substringAfterLast('/')
                    Assertions.assertNotNull(records.remove(id))
                    mapOf("id" to id)
                }
                else -> throw AssertionError("Unexpected request $path")
            }
            val response = json.writeValueAsBytes(mapOf("success" to true, "errors" to emptyList<Any>(), "result" to result))
            exchange.sendResponseHeaders(200, response.size.toLong())
            exchange.responseBody.use { it.write(response) }
        }
        server.start()
    }

    @AfterEach
    fun stop() {
        server.stop(0)
    }

    private fun cloudflare(visible: MutableList<String>) =
        object : Cloudflare("http://127.0.0.1:${server.address.port}", "secret", "cats.coffee", json) {
            override fun awaitVisible(name: String, value: String) {
                visible.add(name)
            }
        }

    @Test
    fun `record exists during action`() {
        val visible = mutableListOf<String>()
        val result = cloudflare(visible).withTxtRecord("test._acme.cats.coffee", "digest") {
            Assertions.assertEquals(listOf("test._acme.cats.coffee"), records.values.toList())
            "done"
        }
        Assertions.assertEquals("done", result)
        Assertions.assertEquals(listOf("test._acme.cats.coffee"), visible)
        Assertions.assertEquals(emptyMap<String, String>(), records)
    }

    @Test
    fun `record is removed on failure`() {
        val e = Assertions.assertThrows(IllegalStateException::class.java) {
            cloudflare(mutableListOf()).withTxtRecord("test._acme.cats.coffee", "digest") {
                throw IllegalStateException("challenge failed")
            }
        }
        Assertions.assertEquals("challenge failed", e.message)
        Assertions.assertEquals(emptyMap<String, String>(), records)
    }

    @Test
    fun `stale records are removed`() {
        records["stale"] = "test._acme.cats.coffee"
        records["other"] = "other._acme.cats.coffee"
        cloudflare(mutableListOf()).withTxtRecord("test._acme.cats.coffee", "digest") {
            Assertions.assertEquals(listOf("other._acme.cats.coffee", "test._acme.cats.coffee"), records.values.toList())
        }
        Assertions.assertEquals(listOf("other._acme.cats.coffee"), records.values.toList())
        Assertions.assertTrue("DELETE /zones/zone1/dns_records/stale" in requests)
    }
}
