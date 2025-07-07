package at.yawk.deviceca

import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Primary
import java.time.Instant
import java.time.InstantSource

@Factory
@Primary
class MockClock : InstantSource {
    var time = Instant.now()!!

    override fun instant() = time
}