package at.yawk.deviceca

import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Secondary
import jakarta.inject.Singleton
import java.time.Clock
import java.time.InstantSource

@Factory
class ClockFactory {
    @Singleton
    @Secondary
    fun clock(): InstantSource {
        return Clock.systemDefaultZone()
    }
}