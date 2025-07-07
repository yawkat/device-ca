package at.yawk.deviceca

import io.micronaut.scheduling.TaskExecutors
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.slf4j.LoggerFactory
import java.time.Instant
import java.time.InstantSource
import java.time.temporal.ChronoUnit
import java.util.concurrent.ExecutorService
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

private val LOG = LoggerFactory.getLogger(TimeScheduler::class.java)

interface TimeScheduler {
    fun schedule(time: Instant, task: () -> Unit)
}

@Singleton
class TimeSchedulerImpl(
    @Named(TaskExecutors.SCHEDULED) private val service: ExecutorService,
    private val clock: InstantSource,
) : TimeScheduler {
    override fun schedule(time: Instant, task: () -> Unit) {
        val runnable = Runnable {
            try {
                task.invoke()
            } catch (e: Exception) {
                LOG.error("Error while running scheduled task", e)
            }
        }
        val delta = clock.instant().until(time, ChronoUnit.MILLIS)
        if (delta <= 0) {
            LOG.info("Running certificate update immediately")
            service.execute(runnable)
        } else {
            LOG.info("Scheduling certificate update for $time")
            (service as ScheduledExecutorService).schedule(runnable, delta, TimeUnit.MILLISECONDS)
        }
    }
}