"""Thread-safe pipeline metrics tracker for VigilWolf v2."""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class PipelineMetrics:
    """Thread-safe counters and histograms for pipeline health."""

    _lock: threading.Lock = field(default_factory=threading.Lock)
    domains_processed: int = 0
    domains_failed: int = 0
    plugin_invocations: int = 0
    plugin_errors: int = 0
    alerts_sent: int = 0
    alerts_failed: int = 0
    start_time: float = field(default_factory=time.time)
    _processing_times: list = field(default_factory=list)

    def record_domain_processed(self) -> None:
        with self._lock:
            self.domains_processed += 1

    def record_domain_failed(self) -> None:
        with self._lock:
            self.domains_failed += 1

    def record_plugin_invocation(self, duration_s: float) -> None:
        with self._lock:
            self.plugin_invocations += 1
            self._processing_times.append(duration_s)

    def record_plugin_error(self) -> None:
        with self._lock:
            self.plugin_errors += 1

    def record_alert_sent(self) -> None:
        with self._lock:
            self.alerts_sent += 1

    def record_alert_failed(self) -> None:
        with self._lock:
            self.alerts_failed += 1

    @property
    def avg_processing_time(self) -> float:
        with self._lock:
            if not self._processing_times:
                return 0.0
            return sum(self._processing_times) / len(self._processing_times)

    @property
    def p99_processing_time(self) -> float:
        with self._lock:
            if not self._processing_times:
                return 0.0
            sorted_times = sorted(self._processing_times)
            idx = int(len(sorted_times) * 0.99)
            return sorted_times[min(idx, len(sorted_times) - 1)]

    @property
    def throughput_per_second(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.domains_processed / elapsed

    def summary(self) -> dict:
        return {
            "domains_processed": self.domains_processed,
            "domains_failed": self.domains_failed,
            "plugin_invocations": self.plugin_invocations,
            "plugin_errors": self.plugin_errors,
            "alerts_sent": self.alerts_sent,
            "alerts_failed": self.alerts_failed,
            "avg_processing_time_s": round(self.avg_processing_time, 4),
            "p99_processing_time_s": round(self.p99_processing_time, 4),
            "throughput_per_second": round(self.throughput_per_second, 2),
            "elapsed_s": round(time.time() - self.start_time, 2),
        }


# Module-level singleton
metrics = PipelineMetrics()