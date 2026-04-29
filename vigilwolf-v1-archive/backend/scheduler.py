"""Background scheduler for the Domain Monitoring System.

Handles:
- Periodic domain checks based on configured frequencies
- Change detection and automatic dump triggering
- Scheduler lifecycle management
"""
from typing import Optional
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from models import Domain, PingLogEntry
from plugins.monitoring_service import get_monitoring_service
from plugins.storage_manager import get_storage_manager
from plugins.capture_engine import get_capture_engine


class DomainScheduler:
    """Manages background scheduling for domain monitoring."""

    def __init__(self):
        """Initialize the domain scheduler."""
        self.scheduler: Optional[BackgroundScheduler] = None
        self.monitoring_service = get_monitoring_service()
        self.storage = get_storage_manager()
        self.capture = get_capture_engine()

    def start_scheduler(self) -> None:
        """Start the background scheduler.

        Initializes the scheduler and schedules checks for all active domains.
        """
        if self.scheduler is not None and self.scheduler.running:
            return

        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

        domains = self.storage.load_domains()
        for domain in domains:
            if domain.active:
                self.schedule_domain_check(domain)

    def stop_scheduler(self) -> None:
        """Stop the background scheduler gracefully.

        Waits for running jobs to complete before shutting down.
        """
        if self.scheduler is not None and self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            self.scheduler = None

    def schedule_domain_check(self, domain: Domain) -> None:
        """Schedule periodic checks for a domain.

        Args:
            domain: Domain object to schedule checks for
        """
        if self.scheduler is None or not self.scheduler.running:
            return

        job_id = f"check_domain_{domain.id}"

        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        trigger = IntervalTrigger(seconds=domain.frequency_seconds)
        self.scheduler.add_job(
            func=self.check_domain,
            trigger=trigger,
            args=[domain.id],
            id=job_id,
            name=f"Check domain {domain.url}",
            replace_existing=True
        )

    def unschedule_domain_check(self, domain_id: str) -> None:
        """Remove scheduled checks for a domain.

        Args:
            domain_id: ID of the domain to unschedule
        """
        if self.scheduler is None:
            return

        job_id = f"check_domain_{domain_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

    def check_domain(self, domain_id: str) -> None:
        """Perform a periodic check for a domain with error isolation.

        This function:
        1. Fetches the current HTML
        2. Compares it with the most recent snapshot
        3. Creates a ping log entry
        4. Triggers an automatic dump if changes are detected

        All errors are caught and logged to ensure one domain's failure
        doesn't affect other domains in the group.

        Args:
            domain_id: ID of the domain to check
        """
        try:
            domain = self.storage.get_domain(domain_id)
            if domain is None or not domain.active:
                return

            html_content, fetch_success = self.capture.fetch_html(domain.url)

            domain.last_checked_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            self.storage.save_domain(domain)

            if not fetch_success:
                ping_entry = PingLogEntry.create(
                    reachable=False,
                    status_code=None,
                    change_detected=False,
                    message=f"Failed to fetch HTML for {domain.url} after retries"
                )
                self.storage.append_ping_log(domain_id, ping_entry)
                return

            latest_snapshot = self.storage.get_latest_snapshot_for_domain(domain_id)

            if latest_snapshot is None:
                ping_entry = PingLogEntry.create(
                    reachable=True,
                    status_code=200,
                    change_detected=False,
                    message="No previous snapshot found for comparison"
                )
                self.storage.append_ping_log(domain_id, ping_entry)
                return

            try:
                previous_html = self.storage.load_html(latest_snapshot.html_path)
            except Exception as e:
                ping_entry = PingLogEntry.create(
                    reachable=True,
                    status_code=200,
                    change_detected=False,
                    message=f"Failed to load previous snapshot for comparison: {str(e)}"
                )
                self.storage.append_ping_log(domain_id, ping_entry)
                return

            change_detected = self.capture.compare_html(previous_html, html_content)

            if change_detected:
                ping_entry = PingLogEntry.create(
                    reachable=True,
                    status_code=200,
                    change_detected=True,
                    message=f"Change detected for {domain.url}"
                )
                self.storage.append_ping_log(domain_id, ping_entry)

                try:
                    self.monitoring_service._perform_dump(domain, trigger_type="automatic")
                except Exception as e:
                    logger = __import__('logging').getLogger(__name__)
                    logger.warning(f"Automatic dump failed for {domain.url}: {e}")
            else:
                ping_entry = PingLogEntry.create(
                    reachable=True,
                    status_code=200,
                    change_detected=False,
                    message=f"No change detected for {domain.url}"
                )
                self.storage.append_ping_log(domain_id, ping_entry)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error checking domain {domain_id}: {e}", exc_info=True)
            try:
                ping_entry = PingLogEntry.create(
                    reachable=False,
                    status_code=None,
                    change_detected=False,
                    message=f"Unexpected error during domain check: {str(e)}"
                )
                self.storage.append_ping_log(domain_id, ping_entry)
            except Exception as inner:
                logger.error(f"Failed to log ping entry for domain {domain_id}: {inner}", exc_info=True)


_scheduler = None


def get_scheduler() -> DomainScheduler:
    """Get the global scheduler instance.

    Returns:
        DomainScheduler instance
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = DomainScheduler()
    return _scheduler
