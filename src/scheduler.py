"""
src/scheduler.py
Background scheduler for automated CTI data collection.
Runs the pipeline every N minutes based on config.
Gap filled: proper scheduler with configurable intervals.
"""
import signal
import sys
import os
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from src.utils.logger import get_logger
from src.database.db import init_db

logger = get_logger("cti.scheduler")


def pipeline_job():
    """Scheduled pipeline run."""
    logger.info(f"Scheduled pipeline run starting at {datetime.now(timezone.utc).isoformat()}")
    try:
        from src.pipeline import run_pipeline
        result = run_pipeline(days_back=1)
        logger.info(f"Scheduled run complete: {result}")
    except Exception as e:
        logger.error(f"Scheduled pipeline failed: {e}", exc_info=True)


def alert_check_job():
    """Check for any unnotified critical threats."""
    logger.info("Alert check job running...")
    # TODO: implement secondary alert check for persistent threats


def run_scheduler():
    """Start the background scheduler. Blocks until interrupted."""
    collection_interval = int(os.getenv("COLLECTION_INTERVAL_MINUTES", "60"))
    alert_interval = int(os.getenv("ALERT_CHECK_INTERVAL_MINUTES", "5"))

    init_db()
    logger.info(f"Starting CTI scheduler (collection every {collection_interval}m, alerts every {alert_interval}m)")

    scheduler = BackgroundScheduler(timezone="UTC")

    scheduler.add_job(
        pipeline_job,
        trigger=IntervalTrigger(minutes=collection_interval),
        id="pipeline_collection",
        name="CTI Data Collection",
        replace_existing=True,
    )

    scheduler.add_job(
        alert_check_job,
        trigger=IntervalTrigger(minutes=alert_interval),
        id="alert_check",
        name="Alert Check",
        replace_existing=True,
    )

    scheduler.start()
    logger.info("Scheduler started. Running initial pipeline collection...")

    # Run immediately on start
    pipeline_job()

    def shutdown(signum, frame):
        logger.info("Shutting down scheduler...")
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    logger.info("Scheduler running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        shutdown(None, None)


if __name__ == "__main__":
    run_scheduler()
