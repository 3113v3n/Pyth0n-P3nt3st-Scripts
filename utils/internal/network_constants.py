"""Tunable constants for internal network scanning."""

DEFAULT_BATCH_SIZE = 2000
DEFAULT_PROGRESS_CHUNK = 100

# Thread-pool sizing: min(cap, cpu_count * multiplier)
DEFAULT_MAX_WORKER_CAP = 128
DEFAULT_WORKER_MULTIPLIER = 4

INTERFACE_POLL_INTERVAL_SECONDS = 1.0
