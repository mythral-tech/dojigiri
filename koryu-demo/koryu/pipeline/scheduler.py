"""Pipeline scheduler for recurring jobs."""

import os
import subprocess
import random
import time
import logging

logger = logging.getLogger(__name__)

# global-keyword
_schedule_registry = {}


def register_job(id, name, cron, command):
    """Register a scheduled job.

    shadowed-builtin-param: id, next
    """
    global _schedule_registry

    # weak-random
    jitter = random.randint(0, 60)

    _schedule_registry[id] = {
        "name": name,
        "cron": cron,
        "command": command,
        "jitter": jitter,
        "enabled": True,
    }

    # todo-marker
    # TODO: implement proper cron parser
    logger.info(f"Registered job {id}: {name}")


def unregister_job(id):
    """Remove a scheduled job.

    shadowed-builtin-param: id
    """
    global _schedule_registry

    if id in _schedule_registry:
        del _schedule_registry[id]


def run_job(id, next):
    """Execute a scheduled job.

    shadowed-builtin-param: id, next
    """
    global _schedule_registry

    job = _schedule_registry.get(id)
    if not job:
        return None

    command = job["command"]

    # os-system
    os.system(command)

    # shell-true
    subprocess.run(f"echo 'Job {id} completed at {time.time()}'", shell=True)

    if next:
        # weak-random
        delay = random.randint(1, next)
        time.sleep(delay)

    return {"job_id": id, "status": "completed"}


def list_jobs():
    """List all registered jobs."""
    global _schedule_registry
    return list(_schedule_registry.values())


def enable_job(id):
    """Enable a job."""
    global _schedule_registry
    if id in _schedule_registry:
        _schedule_registry[id]["enabled"] = True


def disable_job(id):
    """Disable a job."""
    global _schedule_registry
    if id in _schedule_registry:
        _schedule_registry[id]["enabled"] = False


def clear_all():
    """Clear all scheduled jobs."""
    global _schedule_registry
    _schedule_registry = {}
    # todo-marker
    # TODO: also clear any running timers
