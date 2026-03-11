import re
from pathlib import Path
from api.elastic_client import es
from api.config import INDEX_LINUX_EVENTS

BASE_DIR = Path(__file__).resolve().parent.parent
AUTH_LOG_FILE = BASE_DIR / "analytics" / "sample_events" / "auth.log"

FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

SUDO_FAIL_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*authentication failure; user=(?P<user>\w+)"
)

CRON_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*CRON.*CMD \((?P<cmd>.+)\)"
)


def parse_linux_log():
    events = []

    if not AUTH_LOG_FILE.exists():
        return events

    with open(AUTH_LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            raw_line = line.strip()

            failed_match = FAILED_SSH_PATTERN.search(raw_line)
            if failed_match:
                events.append(
                    {
                        "timestamp": failed_match.group("timestamp"),
                        "source_type": "linux",
                        "event_type": "failed_ssh_login",
                        "severity": "medium",
                        "host": "linux-server-01",
                        "source_ip": failed_match.group("ip"),
                        "user": None,
                        "process_name": "sshd",
                        "description": f"Failed SSH login attempt from {failed_match.group('ip')}",
                        "raw_data": {"log": raw_line},
                    }
                )
                continue

            sudo_match = SUDO_FAIL_PATTERN.search(raw_line)
            if sudo_match:
                events.append(
                    {
                        "timestamp": sudo_match.group("timestamp"),
                        "source_type": "linux",
                        "event_type": "sudo_auth_failure",
                        "severity": "high",
                        "host": "linux-server-01",
                        "source_ip": None,
                        "user": sudo_match.group("user"),
                        "process_name": "sudo",
                        "description": f"Sudo authentication failure for user {sudo_match.group('user')}",
                        "raw_data": {"log": raw_line},
                    }
                )
                continue

            cron_match = CRON_PATTERN.search(raw_line)
            if cron_match:
                events.append(
                    {
                        "timestamp": cron_match.group("timestamp"),
                        "source_type": "linux",
                        "event_type": "suspicious_cron_execution",
                        "severity": "high",
                        "host": "linux-server-01",
                        "source_ip": None,
                        "user": "root",
                        "process_name": "cron",
                        "description": f"Suspicious cron execution detected: {cron_match.group('cmd')}",
                        "raw_data": {
                            "log": raw_line,
                            "command": cron_match.group("cmd"),
                        },
                    }
                )

    return events


def ingest_linux_events():
    events = parse_linux_log()

    indexed = 0
    errors = []

    for event in events:
        try:
            es.index(index=INDEX_LINUX_EVENTS, document=event)
            indexed += 1
        except Exception as e:
            errors.append(str(e))

    return {
        "source": "linux",
        "events_parsed": len(events),
        "events_indexed": indexed,
        "errors": errors,
    }