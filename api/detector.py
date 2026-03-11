from collections import Counter
from datetime import datetime, timezone
from api.elastic_client import es
from api.config import (
    INDEX_LINUX_EVENTS,
    INDEX_WINDOWS_EVENTS,
    INDEX_SANDBOX_EVENTS,
    INDEX_ALERTS,
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_alert(
    threat_type: str,
    severity: str,
    description: str,
    source_type: str,
    mitre_technique_id: str,
    mitre_technique_name: str,
    host: str | None = None,
    source_ip: str | None = None,
    extra: dict | None = None,
):
    alert = {
        "timestamp": utc_now(),
        "threat_type": threat_type,
        "severity": severity,
        "description": description,
        "source_type": source_type,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
        "host": host,
        "source_ip": source_ip,
        "status": "new",
    }

    if extra:
        alert.update(extra)

    return alert


def detect_linux_bruteforce():
    response = es.search(index=INDEX_LINUX_EVENTS, body={"size": 1000})

    ips = []
    for hit in response["hits"]["hits"]:
        event = hit["_source"]
        if event["event_type"] == "failed_ssh_login" and event.get("source_ip"):
            ips.append(event["source_ip"])

    counter = Counter(ips)
    alerts = []

    for ip, count in counter.items():
        if count >= 5:
            alert = build_alert(
                threat_type="ssh_bruteforce",
                severity="high",
                description=f"Possible SSH brute-force attack from {ip}",
                source_type="linux",
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                source_ip=ip,
                host="linux-server-01",
                extra={"attempts": count},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

    return alerts


def detect_windows_attacks():
    response = es.search(index=INDEX_WINDOWS_EVENTS, body={"size": 1000})

    alerts = []

    for hit in response["hits"]["hits"]:
        event = hit["_source"]

        if event["event_type"] == "powershell_encoded_command":
            alert = build_alert(
                threat_type="suspicious_powershell",
                severity="high",
                description="Encoded PowerShell command detected",
                source_type="windows",
                mitre_technique_id="T1059.001",
                mitre_technique_name="PowerShell",
                host=event.get("host"),
                source_ip=event.get("source_ip"),
                extra={"process_name": event.get("process_name")},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

        if event["event_type"] == "defender_disabled":
            alert = build_alert(
                threat_type="defense_evasion",
                severity="critical",
                description="Security tooling may have been disabled on endpoint",
                source_type="windows",
                mitre_technique_id="T1562.001",
                mitre_technique_name="Impair Defenses",
                host=event.get("host"),
                source_ip=event.get("source_ip"),
                extra={"process_name": event.get("process_name")},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

        if event["event_type"] == "autorun_persistence":
            alert = build_alert(
                threat_type="persistence_registry_runkey",
                severity="high",
                description="Potential persistence via Windows autorun registry key",
                source_type="windows",
                mitre_technique_id="T1547.001",
                mitre_technique_name="Registry Run Keys / Startup Folder",
                host=event.get("host"),
                source_ip=event.get("source_ip"),
                extra={"process_name": event.get("process_name")},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

    return alerts


def detect_ransomware_behavior():
    response = es.search(index=INDEX_SANDBOX_EVENTS, body={"size": 1000})

    alerts = []

    for hit in response["hits"]["hits"]:
        event = hit["_source"]

        if event["event_type"] == "mass_file_encryption_behavior":
            alert = build_alert(
                threat_type="possible_ransomware",
                severity="critical",
                description="Mass file encryption behavior detected",
                source_type="sandbox",
                mitre_technique_id="T1486",
                mitre_technique_name="Data Encrypted for Impact",
                host=event.get("host"),
                source_ip=event.get("source_ip"),
                extra={"process_name": event.get("process_name")},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

        if event["event_type"] == "c2_beaconing":
            alert = build_alert(
                threat_type="possible_c2_beaconing",
                severity="high",
                description="Repeated suspicious outbound connections detected",
                source_type="sandbox",
                mitre_technique_id="T1071",
                mitre_technique_name="Application Layer Protocol",
                host=event.get("host"),
                source_ip=event.get("source_ip"),
                extra={"process_name": event.get("process_name")},
            )
            es.index(index=INDEX_ALERTS, document=alert)
            alerts.append(alert)

    return alerts


def run_detection_engine():
    linux_alerts = detect_linux_bruteforce()
    windows_alerts = detect_windows_attacks()
    sandbox_alerts = detect_ransomware_behavior()

    return {
        "linux_alerts": linux_alerts,
        "windows_alerts": windows_alerts,
        "sandbox_alerts": sandbox_alerts,
        "total_alerts_created": len(linux_alerts) + len(windows_alerts) + len(sandbox_alerts),
    }


def health_detection_stub():
    return {
        "status": "ready",
        "message": "Detection engine ready",
    }