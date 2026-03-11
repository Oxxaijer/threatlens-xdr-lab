import os

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

INDEX_LINUX_EVENTS = "linux-security-events"
INDEX_WINDOWS_EVENTS = "windows-endpoint-events"
INDEX_SANDBOX_EVENTS = "sandbox-analysis-events"
INDEX_ALERTS = "threat-alerts"